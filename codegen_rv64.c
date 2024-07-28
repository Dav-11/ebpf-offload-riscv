//
// Created by Davide Collovigh on 08/07/24.
//

#include "codegen.h"

/***********************************
 * utils
 **********************************/

static inline bool rvc_enabled(void)
{
	return IS_ENABLED(CONFIG_RISCV_ISA_C);
}

static inline bool is_12b_int(long val)
{
	return -(1L << 11) <= val && val < (1L << 11);
}

static inline bool is_13b_int(long val)
{
	return -(1L << 12) <= val && val < (1L << 12);
}

static inline bool is_21b_int(long val)
{
	return -(1L << 20) <= val && val < (1L << 20);
}

static inline bool is_32b_int(s64 val)
{
	return -(1L << 31) <= val && val < (1L << 31);
}

static bool in_auipc_jalr_range(s64 val)
{
	/*
     * auipc+jalr can reach any signed PC-relative offset in the range
     * [-2^31 - 2^11, 2^31 - 2^11).
     */
	return (-(1L << 31) - (1L << 11)) <= val &&
	       val < ((1L << 31) - (1L << 11));
}

void mark_call(rvo_prog *prog)
{
	__set_bit(RV_CTX_F_SEEN_CALL, &prog->flags);
}

/**
 * @brief Convert from ninsns to bytes.
 * @param ninsns
 * @return
 */
static inline int ninsns_rvoff(int ninsns)
{
	return ninsns << 1;
}

/***********************************
 * codegen
 **********************************/

void init_regs(u8 *rd, u8 *rs, const struct bpf_insn *insn, rvo_prog *prog)
{
	u8 code = insn->code;

	switch (code) {
	case BPF_JMP | BPF_JA:
	case BPF_JMP | BPF_CALL:
	case BPF_JMP | BPF_EXIT:
	case BPF_JMP | BPF_TAIL_CALL:
		break;
	default:
		*rd = bpf_to_rv_reg(insn->dst_reg, &(prog->used_regs));
	}

	if (code & (BPF_ALU | BPF_X) || code & (BPF_ALU64 | BPF_X) ||
	    code & (BPF_JMP | BPF_X) || code & (BPF_JMP32 | BPF_X) ||
	    code & BPF_LDX || code & BPF_STX) {
		*rs = bpf_to_rv_reg(insn->src_reg, &(prog->used_regs));
	}
}

int rv_offset(int insn, int off, rvo_prog *ctx)
{
	int from, to;

	// BPF branch is from PC+1 while RV is from PC
	off++;

	if (insn > 0) {
		from = ctx->offset[insn - 1];
	} else {
		// if insn number <= 0 -> prologue
		from = ctx->prologue_len;
	}

	if (insn + off > 0) {
		to = ctx->offset[insn + off - 1];
	} else {
		to = ctx->prologue_len;
	}

	return ninsns_rvoff(to - from);
}

/* Emit a 2-byte riscv compressed instruction. */
static inline void emitc(const u16 insn, rvo_prog *ctx)
{
	BUILD_BUG_ON(!rvc_enabled());

	if (ctx->insns)
		ctx->insns[ctx->ninsns] = insn;

	ctx->ninsns++;
}

/* Emit a 4-byte riscv instruction. */
static inline void emit(const u32 insn, rvo_prog *ctx)
{
	if (ctx->insns) {
		ctx->insns[ctx->ninsns] = insn;
		ctx->insns[ctx->ninsns + 1] = (insn >> 16);
	}

	ctx->ninsns += 2;
}

/***********************************
 * emit multiple insns
 **********************************/

int emit_jump_and_link(u8 rd, s64 rvoff, bool fixed_addr, rvo_prog *ctx)
{
	s64 upper, lower;

	if (rvoff && fixed_addr && is_21b_int(rvoff)) {
		emit(rv_jal(rd, rvoff >> 1), ctx);
		return 0;

	} else if (in_auipc_jalr_range(rvoff)) {
		upper = (rvoff + (1 << 11)) >> 12;
		lower = rvoff & 0xfff;
		emit(rv_auipc(RV_REG_T1, upper), ctx);
		emit(rv_jalr(rd, RV_REG_T1, lower), ctx);
		return 0;
	}

	pr_err("bpf-jit: target offset 0x%llx is out of range\n", rvoff);
	return -ERANGE;
}

void emit_branch(u8 cond, u8 rd, u8 rs, int rvoff, rvo_prog *ctx)
{
	s64 upper, lower;

	if (is_13b_int(rvoff)) {
		emit_bcc(cond, rd, rs, rvoff, ctx);
		return;
	}

	/* Adjust for jal */
	rvoff -= 4;

	/* Transform, e.g.:
     *   bne rd,rs,foo
     * to
     *   beq rd,rs,<.L1>
     *   (auipc foo)
     *   jal(r) foo
     * .L1
     */
	cond = invert_bpf_cond(cond);
	if (is_21b_int(rvoff)) {
		emit_bcc(cond, rd, rs, 8, ctx);
		emit(rv_jal(RV_REG_ZERO, rvoff >> 1), ctx);
		return;
	}

	/* 32b No need for an additional rvoff adjustment, since we
     * get that from the auipc at PC', where PC = PC' + 4.
     */
	upper = (rvoff + (1 << 11)) >> 12;
	lower = rvoff & 0xfff;

	emit_bcc(cond, rd, rs, 12, ctx);
	emit(rv_auipc(RV_REG_T1, upper), ctx);
	emit(rv_jalr(RV_REG_ZERO, RV_REG_T1, lower), ctx);
}

void emit_imm(u8 rd, s64 val, rvo_prog *ctx)
{
	/* Note that the immediate from the add is sign-extended,
     * which means that we need to compensate this by adding 2^12,
     * when the 12th bit is set. A simpler way of doing this, and
     * getting rid of the check, is to just add 2**11 before the
     * shift. The "Loading a 32-Bit constant" example from the
     * "Computer Organization and Design, RISC-V edition" book by
     * Patterson/Hennessy highlights this fact.
     *
     * This also means that we need to process LSB to MSB.
     */
	s64 upper = (val + (1 << 11)) >> 12;
	/* Sign-extend lower 12 bits to 64 bits since immediates for li, addiw,
     * and addi are signed and RVC checks will perform signed comparisons.
     */
	s64 lower = ((val & 0xfff) << 52) >> 52;
	int shift;

	if (is_32b_int(val)) {
		if (upper)
			emit_lui(rd, upper, ctx);

		if (!upper) {
			emit_li(rd, lower, ctx);
			return;
		}

		emit_addiw(rd, rd, lower, ctx);
		return;
	}

	shift = __ffs(upper);
	upper >>= shift;
	shift += 12;

	emit_imm(rd, upper, ctx);

	emit_slli(rd, rd, shift, ctx);
	if (lower)
		emit_addi(rd, rd, lower, ctx);
}



int emit_call(u64 addr, bool fixed_addr, rvo_prog *ctx)
{
    // TODO: impl
    return 0;
}
int emit_bpf_tail_call(int insn, rvo_prog *ctx){
    //TODO: implement
    return 0;
}
inline int epilogue_offset(rvo_prog *ctx){
    //TODO: implement
    return 0;
}

/* Emit fixed-length instructions for address */
int emit_addr(u8 rd, u64 addr, bool extra_pass, rvo_prog *ctx)
{
    //TODO: implement
    return 0;
}

/* For accesses to BTF pointers, add an entry to the exception table */
int add_exception_handler(const struct bpf_insn *insn,
                          rvo_prog *ctx,
                          int dst_reg, int insn_len)
{
    //TODO: implement
    return 0;
}

void emit_atomic(u8 rd, u8 rs, s16 off, s32 imm, bool is64,
                 rvo_prog *ctx)
{
    //TODO: implement
}





/***********************************
 * instr high lvl
 **********************************/

void emit_bcc(u8 cond, u8 rd, u8 rs, int rvoff, rvo_prog *ctx)
{
	switch (cond) {
	case BPF_JEQ:
		emit(rv_beq(rd, rs, rvoff >> 1), ctx);
		return;
	case BPF_JGT:
		emit(rv_bltu(rs, rd, rvoff >> 1), ctx);
		return;
	case BPF_JLT:
		emit(rv_bltu(rd, rs, rvoff >> 1), ctx);
		return;
	case BPF_JGE:
		emit(rv_bgeu(rd, rs, rvoff >> 1), ctx);
		return;
	case BPF_JLE:
		emit(rv_bgeu(rs, rd, rvoff >> 1), ctx);
		return;
	case BPF_JNE:
		emit(rv_bne(rd, rs, rvoff >> 1), ctx);
		return;
	case BPF_JSGT:
		emit(rv_blt(rs, rd, rvoff >> 1), ctx);
		return;
	case BPF_JSLT:
		emit(rv_blt(rd, rs, rvoff >> 1), ctx);
		return;
	case BPF_JSGE:
		emit(rv_bge(rd, rs, rvoff >> 1), ctx);
		return;
	case BPF_JSLE:
		emit(rv_bge(rs, rd, rvoff >> 1), ctx);
	}
}

inline void emit_jalr(u8 rd, u8 rs, s32 imm, rvo_prog *ctx)
{
	emit(rv_jalr(rd, rs, imm), ctx);
}
inline void emit_mv(u8 rd, u8 rs, rvo_prog *ctx)
{
	emit(rv_addi(rd, rs, 0), ctx);
}
inline void emit_add(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx)
{
	emit(rv_add(rd, rs1, rs2), ctx);
}
inline void emit_addi(u8 rd, u8 rs, s32 imm, rvo_prog *ctx)
{
	emit(rv_addi(rd, rs, imm), ctx);
}
inline void emit_li(u8 rd, s32 imm, rvo_prog *ctx)
{
	emit(rv_addi(rd, RV_REG_ZERO, imm), ctx);
}
inline void emit_lui(u8 rd, s32 imm, rvo_prog *ctx)
{
	emit(rv_lui(rd, imm), ctx);
}
inline void emit_slli(u8 rd, u8 rs, s32 imm, rvo_prog *ctx)
{
	emit(rv_slli(rd, rs, imm), ctx);
}
inline void emit_andi(u8 rd, u8 rs, s32 imm, rvo_prog *ctx)
{
	emit(rv_andi(rd, rs, imm), ctx);
}
inline void emit_srli(u8 rd, u8 rs, s32 imm, rvo_prog *ctx)
{
	emit(rv_srli(rd, rs, imm), ctx);
}
inline void emit_srai(u8 rd, u8 rs, s32 imm, rvo_prog *ctx)
{
	emit(rv_srai(rd, rs, imm), ctx);
}
inline void emit_sub(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx)
{
	emit(rv_sub(rd, rs1, rs2), ctx);
}
inline void emit_or(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx)
{
	emit(rv_or(rd, rs1, rs2), ctx);
}
inline void emit_and(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx)
{
	emit(rv_and(rd, rs1, rs2), ctx);
}
inline void emit_xor(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx)
{
	emit(rv_xor(rd, rs1, rs2), ctx);
}
inline void emit_lw(u8 rd, s32 off, u8 rs1, rvo_prog *ctx)
{
	emit(rv_lw(rd, off, rs1), ctx);
}
inline void emit_sw(u8 rs1, s32 off, u8 rs2, rvo_prog *ctx)
{
	emit(rv_sw(rs1, off, rs2), ctx);
}

/* RV64-only helper functions. */

inline void emit_addiw(u8 rd, u8 rs, s32 imm, rvo_prog *ctx)
{
	emit(rv_addiw(rd, rs, imm), ctx);
}
inline void emit_ld(u8 rd, s32 off, u8 rs1, rvo_prog *ctx)
{
	emit(rv_ld(rd, off, rs1), ctx);
}
inline void emit_sd(u8 rs1, s32 off, u8 rs2, rvo_prog *ctx)
{
	emit(rv_sd(rs1, off, rs2), ctx);
}
inline void emit_subw(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx)
{
	emit(rv_subw(rd, rs1, rs2), ctx);
}

inline void emit_zext_32(u8 reg, rvo_prog *ctx)
{
	emit_slli(reg, reg, 32, ctx);
	emit_srli(reg, reg, 32, ctx);
}

void emit_zext_32_rd_rs(u8 *rd, u8 *rs, rvo_prog *ctx)
{
	emit_mv(RV_REG_T2, *rd, ctx);
	emit_zext_32(RV_REG_T2, ctx);
	emit_mv(RV_REG_T1, *rs, ctx);
	emit_zext_32(RV_REG_T1, ctx);
	*rd = RV_REG_T2;
	*rs = RV_REG_T1;
}

void emit_sext_32_rd_rs(u8 *rd, u8 *rs, rvo_prog *ctx)
{
	emit_addiw(RV_REG_T2, *rd, 0, ctx);
	emit_addiw(RV_REG_T1, *rs, 0, ctx);
	*rd = RV_REG_T2;
	*rs = RV_REG_T1;
}

void emit_zext_32_rd_t1(u8 *rd, rvo_prog *ctx)
{
	emit_mv(RV_REG_T2, *rd, ctx);
	emit_zext_32(RV_REG_T2, ctx);
	emit_zext_32(RV_REG_T1, ctx);
	*rd = RV_REG_T2;
}

void emit_sext_32_rd(u8 *rd, rvo_prog *ctx)
{
	emit_addiw(RV_REG_T2, *rd, 0, ctx);
	*rd = RV_REG_T2;
}

/***********************************
 * main emit function
 **********************************/

int bpf_jit_emit_insn(const struct bpf_insn *insn, rvo_prog *ctx,
		      bool extra_pass)
{
	bool is64 = BPF_CLASS(insn->code) == BPF_ALU64 ||
		    BPF_CLASS(insn->code) == BPF_JMP;

	int s, e, rvoff, ret, i = insn - ctx->prog->insnsi;
	struct bpf_prog_aux *aux = ctx->prog->aux;

	s16 off = insn->off;
	s32 imm = insn->imm;

	u8 rd = -1;
	u8 rs = -1;
	u8 code = insn->code;

	init_regs(&rd, &rs, insn, ctx);

	switch (code) {
	/* dst = src */
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		if (imm == 1) {
			/* Special mov32 for zext */
			emit_zext_32(rd, ctx);
			break;
		}
		switch (insn->off) {
		case 0:
			emit_mv(rd, rs, ctx);
			break;
		case 8:
		case 16:
			emit_slli(RV_REG_T1, rs, 64 - insn->off, ctx);
			emit_srai(rd, RV_REG_T1, 64 - insn->off, ctx);
			break;
		case 32:
			emit_addiw(rd, rs, 0, ctx);
			break;
		}
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;

		/* dst = dst OP src */
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_X:
		emit_add(rd, rd, rs, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_X:
		if (is64)
			emit_sub(rd, rd, rs, ctx);
		else
			emit_subw(rd, rd, rs, ctx);

		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_X:
		emit_and(rd, rd, rs, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_X:
		emit_or(rd, rd, rs, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		emit_xor(rd, rd, rs, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_X:
		emit(is64 ? rv_mul(rd, rd, rs) : rv_mulw(rd, rd, rs), ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_DIV | BPF_X:
		if (off)
			emit(is64 ? rv_div(rd, rd, rs) : rv_divw(rd, rd, rs),
			     ctx);
		else
			emit(is64 ? rv_divu(rd, rd, rs) : rv_divuw(rd, rd, rs),
			     ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_X:
		if (off)
			emit(is64 ? rv_rem(rd, rd, rs) : rv_remw(rd, rd, rs),
			     ctx);
		else
			emit(is64 ? rv_remu(rd, rd, rs) : rv_remuw(rd, rd, rs),
			     ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_LSH | BPF_X:
		emit(is64 ? rv_sll(rd, rd, rs) : rv_sllw(rd, rd, rs), ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_X:
		emit(is64 ? rv_srl(rd, rd, rs) : rv_srlw(rd, rd, rs), ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit(is64 ? rv_sra(rd, rd, rs) : rv_sraw(rd, rd, rs), ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;

		/* dst = -dst */
	case BPF_ALU | BPF_NEG:
	case BPF_ALU64 | BPF_NEG:
		emit_sub(rd, RV_REG_ZERO, rd, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;

		/* dst = BSWAP##imm(dst) */
	case BPF_ALU | BPF_END | BPF_FROM_LE:
		switch (imm) {
		case 16:
			emit_slli(rd, rd, 48, ctx);
			emit_srli(rd, rd, 48, ctx);
			break;
		case 32:
			if (!aux->verifier_zext)
				emit_zext_32(rd, ctx);
			break;
		case 64:
			/* Do nothing */
			break;
		}
		break;

	case BPF_ALU | BPF_END | BPF_FROM_BE:
	case BPF_ALU64 | BPF_END | BPF_FROM_LE:
		emit_li(RV_REG_T2, 0, ctx);

		emit_andi(RV_REG_T1, rd, 0xff, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, RV_REG_T1, ctx);
		emit_slli(RV_REG_T2, RV_REG_T2, 8, ctx);
		emit_srli(rd, rd, 8, ctx);
		if (imm == 16)
			goto out_be;

		emit_andi(RV_REG_T1, rd, 0xff, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, RV_REG_T1, ctx);
		emit_slli(RV_REG_T2, RV_REG_T2, 8, ctx);
		emit_srli(rd, rd, 8, ctx);

		emit_andi(RV_REG_T1, rd, 0xff, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, RV_REG_T1, ctx);
		emit_slli(RV_REG_T2, RV_REG_T2, 8, ctx);
		emit_srli(rd, rd, 8, ctx);
		if (imm == 32)
			goto out_be;

		emit_andi(RV_REG_T1, rd, 0xff, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, RV_REG_T1, ctx);
		emit_slli(RV_REG_T2, RV_REG_T2, 8, ctx);
		emit_srli(rd, rd, 8, ctx);

		emit_andi(RV_REG_T1, rd, 0xff, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, RV_REG_T1, ctx);
		emit_slli(RV_REG_T2, RV_REG_T2, 8, ctx);
		emit_srli(rd, rd, 8, ctx);

		emit_andi(RV_REG_T1, rd, 0xff, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, RV_REG_T1, ctx);
		emit_slli(RV_REG_T2, RV_REG_T2, 8, ctx);
		emit_srli(rd, rd, 8, ctx);

		emit_andi(RV_REG_T1, rd, 0xff, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, RV_REG_T1, ctx);
		emit_slli(RV_REG_T2, RV_REG_T2, 8, ctx);
		emit_srli(rd, rd, 8, ctx);
out_be:
		emit_andi(RV_REG_T1, rd, 0xff, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, RV_REG_T1, ctx);

		emit_mv(rd, RV_REG_T2, ctx);
		break;

		/* dst = imm */
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_K:
		emit_imm(rd, imm, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;

		/* dst = dst OP imm */
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_ADD | BPF_K:
		if (is_12b_int(imm)) {
			emit_addi(rd, rd, imm, ctx);
		} else {
			emit_imm(RV_REG_T1, imm, ctx);
			emit_add(rd, rd, RV_REG_T1, ctx);
		}
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
		if (is_12b_int(-imm)) {
			emit_addi(rd, rd, -imm, ctx);
		} else {
			emit_imm(RV_REG_T1, imm, ctx);
			emit_sub(rd, rd, RV_REG_T1, ctx);
		}
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
		if (is_12b_int(imm)) {
			emit_andi(rd, rd, imm, ctx);
		} else {
			emit_imm(RV_REG_T1, imm, ctx);
			emit_and(rd, rd, RV_REG_T1, ctx);
		}
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU64 | BPF_OR | BPF_K:
		if (is_12b_int(imm)) {
			emit(rv_ori(rd, rd, imm), ctx);
		} else {
			emit_imm(RV_REG_T1, imm, ctx);
			emit_or(rd, rd, RV_REG_T1, ctx);
		}
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
		if (is_12b_int(imm)) {
			emit(rv_xori(rd, rd, imm), ctx);
		} else {
			emit_imm(RV_REG_T1, imm, ctx);
			emit_xor(rd, rd, RV_REG_T1, ctx);
		}
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_MUL | BPF_K:
		emit_imm(RV_REG_T1, imm, ctx);
		emit(is64 ? rv_mul(rd, rd, RV_REG_T1) :
			    rv_mulw(rd, rd, RV_REG_T1),
		     ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_K:
		emit_imm(RV_REG_T1, imm, ctx);
		if (off)
			emit(is64 ? rv_div(rd, rd, RV_REG_T1) :
				    rv_divw(rd, rd, RV_REG_T1),
			     ctx);
		else
			emit(is64 ? rv_divu(rd, rd, RV_REG_T1) :
				    rv_divuw(rd, rd, RV_REG_T1),
			     ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_MOD | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
		emit_imm(RV_REG_T1, imm, ctx);
		if (off)
			emit(is64 ? rv_rem(rd, rd, RV_REG_T1) :
				    rv_remw(rd, rd, RV_REG_T1),
			     ctx);
		else
			emit(is64 ? rv_remu(rd, rd, RV_REG_T1) :
				    rv_remuw(rd, rd, RV_REG_T1),
			     ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU64 | BPF_LSH | BPF_K:
		emit_slli(rd, rd, imm, ctx);

		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU64 | BPF_RSH | BPF_K:
		if (is64)
			emit_srli(rd, rd, imm, ctx);
		else
			emit(rv_srliw(rd, rd, imm), ctx);

		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_K:
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		if (is64)
			emit_srai(rd, rd, imm, ctx);
		else
			emit(rv_sraiw(rd, rd, imm), ctx);

		if (!is64 && !aux->verifier_zext)
			emit_zext_32(rd, ctx);
		break;

		/* JUMP off */
	case BPF_JMP | BPF_JA:
	case BPF_JMP32 | BPF_JA:
		if (BPF_CLASS(code) == BPF_JMP)
			rvoff = rv_offset(i, off, ctx);
		else
			rvoff = rv_offset(i, imm, ctx);
		ret = emit_jump_and_link(RV_REG_ZERO, rvoff, true, ctx);
		if (ret)
			return ret;
		break;

		/* IF (dst COND src) JUMP off */
	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP32 | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP32 | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP32 | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP32 | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP32 | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP32 | BPF_JSET | BPF_X:
		rvoff = rv_offset(i, off, ctx);
		if (!is64) {
			s = ctx->ninsns;
			if (is_signed_bpf_cond(BPF_OP(code)))
				emit_sext_32_rd_rs(&rd, &rs, ctx);
			else
				emit_zext_32_rd_rs(&rd, &rs, ctx);
			e = ctx->ninsns;

			/* Adjust for extra insns */
			rvoff -= ninsns_rvoff(e - s);
		}

		if (BPF_OP(code) == BPF_JSET) {
			/* Adjust for and */
			rvoff -= 4;
			emit_and(RV_REG_T1, rd, rs, ctx);
			emit_branch(BPF_JNE, RV_REG_T1, RV_REG_ZERO, rvoff,
				    ctx);
		} else {
			emit_branch(BPF_OP(code), rd, rs, rvoff, ctx);
		}
		break;

		/* IF (dst COND imm) JUMP off */
	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP32 | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP32 | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP32 | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP32 | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP32 | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP32 | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		rvoff = rv_offset(i, off, ctx);
		s = ctx->ninsns;
		if (imm) {
			emit_imm(RV_REG_T1, imm, ctx);
			rs = RV_REG_T1;
		} else {
			/* If imm is 0, simply use zero register. */
			rs = RV_REG_ZERO;
		}
		if (!is64) {
			if (is_signed_bpf_cond(BPF_OP(code)))
				emit_sext_32_rd(&rd, ctx);
			else
				emit_zext_32_rd_t1(&rd, ctx);
		}
		e = ctx->ninsns;

		/* Adjust for extra insns */
		rvoff -= ninsns_rvoff(e - s);
		emit_branch(BPF_OP(code), rd, rs, rvoff, ctx);
		break;

	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
		rvoff = rv_offset(i, off, ctx);
		s = ctx->ninsns;
		if (is_12b_int(imm)) {
			emit_andi(RV_REG_T1, rd, imm, ctx);
		} else {
			emit_imm(RV_REG_T1, imm, ctx);
			emit_and(RV_REG_T1, rd, RV_REG_T1, ctx);
		}
		/* For jset32, we should clear the upper 32 bits of t1, but
             * sign-extension is sufficient here and saves one instruction,
             * as t1 is used only in comparison against zero.
             */
		if (!is64 && imm < 0)
			emit_addiw(RV_REG_T1, RV_REG_T1, 0, ctx);
		e = ctx->ninsns;
		rvoff -= ninsns_rvoff(e - s);
		emit_branch(BPF_JNE, RV_REG_T1, RV_REG_ZERO, rvoff, ctx);
		break;

	case BPF_JMP | BPF_CALL: /* function call  TODO: fix */
	{
		bool fixed_addr;
		u64 addr;

		mark_call(ctx);
		ret = rvo_bpf_jit_get_func_addr(ctx->prog, insn, extra_pass,
						&addr, &fixed_addr);
		if (ret < 0)
			return ret;

		ret = emit_call(addr, fixed_addr, ctx);
		if (ret)
			return ret;

		if (insn->src_reg != BPF_PSEUDO_CALL)
			emit_mv(bpf_to_rv_reg(BPF_REG_0, &ctx->flags), RV_REG_A0, ctx);
		break;
	}
		/* tail call */
	case BPF_JMP | BPF_TAIL_CALL:
		if (emit_bpf_tail_call(i, ctx))
			return -1;
		break;

		/* function return */
	case BPF_JMP | BPF_EXIT:
		if (i == ctx->prog->len - 1)
			break;

		rvoff = epilogue_offset(ctx);
		ret = emit_jump_and_link(RV_REG_ZERO, rvoff, true, ctx);
		if (ret)
			return ret;
		break;

		/* dst = imm64 */
	case BPF_LD | BPF_IMM | BPF_DW: {
		struct bpf_insn insn1 = insn[1];
		u64 imm64;

		imm64 = (u64)insn1.imm << 32 | (u32)imm;
		if (bpf_pseudo_func(insn)) {
			/* fixed-length insns for extra jit pass */
			ret = emit_addr(rd, imm64, extra_pass, ctx);
			if (ret)
				return ret;
		} else {
			emit_imm(rd, imm64, ctx);
		}

		return 1;
	}

		/* LDX: dst = *(unsigned size *)(src + off) */
	case BPF_LDX | BPF_MEM | BPF_B:
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_LDX | BPF_MEM | BPF_DW:
	case BPF_LDX | BPF_PROBE_MEM | BPF_B:
	case BPF_LDX | BPF_PROBE_MEM | BPF_H:
	case BPF_LDX | BPF_PROBE_MEM | BPF_W:
	case BPF_LDX | BPF_PROBE_MEM | BPF_DW:
		/* LDSX: dst = *(signed size *)(src + off) */
	case BPF_LDX | BPF_MEMSX | BPF_B:
	case BPF_LDX | BPF_MEMSX | BPF_H:
	case BPF_LDX | BPF_MEMSX | BPF_W:
	case BPF_LDX | BPF_PROBE_MEMSX | BPF_B:
	case BPF_LDX | BPF_PROBE_MEMSX | BPF_H:
	case BPF_LDX | BPF_PROBE_MEMSX | BPF_W: {
		int insn_len, insns_start;
		bool sign_ext;

		sign_ext = BPF_MODE(insn->code) == BPF_MEMSX ||
			   BPF_MODE(insn->code) == BPF_PROBE_MEMSX;

		switch (BPF_SIZE(code)) {
		case BPF_B:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				if (sign_ext)
					emit(rv_lb(rd, off, rs), ctx);
				else
					emit(rv_lbu(rd, off, rs), ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rs, ctx);
			insns_start = ctx->ninsns;
			if (sign_ext)
				emit(rv_lb(rd, 0, RV_REG_T1), ctx);
			else
				emit(rv_lbu(rd, 0, RV_REG_T1), ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_H:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				if (sign_ext)
					emit(rv_lh(rd, off, rs), ctx);
				else
					emit(rv_lhu(rd, off, rs), ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rs, ctx);
			insns_start = ctx->ninsns;
			if (sign_ext)
				emit(rv_lh(rd, 0, RV_REG_T1), ctx);
			else
				emit(rv_lhu(rd, 0, RV_REG_T1), ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_W:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				if (sign_ext)
					emit(rv_lw(rd, off, rs), ctx);
				else
					emit(rv_lwu(rd, off, rs), ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rs, ctx);
			insns_start = ctx->ninsns;
			if (sign_ext)
				emit(rv_lw(rd, 0, RV_REG_T1), ctx);
			else
				emit(rv_lwu(rd, 0, RV_REG_T1), ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_DW:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit_ld(rd, off, rs, ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rs, ctx);
			insns_start = ctx->ninsns;
			emit_ld(rd, 0, RV_REG_T1, ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		}

		ret = add_exception_handler(insn, ctx, rd, insn_len);
		if (ret)
			return ret;

		if (BPF_SIZE(code) != BPF_DW && insn_is_zext(&insn[1]))
			return 1;
		break;
	}
		/* speculation barrier */
	case BPF_ST | BPF_NOSPEC:
		break;

		/* ST: *(size *)(dst + off) = imm */
	case BPF_ST | BPF_MEM | BPF_B:
		emit_imm(RV_REG_T1, imm, ctx);
		if (is_12b_int(off)) {
			emit(rv_sb(rd, off, RV_REG_T1), ctx);
			break;
		}

		emit_imm(RV_REG_T2, off, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, rd, ctx);
		emit(rv_sb(RV_REG_T2, 0, RV_REG_T1), ctx);
		break;

	case BPF_ST | BPF_MEM | BPF_H:
		emit_imm(RV_REG_T1, imm, ctx);
		if (is_12b_int(off)) {
			emit(rv_sh(rd, off, RV_REG_T1), ctx);
			break;
		}

		emit_imm(RV_REG_T2, off, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, rd, ctx);
		emit(rv_sh(RV_REG_T2, 0, RV_REG_T1), ctx);
		break;
	case BPF_ST | BPF_MEM | BPF_W:
		emit_imm(RV_REG_T1, imm, ctx);
		if (is_12b_int(off)) {
			emit_sw(rd, off, RV_REG_T1, ctx);
			break;
		}

		emit_imm(RV_REG_T2, off, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, rd, ctx);
		emit_sw(RV_REG_T2, 0, RV_REG_T1, ctx);
		break;
	case BPF_ST | BPF_MEM | BPF_DW:
		emit_imm(RV_REG_T1, imm, ctx);
		if (is_12b_int(off)) {
			emit_sd(rd, off, RV_REG_T1, ctx);
			break;
		}

		emit_imm(RV_REG_T2, off, ctx);
		emit_add(RV_REG_T2, RV_REG_T2, rd, ctx);
		emit_sd(RV_REG_T2, 0, RV_REG_T1, ctx);
		break;

		/* STX: *(size *)(dst + off) = src */
	case BPF_STX | BPF_MEM | BPF_B:
		if (is_12b_int(off)) {
			emit(rv_sb(rd, off, rs), ctx);
			break;
		}

		emit_imm(RV_REG_T1, off, ctx);
		emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
		emit(rv_sb(RV_REG_T1, 0, rs), ctx);
		break;
	case BPF_STX | BPF_MEM | BPF_H:
		if (is_12b_int(off)) {
			emit(rv_sh(rd, off, rs), ctx);
			break;
		}

		emit_imm(RV_REG_T1, off, ctx);
		emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
		emit(rv_sh(RV_REG_T1, 0, rs), ctx);
		break;
	case BPF_STX | BPF_MEM | BPF_W:
		if (is_12b_int(off)) {
			emit_sw(rd, off, rs, ctx);
			break;
		}

		emit_imm(RV_REG_T1, off, ctx);
		emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
		emit_sw(RV_REG_T1, 0, rs, ctx);
		break;
	case BPF_STX | BPF_MEM | BPF_DW:
		if (is_12b_int(off)) {
			emit_sd(rd, off, rs, ctx);
			break;
		}

		emit_imm(RV_REG_T1, off, ctx);
		emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
		emit_sd(RV_REG_T1, 0, rs, ctx);
		break;
	case BPF_STX | BPF_ATOMIC | BPF_W:
	case BPF_STX | BPF_ATOMIC | BPF_DW:
		emit_atomic(rd, rs, off, imm, BPF_SIZE(code) == BPF_DW, ctx);
		break;
	default:
		pr_err("bpf-jit: unknown opcode %02x\n", code);
		return -EINVAL;
	}

	return 0;
}
