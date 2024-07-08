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

static inline bool rvzbb_enabled(void)
{
	return IS_ENABLED(CONFIG_RISCV_ISA_ZBB) &&
	       riscv_has_extension_likely(RISCV_ISA_EXT_ZBB);
}

static bool is_32b_int(s64 val)
{
	return -(1L << 31) <= val && val < (1L << 31);
}

/***********************************
 * codegen
 **********************************/

/* Emit a 2-byte riscv compressed instruction. */
static inline void emitc(const u16 insn, rvo_jit_context *ctx)
{
	BUILD_BUG_ON(!rvc_enabled());

	if (ctx->insns)
		ctx->insns[ctx->ninsns] = insn;

	ctx->ninsns++;
}

/* Emit a 4-byte riscv instruction. */
static inline void emit(const u32 insn, rvo_jit_context *ctx)
{
	if (ctx->insns) {
		ctx->insns[ctx->ninsns] = insn;
		ctx->insns[ctx->ninsns + 1] = (insn >> 16);
	}

	ctx->ninsns += 2;
}

/***********************************
 * instr high lvl
 **********************************/

inline void emit_jalr(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_jalr(rd, rs, imm), ctx);
}
inline void emit_mv(u8 rd, u8 rs, rvo_jit_context *ctx)
{
	emit(rv_addi(rd, rs, 0), ctx);
}
inline void emit_add(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx)
{
	emit(rv_add(rd, rs1, rs2), ctx);
}
inline void emit_addi(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_addi(rd, rs, imm), ctx);
}
inline void emit_li(u8 rd, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_addi(rd, RV_REG_ZERO, imm), ctx);
}
inline void emit_lui(u8 rd, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_lui(rd, imm), ctx);
}
inline void emit_slli(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_slli(rd, rs, imm), ctx);
}
inline void emit_andi(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_andi(rd, rs, imm), ctx);
}
inline void emit_srli(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_srli(rd, rs, imm), ctx);
}
inline void emit_srai(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_srai(rd, rs, imm), ctx);
}
inline void emit_sub(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx)
{
	emit(rv_sub(rd, rs1, rs2), ctx);
}
inline void emit_or(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx)
{
	emit(rv_or(rd, rs1, rs2), ctx);
}
inline void emit_and(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx)
{
	emit(rv_and(rd, rs1, rs2), ctx);
}
inline void emit_xor(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx)
{
	emit(rv_xor(rd, rs1, rs2), ctx);
}
inline void emit_lw(u8 rd, s32 off, u8 rs1, rvo_jit_context *ctx)
{
	emit(rv_lw(rd, off, rs1), ctx);
}
inline void emit_sw(u8 rs1, s32 off, u8 rs2, rvo_jit_context *ctx)
{
	emit(rv_sw(rs1, off, rs2), ctx);
}

/* RV64-only helper functions. */

inline void emit_addiw(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx)
{
	emit(rv_addiw(rd, rs, imm), ctx);
}
inline void emit_ld(u8 rd, s32 off, u8 rs1, rvo_jit_context *ctx)
{
	emit(rv_ld(rd, off, rs1), ctx);
}
inline void emit_sd(u8 rs1, s32 off, u8 rs2, rvo_jit_context *ctx)
{
	emit(rv_sd(rs1, off, rs2), ctx);
}
inline void emit_subw(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx)
{
	emit(rv_subw(rd, rs1, rs2), ctx);
}
inline void emit_sextb(u8 rd, u8 rs, rvo_jit_context *ctx)
{
	if (rvzbb_enabled()) {
		emit(rvzbb_sextb(rd, rs), ctx);
		return;
	}

	emit_slli(rd, rs, 56, ctx);
	emit_srai(rd, rd, 56, ctx);
}
inline void emit_sexth(u8 rd, u8 rs, rvo_jit_context *ctx)
{
	if (rvzbb_enabled()) {
		emit(rvzbb_sexth(rd, rs), ctx);
		return;
	}

	emit_slli(rd, rs, 48, ctx);
	emit_srai(rd, rd, 48, ctx);
}
inline void emit_sextw(u8 rd, u8 rs, rvo_jit_context *ctx)
{
	emit_addiw(rd, rs, 0, ctx);
}
inline void emit_zexth(u8 rd, u8 rs, rvo_jit_context *ctx)
{
	if (rvzbb_enabled()) {
		emit(rvzbb_zexth(rd, rs), ctx);
		return;
	}

	emit_slli(rd, rs, 48, ctx);
	emit_srli(rd, rd, 48, ctx);
}
inline void emit_zextw(u8 rd, u8 rs, rvo_jit_context *ctx)
{
	emit_slli(rd, rs, 32, ctx);
	emit_srli(rd, rd, 32, ctx);
}

static void emit_imm(u8 rd, s64 val, rvo_jit_context *ctx)
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

/***********************************
 * main emit function
 **********************************/

int bpf_jit_emit_insn(const struct bpf_insn *insn, rvo_jit_context *ctx,
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
	u8 code = insn->code

		  switch (code)
	{
	/* dst = src */
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		if (insn_is_cast_user(insn)) {
			emit_mv(RV_REG_T1, rs, ctx);
			emit_zextw(RV_REG_T1, RV_REG_T1, ctx);
			emit_imm(rd, (ctx->user_vm_start >> 32) << 32, ctx);
			emit(rv_beq(RV_REG_T1, RV_REG_ZERO, 4), ctx);
			emit_or(RV_REG_T1, rd, RV_REG_T1, ctx);
			emit_mv(rd, RV_REG_T1, ctx);
			break;
		} else if (insn_is_mov_percpu_addr(insn)) {
			if (rd != rs)
				emit_mv(rd, rs, ctx);
#ifdef CONFIG_SMP
			/* Load current CPU number in T1 */
			emit_ld(RV_REG_T1, offsetof(struct thread_info, cpu),
				RV_REG_TP, ctx);
			/* << 3 because offsets are 8 bytes */
			emit_slli(RV_REG_T1, RV_REG_T1, 3, ctx);
			/* Load address of __per_cpu_offset array in T2 */
			emit_addr(RV_REG_T2, (u64)&__per_cpu_offset, extra_pass,
				  ctx);
			/* Add offset of current CPU to  __per_cpu_offset */
			emit_add(RV_REG_T1, RV_REG_T2, RV_REG_T1, ctx);
			/* Load __per_cpu_offset[cpu] in T1 */
			emit_ld(RV_REG_T1, 0, RV_REG_T1, ctx);
			/* Add the offset to Rd */
			emit_add(rd, rd, RV_REG_T1, ctx);
#endif
		}
		if (imm == 1) {
			/* Special mov32 for zext */
			emit_zextw(rd, rd, ctx);
			break;
		}
		switch (insn->off) {
		case 0:
			emit_mv(rd, rs, ctx);
			break;
		case 8:
			emit_sextb(rd, rs, ctx);
			break;
		case 16:
			emit_sexth(rd, rs, ctx);
			break;
		case 32:
			emit_sextw(rd, rs, ctx);
			break;
		}
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;

	/* dst = dst OP src */
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_X:
		emit_add(rd, rd, rs, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_X:
		if (is64)
			emit_sub(rd, rd, rs, ctx);
		else
			emit_subw(rd, rd, rs, ctx);

		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_X:
		emit_and(rd, rd, rs, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_X:
		emit_or(rd, rd, rs, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		emit_xor(rd, rd, rs, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_X:
		emit(is64 ? rv_mul(rd, rd, rs) : rv_mulw(rd, rd, rs), ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_LSH | BPF_X:
		emit(is64 ? rv_sll(rd, rd, rs) : rv_sllw(rd, rd, rs), ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_X:
		emit(is64 ? rv_srl(rd, rd, rs) : rv_srlw(rd, rd, rs), ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit(is64 ? rv_sra(rd, rd, rs) : rv_sraw(rd, rd, rs), ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;

	/* dst = -dst */
	case BPF_ALU | BPF_NEG:
	case BPF_ALU64 | BPF_NEG:
		emit_sub(rd, RV_REG_ZERO, rd, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;

	/* dst = BSWAP##imm(dst) */
	case BPF_ALU | BPF_END | BPF_FROM_LE:
		switch (imm) {
		case 16:
			emit_zexth(rd, rd, ctx);
			break;
		case 32:
			if (!aux->verifier_zext)
				emit_zextw(rd, rd, ctx);
			break;
		case 64:
			/* Do nothing */
			break;
		}
		break;
	case BPF_ALU | BPF_END | BPF_FROM_BE:
	case BPF_ALU64 | BPF_END | BPF_FROM_LE:
		emit_bswap(rd, imm, ctx);
		break;

	/* dst = imm */
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_K:
		emit_imm(rd, imm, ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_MUL | BPF_K:
		emit_imm(RV_REG_T1, imm, ctx);
		emit(is64 ? rv_mul(rd, rd, RV_REG_T1) :
			    rv_mulw(rd, rd, RV_REG_T1),
		     ctx);
		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
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
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU64 | BPF_LSH | BPF_K:
		emit_slli(rd, rd, imm, ctx);

		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU64 | BPF_RSH | BPF_K:
		if (is64)
			emit_srli(rd, rd, imm, ctx);
		else
			emit(rv_srliw(rd, rd, imm), ctx);

		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_K:
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		if (is64)
			emit_srai(rd, rd, imm, ctx);
		else
			emit(rv_sraiw(rd, rd, imm), ctx);

		if (!is64 && !aux->verifier_zext)
			emit_zextw(rd, rd, ctx);
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
			if (is_signed_bpf_cond(BPF_OP(code))) {
				emit_sextw_alt(&rs, RV_REG_T1, ctx);
				emit_sextw_alt(&rd, RV_REG_T2, ctx);
			} else {
				emit_zextw_alt(&rs, RV_REG_T1, ctx);
				emit_zextw_alt(&rd, RV_REG_T2, ctx);
			}
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
		if (imm)
			emit_imm(RV_REG_T1, imm, ctx);
		rs = imm ? RV_REG_T1 : RV_REG_ZERO;
		if (!is64) {
			if (is_signed_bpf_cond(BPF_OP(code))) {
				emit_sextw_alt(&rd, RV_REG_T2, ctx);
				/* rs has been sign extended */
			} else {
				emit_zextw_alt(&rd, RV_REG_T2, ctx);
				if (imm)
					emit_zextw(rs, rs, ctx);
			}
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
			emit_sextw(RV_REG_T1, RV_REG_T1, ctx);
		e = ctx->ninsns;
		rvoff -= ninsns_rvoff(e - s);
		emit_branch(BPF_JNE, RV_REG_T1, RV_REG_ZERO, rvoff, ctx);
		break;

	/* function call */
	case BPF_JMP | BPF_CALL: {
		bool fixed_addr;
		u64 addr;

		/* Inline calls to bpf_get_smp_processor_id()
		 *
		 * RV_REG_TP holds the address of the current CPU's task_struct and thread_info is
		 * at offset 0 in task_struct.
		 * Load cpu from thread_info:
		 *     Set R0 to ((struct thread_info *)(RV_REG_TP))->cpu
		 *
		 * This replicates the implementation of raw_smp_processor_id() on RISCV
		 */
		if (insn->src_reg == 0 &&
		    insn->imm == BPF_FUNC_get_smp_processor_id) {
			/* Load current CPU number in R0 */
			emit_ld(bpf_to_rv_reg(BPF_REG_0, ctx),
				offsetof(struct thread_info, cpu), RV_REG_TP,
				ctx);
			break;
		}

		mark_call(ctx);
		ret = bpf_jit_get_func_addr(ctx->prog, insn, extra_pass, &addr,
					    &fixed_addr);
		if (ret < 0)
			return ret;

		if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL) {
			const struct btf_func_model *fm;
			int idx;

			fm = bpf_jit_find_kfunc_model(ctx->prog, insn);
			if (!fm)
				return -EINVAL;

			for (idx = 0; idx < fm->nr_args; idx++) {
				u8 reg = bpf_to_rv_reg(BPF_REG_1 + idx, ctx);

				if (fm->arg_size[idx] == sizeof(int))
					emit_sextw(reg, reg, ctx);
			}
		}

		ret = emit_call(addr, fixed_addr, ctx);
		if (ret)
			return ret;

		if (insn->src_reg != BPF_PSEUDO_CALL)
			emit_mv(bpf_to_rv_reg(BPF_REG_0, ctx), RV_REG_A0, ctx);
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
	case BPF_LDX | BPF_PROBE_MEMSX | BPF_W:
	/* LDX | PROBE_MEM32: dst = *(unsigned size *)(src + RV_REG_ARENA + off) */
	case BPF_LDX | BPF_PROBE_MEM32 | BPF_B:
	case BPF_LDX | BPF_PROBE_MEM32 | BPF_H:
	case BPF_LDX | BPF_PROBE_MEM32 | BPF_W:
	case BPF_LDX | BPF_PROBE_MEM32 | BPF_DW: {
		int insn_len, insns_start;
		bool sign_ext;

		sign_ext = BPF_MODE(insn->code) == BPF_MEMSX ||
			   BPF_MODE(insn->code) == BPF_PROBE_MEMSX;

		if (BPF_MODE(insn->code) == BPF_PROBE_MEM32) {
			emit_add(RV_REG_T2, rs, RV_REG_ARENA, ctx);
			rs = RV_REG_T2;
		}

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

	case BPF_ST | BPF_PROBE_MEM32 | BPF_B:
	case BPF_ST | BPF_PROBE_MEM32 | BPF_H:
	case BPF_ST | BPF_PROBE_MEM32 | BPF_W:
	case BPF_ST | BPF_PROBE_MEM32 | BPF_DW: {
		int insn_len, insns_start;

		emit_add(RV_REG_T3, rd, RV_REG_ARENA, ctx);
		rd = RV_REG_T3;

		/* Load imm to a register then store it */
		emit_imm(RV_REG_T1, imm, ctx);

		switch (BPF_SIZE(code)) {
		case BPF_B:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit(rv_sb(rd, off, RV_REG_T1), ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T2, off, ctx);
			emit_add(RV_REG_T2, RV_REG_T2, rd, ctx);
			insns_start = ctx->ninsns;
			emit(rv_sb(RV_REG_T2, 0, RV_REG_T1), ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_H:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit(rv_sh(rd, off, RV_REG_T1), ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T2, off, ctx);
			emit_add(RV_REG_T2, RV_REG_T2, rd, ctx);
			insns_start = ctx->ninsns;
			emit(rv_sh(RV_REG_T2, 0, RV_REG_T1), ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_W:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit_sw(rd, off, RV_REG_T1, ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T2, off, ctx);
			emit_add(RV_REG_T2, RV_REG_T2, rd, ctx);
			insns_start = ctx->ninsns;
			emit_sw(RV_REG_T2, 0, RV_REG_T1, ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_DW:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit_sd(rd, off, RV_REG_T1, ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T2, off, ctx);
			emit_add(RV_REG_T2, RV_REG_T2, rd, ctx);
			insns_start = ctx->ninsns;
			emit_sd(RV_REG_T2, 0, RV_REG_T1, ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		}

		ret = add_exception_handler(insn, ctx, REG_DONT_CLEAR_MARKER,
					    insn_len);
		if (ret)
			return ret;

		break;
	}

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

	case BPF_STX | BPF_PROBE_MEM32 | BPF_B:
	case BPF_STX | BPF_PROBE_MEM32 | BPF_H:
	case BPF_STX | BPF_PROBE_MEM32 | BPF_W:
	case BPF_STX | BPF_PROBE_MEM32 | BPF_DW: {
		int insn_len, insns_start;

		emit_add(RV_REG_T2, rd, RV_REG_ARENA, ctx);
		rd = RV_REG_T2;

		switch (BPF_SIZE(code)) {
		case BPF_B:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit(rv_sb(rd, off, rs), ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
			insns_start = ctx->ninsns;
			emit(rv_sb(RV_REG_T1, 0, rs), ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_H:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit(rv_sh(rd, off, rs), ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
			insns_start = ctx->ninsns;
			emit(rv_sh(RV_REG_T1, 0, rs), ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_W:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit_sw(rd, off, rs, ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
			insns_start = ctx->ninsns;
			emit_sw(RV_REG_T1, 0, rs, ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		case BPF_DW:
			if (is_12b_int(off)) {
				insns_start = ctx->ninsns;
				emit_sd(rd, off, rs, ctx);
				insn_len = ctx->ninsns - insns_start;
				break;
			}

			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
			insns_start = ctx->ninsns;
			emit_sd(RV_REG_T1, 0, rs, ctx);
			insn_len = ctx->ninsns - insns_start;
			break;
		}

		ret = add_exception_handler(insn, ctx, REG_DONT_CLEAR_MARKER,
					    insn_len);
		if (ret)
			return ret;

		break;
	}

	default:
		pr_err("bpf-jit: unknown opcode %02x\n", code);
		return -EINVAL;
	}

	return 0;
}
