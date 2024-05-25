//
// Created by Davide Collovigh on 24/05/24.
//

#include "jit.h"

inline int ninsns_rvoff(int ninsns)
{
	return ninsns << 1;
}

inline void bpf_fill_ill_insns(void *area, unsigned int size)
{
	memset(area, 0, size);
}

inline void emit(const u32 insn, struct rv_jit_context *ctx)
{
	if (ctx->insns) {
		ctx->insns[ctx->ninsns] = insn;
		ctx->insns[ctx->ninsns + 1] = (insn >> 16);
	}

	ctx->ninsns += 2;
}

inline void emitc(const u16 insn, struct rv_jit_context *ctx)
{
	BUILD_BUG_ON(!rvc_enabled());

	if (ctx->insns)
		ctx->insns[ctx->ninsns] = insn;

	ctx->ninsns++;
}

inline int epilogue_offset(struct rv_jit_context *ctx)
{
	int to = ctx->epilogue_offset, from = ctx->ninsns;

	return ninsns_rvoff(to - from);
}

inline int rv_offset(int insn, int off, struct rv_jit_context *ctx)
{
	int from, to;

	off++; /* BPF branch is from PC+1, RV is from PC */
	from = (insn > 0) ? ctx->offset[insn - 1] : ctx->prologue_len;
	to = (insn + off > 0) ? ctx->offset[insn + off - 1] : ctx->prologue_len;
	return ninsns_rvoff(to - from);
}

/*
 * vars checks
 */

inline bool is_6b_int(long val)
{
	return -(1L << 5) <= val && val < (1L << 5);
}

inline bool is_7b_uint(unsigned long val)
{
	return val < (1UL << 7);
}

inline bool is_8b_uint(unsigned long val)
{
	return val < (1UL << 8);
}

inline bool is_9b_uint(unsigned long val)
{
	return val < (1UL << 9);
}

inline bool is_10b_int(long val)
{
	return -(1L << 9) <= val && val < (1L << 9);
}

inline bool is_10b_uint(unsigned long val)
{
	return val < (1UL << 10);
}

inline bool is_12b_int(long val)
{
	return -(1L << 11) <= val && val < (1L << 11);
}

inline int is_12b_check(int off, int insn)
{
	if (!is_12b_int(off)) {
		pr_err("bpf-jit: insn=%d 12b < offset=%d not supported yet!\n",
		       insn, (int)off);
		return -1;
	}
	return 0;
}

inline bool is_13b_int(long val)
{
	return -(1L << 12) <= val && val < (1L << 12);
}

inline bool is_21b_int(long val)
{
	return -(1L << 20) <= val && val < (1L << 20);
}

/*
 * Instruction formats.
 */

inline u32 rv_r_insn(u8 funct7, u8 rs2, u8 rs1, u8 funct3, u8 rd,
			    u8 opcode)
{
	return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
	       (rd << 7) | opcode;
}

inline u32 rv_i_insn(u16 imm11_0, u8 rs1, u8 funct3, u8 rd, u8 opcode)
{
	return (imm11_0 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) |
	       opcode;
}

inline u32 rv_s_insn(u16 imm11_0, u8 rs2, u8 rs1, u8 funct3, u8 opcode)
{
	u8 imm11_5 = imm11_0 >> 5, imm4_0 = imm11_0 & 0x1f;

	return (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
	       (imm4_0 << 7) | opcode;
}

inline u32 rv_b_insn(u16 imm12_1, u8 rs2, u8 rs1, u8 funct3, u8 opcode)
{
	u8 imm12 = ((imm12_1 & 0x800) >> 5) | ((imm12_1 & 0x3f0) >> 4);
	u8 imm4_1 = ((imm12_1 & 0xf) << 1) | ((imm12_1 & 0x400) >> 10);

	return (imm12 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
	       (imm4_1 << 7) | opcode;
}

inline u32 rv_u_insn(u32 imm31_12, u8 rd, u8 opcode)
{
	return (imm31_12 << 12) | (rd << 7) | opcode;
}

inline u32 rv_j_insn(u32 imm20_1, u8 rd, u8 opcode)
{
	u32 imm;

	imm = (imm20_1 & 0x80000) | ((imm20_1 & 0x3ff) << 9) |
	      ((imm20_1 & 0x400) >> 2) | ((imm20_1 & 0x7f800) >> 11);

	return (imm << 12) | (rd << 7) | opcode;
}

inline u32 rv_amo_insn(u8 funct5, u8 aq, u8 rl, u8 rs2, u8 rs1,
			      u8 funct3, u8 rd, u8 opcode)
{
	u8 funct7 = (funct5 << 2) | (aq << 1) | rl;

	return rv_r_insn(funct7, rs2, rs1, funct3, rd, opcode);
}

/*
 * RISC-V compressed instruction formats.
 */

inline u16 rv_cr_insn(u8 funct4, u8 rd, u8 rs2, u8 op)
{
	return (funct4 << 12) | (rd << 7) | (rs2 << 2) | op;
}

inline u16 rv_ci_insn(u8 funct3, u32 imm6, u8 rd, u8 op)
{
	u32 imm;

	imm = ((imm6 & 0x20) << 7) | ((imm6 & 0x1f) << 2);
	return (funct3 << 13) | (rd << 7) | op | imm;
}

inline u16 rv_css_insn(u8 funct3, u32 uimm, u8 rs2, u8 op)
{
	return (funct3 << 13) | (uimm << 7) | (rs2 << 2) | op;
}

inline u16 rv_ciw_insn(u8 funct3, u32 uimm, u8 rd, u8 op)
{
	return (funct3 << 13) | (uimm << 5) | ((rd & 0x7) << 2) | op;
}

inline u16 rv_cl_insn(u8 funct3, u32 imm_hi, u8 rs1, u32 imm_lo, u8 rd,
			     u8 op)
{
	return (funct3 << 13) | (imm_hi << 10) | ((rs1 & 0x7) << 7) |
	       (imm_lo << 5) | ((rd & 0x7) << 2) | op;
}

inline u16 rv_cs_insn(u8 funct3, u32 imm_hi, u8 rs1, u32 imm_lo, u8 rs2,
			     u8 op)
{
	return (funct3 << 13) | (imm_hi << 10) | ((rs1 & 0x7) << 7) |
	       (imm_lo << 5) | ((rs2 & 0x7) << 2) | op;
}

inline u16 rv_ca_insn(u8 funct6, u8 rd, u8 funct2, u8 rs2, u8 op)
{
	return (funct6 << 10) | ((rd & 0x7) << 7) | (funct2 << 5) |
	       ((rs2 & 0x7) << 2) | op;
}

inline u16 rv_cb_insn(u8 funct3, u32 imm6, u8 funct2, u8 rd, u8 op)
{
	u32 imm;

	imm = ((imm6 & 0x20) << 7) | ((imm6 & 0x1f) << 2);
	return (funct3 << 13) | (funct2 << 10) | ((rd & 0x7) << 7) | op | imm;
}

/* Instructions shared by both RV32 and RV64. */

inline u32 rv_addi(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 0, rd, 0x13);
}

inline u32 rv_andi(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 7, rd, 0x13);
}

inline u32 rv_ori(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 6, rd, 0x13);
}

inline u32 rv_xori(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 4, rd, 0x13);
}

inline u32 rv_slli(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 1, rd, 0x13);
}

inline u32 rv_srli(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 5, rd, 0x13);
}

inline u32 rv_srai(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(0x400 | imm11_0, rs1, 5, rd, 0x13);
}

inline u32 rv_lui(u8 rd, u32 imm31_12)
{
	return rv_u_insn(imm31_12, rd, 0x37);
}

inline u32 rv_auipc(u8 rd, u32 imm31_12)
{
	return rv_u_insn(imm31_12, rd, 0x17);
}

inline u32 rv_add(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 0, rd, 0x33);
}

inline u32 rv_sub(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0x20, rs2, rs1, 0, rd, 0x33);
}

inline u32 rv_sltu(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 3, rd, 0x33);
}

inline u32 rv_and(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 7, rd, 0x33);
}

inline u32 rv_or(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 6, rd, 0x33);
}

inline u32 rv_xor(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 4, rd, 0x33);
}

inline u32 rv_sll(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 1, rd, 0x33);
}

inline u32 rv_srl(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 5, rd, 0x33);
}

inline u32 rv_sra(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0x20, rs2, rs1, 5, rd, 0x33);
}

inline u32 rv_mul(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 0, rd, 0x33);
}

inline u32 rv_mulhu(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 3, rd, 0x33);
}

inline u32 rv_div(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 4, rd, 0x33);
}

inline u32 rv_divu(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 5, rd, 0x33);
}

inline u32 rv_rem(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 6, rd, 0x33);
}

inline u32 rv_remu(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 7, rd, 0x33);
}

inline u32 rv_jal(u8 rd, u32 imm20_1)
{
	return rv_j_insn(imm20_1, rd, 0x6f);
}

inline u32 rv_jalr(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 0, rd, 0x67);
}

inline u32 rv_beq(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_b_insn(imm12_1, rs2, rs1, 0, 0x63);
}

inline u32 rv_bne(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_b_insn(imm12_1, rs2, rs1, 1, 0x63);
}

inline u32 rv_bltu(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_b_insn(imm12_1, rs2, rs1, 6, 0x63);
}

inline u32 rv_bgtu(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_bltu(rs2, rs1, imm12_1);
}

inline u32 rv_bgeu(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_b_insn(imm12_1, rs2, rs1, 7, 0x63);
}

inline u32 rv_bleu(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_bgeu(rs2, rs1, imm12_1);
}

inline u32 rv_blt(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_b_insn(imm12_1, rs2, rs1, 4, 0x63);
}

inline u32 rv_bgt(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_blt(rs2, rs1, imm12_1);
}

inline u32 rv_bge(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_b_insn(imm12_1, rs2, rs1, 5, 0x63);
}

inline u32 rv_ble(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_bge(rs2, rs1, imm12_1);
}

inline u32 rv_lb(u8 rd, u16 imm11_0, u8 rs1)
{
	return rv_i_insn(imm11_0, rs1, 0, rd, 0x03);
}

inline u32 rv_lh(u8 rd, u16 imm11_0, u8 rs1)
{
	return rv_i_insn(imm11_0, rs1, 1, rd, 0x03);
}

inline u32 rv_lw(u8 rd, u16 imm11_0, u8 rs1)
{
	return rv_i_insn(imm11_0, rs1, 2, rd, 0x03);
}

inline u32 rv_lbu(u8 rd, u16 imm11_0, u8 rs1)
{
	return rv_i_insn(imm11_0, rs1, 4, rd, 0x03);
}

inline u32 rv_lhu(u8 rd, u16 imm11_0, u8 rs1)
{
	return rv_i_insn(imm11_0, rs1, 5, rd, 0x03);
}

inline u32 rv_sb(u8 rs1, u16 imm11_0, u8 rs2)
{
	return rv_s_insn(imm11_0, rs2, rs1, 0, 0x23);
}

inline u32 rv_sh(u8 rs1, u16 imm11_0, u8 rs2)
{
	return rv_s_insn(imm11_0, rs2, rs1, 1, 0x23);
}

inline u32 rv_sw(u8 rs1, u16 imm11_0, u8 rs2)
{
	return rv_s_insn(imm11_0, rs2, rs1, 2, 0x23);
}

inline u32 rv_amoadd_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0, aq, rl, rs2, rs1, 2, rd, 0x2f);
}

inline u32 rv_amoand_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0xc, aq, rl, rs2, rs1, 2, rd, 0x2f);
}

inline u32 rv_amoor_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x8, aq, rl, rs2, rs1, 2, rd, 0x2f);
}

inline u32 rv_amoxor_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x4, aq, rl, rs2, rs1, 2, rd, 0x2f);
}

inline u32 rv_amoswap_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x1, aq, rl, rs2, rs1, 2, rd, 0x2f);
}

inline u32 rv_lr_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x2, aq, rl, rs2, rs1, 2, rd, 0x2f);
}

inline u32 rv_sc_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x3, aq, rl, rs2, rs1, 2, rd, 0x2f);
}

inline u32 rv_fence(u8 pred, u8 succ)
{
	u16 imm11_0 = pred << 4 | succ;

	return rv_i_insn(imm11_0, 0, 0, 0, 0xf);
}

inline u32 rv_nop(void)
{
	return rv_i_insn(0, 0, 0, 0, 0x13);
}

/* RVC instrutions. */

inline u16 rvc_addi4spn(u8 rd, u32 imm10)
{
	u32 imm;

	imm = ((imm10 & 0x30) << 2) | ((imm10 & 0x3c0) >> 4) |
	      ((imm10 & 0x4) >> 1) | ((imm10 & 0x8) >> 3);
	return rv_ciw_insn(0x0, imm, rd, 0x0);
}

inline u16 rvc_lw(u8 rd, u32 imm7, u8 rs1)
{
	u32 imm_hi, imm_lo;

	imm_hi = (imm7 & 0x38) >> 3;
	imm_lo = ((imm7 & 0x4) >> 1) | ((imm7 & 0x40) >> 6);
	return rv_cl_insn(0x2, imm_hi, rs1, imm_lo, rd, 0x0);
}

inline u16 rvc_sw(u8 rs1, u32 imm7, u8 rs2)
{
	u32 imm_hi, imm_lo;

	imm_hi = (imm7 & 0x38) >> 3;
	imm_lo = ((imm7 & 0x4) >> 1) | ((imm7 & 0x40) >> 6);
	return rv_cs_insn(0x6, imm_hi, rs1, imm_lo, rs2, 0x0);
}

inline u16 rvc_addi(u8 rd, u32 imm6)
{
	return rv_ci_insn(0, imm6, rd, 0x1);
}

inline u16 rvc_li(u8 rd, u32 imm6)
{
	return rv_ci_insn(0x2, imm6, rd, 0x1);
}

inline u16 rvc_addi16sp(u32 imm10)
{
	u32 imm;

	imm = ((imm10 & 0x200) >> 4) | (imm10 & 0x10) | ((imm10 & 0x40) >> 3) |
	      ((imm10 & 0x180) >> 6) | ((imm10 & 0x20) >> 5);
	return rv_ci_insn(0x3, imm, RV_REG_SP, 0x1);
}

inline u16 rvc_lui(u8 rd, u32 imm6)
{
	return rv_ci_insn(0x3, imm6, rd, 0x1);
}

inline u16 rvc_srli(u8 rd, u32 imm6)
{
	return rv_cb_insn(0x4, imm6, 0, rd, 0x1);
}

inline u16 rvc_srai(u8 rd, u32 imm6)
{
	return rv_cb_insn(0x4, imm6, 0x1, rd, 0x1);
}

inline u16 rvc_andi(u8 rd, u32 imm6)
{
	return rv_cb_insn(0x4, imm6, 0x2, rd, 0x1);
}

inline u16 rvc_sub(u8 rd, u8 rs)
{
	return rv_ca_insn(0x23, rd, 0, rs, 0x1);
}

inline u16 rvc_xor(u8 rd, u8 rs)
{
	return rv_ca_insn(0x23, rd, 0x1, rs, 0x1);
}

inline u16 rvc_or(u8 rd, u8 rs)
{
	return rv_ca_insn(0x23, rd, 0x2, rs, 0x1);
}

inline u16 rvc_and(u8 rd, u8 rs)
{
	return rv_ca_insn(0x23, rd, 0x3, rs, 0x1);
}

inline u16 rvc_slli(u8 rd, u32 imm6)
{
	return rv_ci_insn(0, imm6, rd, 0x2);
}

inline u16 rvc_lwsp(u8 rd, u32 imm8)
{
	u32 imm;

	imm = ((imm8 & 0xc0) >> 6) | (imm8 & 0x3c);
	return rv_ci_insn(0x2, imm, rd, 0x2);
}

inline u16 rvc_jr(u8 rs1)
{
	return rv_cr_insn(0x8, rs1, RV_REG_ZERO, 0x2);
}

inline u16 rvc_mv(u8 rd, u8 rs)
{
	return rv_cr_insn(0x8, rd, rs, 0x2);
}

inline u16 rvc_jalr(u8 rs1)
{
	return rv_cr_insn(0x9, rs1, RV_REG_ZERO, 0x2);
}

inline u16 rvc_add(u8 rd, u8 rs)
{
	return rv_cr_insn(0x9, rd, rs, 0x2);
}

inline u16 rvc_swsp(u32 imm8, u8 rs2)
{
	u32 imm;

	imm = (imm8 & 0x3c) | ((imm8 & 0xc0) >> 6);
	return rv_css_insn(0x6, imm, rs2, 0x2);
}

#if __riscv_xlen == 64

inline u32 rv_addiw(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 0, rd, 0x1b);
}

inline u32 rv_slliw(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 1, rd, 0x1b);
}

inline u32 rv_srliw(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 5, rd, 0x1b);
}

inline u32 rv_sraiw(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(0x400 | imm11_0, rs1, 5, rd, 0x1b);
}

inline u32 rv_addw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 0, rd, 0x3b);
}

inline u32 rv_subw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0x20, rs2, rs1, 0, rd, 0x3b);
}

inline u32 rv_sllw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 1, rd, 0x3b);
}

inline u32 rv_srlw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 5, rd, 0x3b);
}

inline u32 rv_sraw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0x20, rs2, rs1, 5, rd, 0x3b);
}

inline u32 rv_mulw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 0, rd, 0x3b);
}

inline u32 rv_divw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 4, rd, 0x3b);
}

inline u32 rv_divuw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 5, rd, 0x3b);
}

inline u32 rv_remw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 6, rd, 0x3b);
}

inline u32 rv_remuw(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 7, rd, 0x3b);
}

inline u32 rv_ld(u8 rd, u16 imm11_0, u8 rs1)
{
	return rv_i_insn(imm11_0, rs1, 3, rd, 0x03);
}

inline u32 rv_lwu(u8 rd, u16 imm11_0, u8 rs1)
{
	return rv_i_insn(imm11_0, rs1, 6, rd, 0x03);
}

inline u32 rv_sd(u8 rs1, u16 imm11_0, u8 rs2)
{
	return rv_s_insn(imm11_0, rs2, rs1, 3, 0x23);
}

inline u32 rv_amoadd_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0, aq, rl, rs2, rs1, 3, rd, 0x2f);
}

inline u32 rv_amoand_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0xc, aq, rl, rs2, rs1, 3, rd, 0x2f);
}

inline u32 rv_amoor_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x8, aq, rl, rs2, rs1, 3, rd, 0x2f);
}

inline u32 rv_amoxor_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x4, aq, rl, rs2, rs1, 3, rd, 0x2f);
}

inline u32 rv_amoswap_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x1, aq, rl, rs2, rs1, 3, rd, 0x2f);
}

inline u32 rv_lr_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x2, aq, rl, rs2, rs1, 3, rd, 0x2f);
}

inline u32 rv_sc_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	return rv_amo_insn(0x3, aq, rl, rs2, rs1, 3, rd, 0x2f);
}

/* RV64-only RVC instructions. */

inline u16 rvc_ld(u8 rd, u32 imm8, u8 rs1)
{
	u32 imm_hi, imm_lo;

	imm_hi = (imm8 & 0x38) >> 3;
	imm_lo = (imm8 & 0xc0) >> 6;
	return rv_cl_insn(0x3, imm_hi, rs1, imm_lo, rd, 0x0);
}

inline u16 rvc_sd(u8 rs1, u32 imm8, u8 rs2)
{
	u32 imm_hi, imm_lo;

	imm_hi = (imm8 & 0x38) >> 3;
	imm_lo = (imm8 & 0xc0) >> 6;
	return rv_cs_insn(0x7, imm_hi, rs1, imm_lo, rs2, 0x0);
}

inline u16 rvc_subw(u8 rd, u8 rs)
{
	return rv_ca_insn(0x27, rd, 0, rs, 0x1);
}

inline u16 rvc_addiw(u8 rd, u32 imm6)
{
	return rv_ci_insn(0x1, imm6, rd, 0x1);
}

inline u16 rvc_ldsp(u8 rd, u32 imm9)
{
	u32 imm;

	imm = ((imm9 & 0x1c0) >> 6) | (imm9 & 0x38);
	return rv_ci_insn(0x3, imm, rd, 0x2);
}

inline u16 rvc_sdsp(u32 imm9, u8 rs2)
{
	u32 imm;

	imm = (imm9 & 0x38) | ((imm9 & 0x1c0) >> 6);
	return rv_css_insn(0x7, imm, rs2, 0x2);
}

#endif /* __riscv_xlen == 64 */

/* Helper functions that emit RVC instructions when possible. */

inline void emit_jalr(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd == RV_REG_RA && rs && !imm)
		emitc(rvc_jalr(rs), ctx);
	else if (rvc_enabled() && !rd && rs && !imm)
		emitc(rvc_jr(rs), ctx);
	else
		emit(rv_jalr(rd, rs, imm), ctx);
}

inline void emit_mv(u8 rd, u8 rs, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rs)
		emitc(rvc_mv(rd, rs), ctx);
	else
		emit(rv_addi(rd, rs, 0), ctx);
}

inline void emit_add(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rd == rs1 && rs2)
		emitc(rvc_add(rd, rs2), ctx);
	else
		emit(rv_add(rd, rs1, rs2), ctx);
}

inline void emit_addi(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd == RV_REG_SP && rd == rs && is_10b_int(imm) &&
	    imm && !(imm & 0xf))
		emitc(rvc_addi16sp(imm), ctx);
	else if (rvc_enabled() && is_creg(rd) && rs == RV_REG_SP &&
		 is_10b_uint(imm) && !(imm & 0x3) && imm)
		emitc(rvc_addi4spn(rd, imm), ctx);
	else if (rvc_enabled() && rd && rd == rs && imm && is_6b_int(imm))
		emitc(rvc_addi(rd, imm), ctx);
	else
		emit(rv_addi(rd, rs, imm), ctx);
}

inline void emit_li(u8 rd, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && is_6b_int(imm))
		emitc(rvc_li(rd, imm), ctx);
	else
		emit(rv_addi(rd, RV_REG_ZERO, imm), ctx);
}

inline void emit_lui(u8 rd, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rd != RV_REG_SP && is_6b_int(imm) && imm)
		emitc(rvc_lui(rd, imm), ctx);
	else
		emit(rv_lui(rd, imm), ctx);
}

inline void emit_slli(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rd == rs && imm && (u32)imm < __riscv_xlen)
		emitc(rvc_slli(rd, imm), ctx);
	else
		emit(rv_slli(rd, rs, imm), ctx);
}

inline void emit_andi(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs && is_6b_int(imm))
		emitc(rvc_andi(rd, imm), ctx);
	else
		emit(rv_andi(rd, rs, imm), ctx);
}

inline void emit_srli(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs && imm &&
	    (u32)imm < __riscv_xlen)
		emitc(rvc_srli(rd, imm), ctx);
	else
		emit(rv_srli(rd, rs, imm), ctx);
}

inline void emit_srai(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs && imm &&
	    (u32)imm < __riscv_xlen)
		emitc(rvc_srai(rd, imm), ctx);
	else
		emit(rv_srai(rd, rs, imm), ctx);
}

inline void emit_sub(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_sub(rd, rs2), ctx);
	else
		emit(rv_sub(rd, rs1, rs2), ctx);
}

inline void emit_or(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_or(rd, rs2), ctx);
	else
		emit(rv_or(rd, rs1, rs2), ctx);
}

inline void emit_and(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_and(rd, rs2), ctx);
	else
		emit(rv_and(rd, rs1, rs2), ctx);
}

inline void emit_xor(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_xor(rd, rs2), ctx);
	else
		emit(rv_xor(rd, rs1, rs2), ctx);
}

inline void emit_lw(u8 rd, s32 off, u8 rs1, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rs1 == RV_REG_SP && rd && is_8b_uint(off) &&
	    !(off & 0x3))
		emitc(rvc_lwsp(rd, off), ctx);
	else if (rvc_enabled() && is_creg(rd) && is_creg(rs1) &&
		 is_7b_uint(off) && !(off & 0x3))
		emitc(rvc_lw(rd, off, rs1), ctx);
	else
		emit(rv_lw(rd, off, rs1), ctx);
}

inline void emit_sw(u8 rs1, s32 off, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rs1 == RV_REG_SP && is_8b_uint(off) &&
	    !(off & 0x3))
		emitc(rvc_swsp(off, rs2), ctx);
	else if (rvc_enabled() && is_creg(rs1) && is_creg(rs2) &&
		 is_7b_uint(off) && !(off & 0x3))
		emitc(rvc_sw(rs1, off, rs2), ctx);
	else
		emit(rv_sw(rs1, off, rs2), ctx);
}

/* RV64-only helper functions. */
#if __riscv_xlen == 64

inline void emit_addiw(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rd == rs && is_6b_int(imm))
		emitc(rvc_addiw(rd, imm), ctx);
	else
		emit(rv_addiw(rd, rs, imm), ctx);
}

inline void emit_ld(u8 rd, s32 off, u8 rs1, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rs1 == RV_REG_SP && rd && is_9b_uint(off) &&
	    !(off & 0x7))
		emitc(rvc_ldsp(rd, off), ctx);
	else if (rvc_enabled() && is_creg(rd) && is_creg(rs1) &&
		 is_8b_uint(off) && !(off & 0x7))
		emitc(rvc_ld(rd, off, rs1), ctx);
	else
		emit(rv_ld(rd, off, rs1), ctx);
}

inline void emit_sd(u8 rs1, s32 off, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rs1 == RV_REG_SP && is_9b_uint(off) &&
	    !(off & 0x7))
		emitc(rvc_sdsp(off, rs2), ctx);
	else if (rvc_enabled() && is_creg(rs1) && is_creg(rs2) &&
		 is_8b_uint(off) && !(off & 0x7))
		emitc(rvc_sd(rs1, off, rs2), ctx);
	else
		emit(rv_sd(rs1, off, rs2), ctx);
}

inline void emit_subw(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_subw(rd, rs2), ctx);
	else
		emit(rv_subw(rd, rs1, rs2), ctx);
}

#endif /* __riscv_xlen == 64 */