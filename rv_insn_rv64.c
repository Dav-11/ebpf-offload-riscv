//
// Created by Davide Collovigh on 08/07/24.
//

#include "rv_insn.h"

/***********************************
 * regs
 **********************************/

u8 bpf_to_rv_reg(int bpf_reg, unsigned long *flags)
{
	u8 reg = regmap[bpf_reg];

	switch (reg) {
	case RV_CTX_F_SEEN_S1:
	case RV_CTX_F_SEEN_S2:
	case RV_CTX_F_SEEN_S3:
	case RV_CTX_F_SEEN_S4:
	case RV_CTX_F_SEEN_S5:
	case RV_CTX_F_SEEN_S6:
		__set_bit(reg, flags);
	}

	return reg;
}

bool seen_reg(int reg, unsigned long *flags)
{
	switch (reg) {
	case RV_CTX_F_SEEN_CALL:
	case RV_CTX_F_SEEN_S1:
	case RV_CTX_F_SEEN_S2:
	case RV_CTX_F_SEEN_S3:
	case RV_CTX_F_SEEN_S4:
	case RV_CTX_F_SEEN_S5:
	case RV_CTX_F_SEEN_S6:
		return test_bit(reg, flags);
	}
	return false;
}

/***********************************
 * general format
 **********************************/

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

/***********************************
 * instr generation
 **********************************/

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
