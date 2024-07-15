//
// Created by Davide Collovigh on 08/07/24.
//

#ifndef EBPF_OFFLOAD_RISCV_RV_INSN_H
#define EBPF_OFFLOAD_RISCV_RV_INSN_H

#include <linux/bpf.h>
#include <linux/filter.h>

enum {
	RV_REG_ZERO = 0, /* The constant value 0 */
	RV_REG_RA = 1, /* Return address */
	RV_REG_SP = 2, /* Stack pointer */
	RV_REG_GP = 3, /* Global pointer */
	RV_REG_TP = 4, /* Thread pointer */
	RV_REG_T0 = 5, /* Temporaries */
	RV_REG_T1 = 6,
	RV_REG_T2 = 7,
	RV_REG_FP = 8, /* Saved register/frame pointer */
	RV_REG_S1 = 9, /* Saved register */
	RV_REG_A0 = 10, /* Function argument/return values */
	RV_REG_A1 = 11, /* Function arguments */
	RV_REG_A2 = 12,
	RV_REG_A3 = 13,
	RV_REG_A4 = 14,
	RV_REG_A5 = 15,
	RV_REG_A6 = 16,
	RV_REG_A7 = 17,
	RV_REG_S2 = 18, /* Saved registers */
	RV_REG_S3 = 19,
	RV_REG_S4 = 20,
	RV_REG_S5 = 21,
	RV_REG_S6 = 22,
	RV_REG_S7 = 23,
	RV_REG_S8 = 24,
	RV_REG_S9 = 25,
	RV_REG_S10 = 26,
	RV_REG_S11 = 27,
	RV_REG_T3 = 28, /* Temporaries */
	RV_REG_T4 = 29,
	RV_REG_T5 = 30,
	RV_REG_T6 = 31,
};

static const int regmap[] = {
	[BPF_REG_0] = RV_REG_A5,  [BPF_REG_1] = RV_REG_A0,
	[BPF_REG_2] = RV_REG_A1,  [BPF_REG_3] = RV_REG_A2,
	[BPF_REG_4] = RV_REG_A3,  [BPF_REG_5] = RV_REG_A4,
	[BPF_REG_6] = RV_REG_S1,  [BPF_REG_7] = RV_REG_S2,
	[BPF_REG_8] = RV_REG_S3,  [BPF_REG_9] = RV_REG_S4,
	[BPF_REG_FP] = RV_REG_S5, [BPF_REG_AX] = RV_REG_T0,
};

enum {
	RV_CTX_F_SEEN_TAIL_CALL =	0,
	RV_CTX_F_SEEN_CALL =		RV_REG_RA,
	RV_CTX_F_SEEN_S1 =		RV_REG_S1,
	RV_CTX_F_SEEN_S2 =		RV_REG_S2,
	RV_CTX_F_SEEN_S3 =		RV_REG_S3,
	RV_CTX_F_SEEN_S4 =		RV_REG_S4,
	RV_CTX_F_SEEN_S5 =		RV_REG_S5,
	RV_CTX_F_SEEN_S6 =		RV_REG_S6,
};

/***********************************
 * regs
 **********************************/

static u8 bpf_to_rv_reg(int bpf_reg, unsigned long *flags);
static bool seen_reg(int reg, unsigned long *flags);

/***********************************
 * instr generation
 **********************************/

/* NORMAL */
inline u32 rv_addi(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_andi(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_ori(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_xori(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_slli(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_srli(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_srai(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_lui(u8 rd, u32 imm31_12);
inline u32 rv_auipc(u8 rd, u32 imm31_12);
inline u32 rv_add(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_sub(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_sltu(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_and(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_or(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_xor(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_sll(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_srl(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_sra(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_mul(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_mulhu(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_div(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_divu(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_rem(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_remu(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_jal(u8 rd, u32 imm20_1);
inline u32 rv_jalr(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_beq(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_bne(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_bltu(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_bgtu(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_bgeu(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_bleu(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_blt(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_bgt(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_bge(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_ble(u8 rs1, u8 rs2, u16 imm12_1);
inline u32 rv_lb(u8 rd, u16 imm11_0, u8 rs1);
inline u32 rv_lh(u8 rd, u16 imm11_0, u8 rs1);
inline u32 rv_lw(u8 rd, u16 imm11_0, u8 rs1);
inline u32 rv_lbu(u8 rd, u16 imm11_0, u8 rs1);
inline u32 rv_lhu(u8 rd, u16 imm11_0, u8 rs1);
inline u32 rv_sb(u8 rs1, u16 imm11_0, u8 rs2);
inline u32 rv_sh(u8 rs1, u16 imm11_0, u8 rs2);
inline u32 rv_sw(u8 rs1, u16 imm11_0, u8 rs2);
inline u32 rv_amoadd_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_amoand_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_amoor_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_amoxor_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_amoswap_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_lr_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_sc_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_fence(u8 pred, u8 succ);
inline u32 rv_nop(void);

#endif //EBPF_OFFLOAD_RISCV_RV_INSN_H
