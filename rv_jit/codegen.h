//
// Created by davide on 6/23/24.
//

#ifndef CODEGEN_H
#define CODEGEN_H

#include "base.h"

/************************
 RV64 Arch
************************/

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

// TODO: understand advantages of compressed instr
#define CONFIG_RISCV_ISA_C 0

/*************************
 CODEGEN RV
*************************/

inline void emit_jalr(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx);
inline void emit_mv(u8 rd, u8 rs, struct rv_jit_context *ctx);
inline void emit_add(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx);
inline void emit_addi(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx);
inline void emit_li(u8 rd, s32 imm, struct rv_jit_context *ctx);
inline void emit_lui(u8 rd, s32 imm, struct rv_jit_context *ctx);
inline void emit_slli(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx);
inline void emit_andi(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx);
inline void emit_srli(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx);
inline void emit_srai(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx);
inline void emit_sub(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx);
inline void emit_or(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx);
inline void emit_and(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx);
inline void emit_xor(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx);
inline void emit_lw(u8 rd, s32 off, u8 rs1, struct rv_jit_context *ctx);
inline void emit_sw(u8 rs1, s32 off, u8 rs2, struct rv_jit_context *ctx);

/* RV64-only instructions */
inline void emit_addiw(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx);
inline void emit_ld(u8 rd, s32 off, u8 rs1, struct rv_jit_context *ctx);
inline void emit_sd(u8 rs1, s32 off, u8 rs2, struct rv_jit_context *ctx);
inline void emit_subw(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx);

#endif //CODEGEN_H
