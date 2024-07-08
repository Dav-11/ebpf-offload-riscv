//
// Created by Davide Collovigh on 08/07/24.
//

#ifndef EBPF_OFFLOAD_RISCV_RV64_H
#define EBPF_OFFLOAD_RISCV_RV64_H

#include <linux/bpf.h>
#include "base.h"
#include "rv_insn.h"
#include "jit.h"

typedef struct basic_bpf_instruction {
	__u8 specific : 5, class : 3;
	__u8 dst_reg : 4;
	__u8 src_reg : 4;
	__u16 offset;
	__s32 imm;
} basic_bpf_instruction;

typedef struct wide_bpf_instruction {
	__u8 specific : 5, class : 3;
	__u8 dst_reg : 4;
	__u8 src_reg : 4;
	__u16 offset;
	__s32 imm;
	__s32 next_imm;
} wide_bpf_instruction;

inline void emit_jalr(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx);
inline void emit_mv(u8 rd, u8 rs, rvo_jit_context *ctx);
inline void emit_add(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx);
inline void emit_addi(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx);
inline void emit_li(u8 rd, s32 imm, rvo_jit_context *ctx);
inline void emit_lui(u8 rd, s32 imm, rvo_jit_context *ctx);
inline void emit_slli(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx);
inline void emit_andi(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx);
inline void emit_srli(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx);
inline void emit_srai(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx);
inline void emit_sub(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx);
inline void emit_or(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx);
inline void emit_and(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx);
inline void emit_xor(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx);
inline void emit_lw(u8 rd, s32 off, u8 rs1, rvo_jit_context *ctx);
inline void emit_sw(u8 rs1, s32 off, u8 rs2, rvo_jit_context *ctx);

/* RV64-only instructions */
inline void emit_addiw(u8 rd, u8 rs, s32 imm, rvo_jit_context *ctx);
inline void emit_ld(u8 rd, s32 off, u8 rs1, rvo_jit_context *ctx);
inline void emit_sd(u8 rs1, s32 off, u8 rs2, rvo_jit_context *ctx);
inline void emit_subw(u8 rd, u8 rs1, u8 rs2, rvo_jit_context *ctx);
inline void emit_sextb(u8 rd, u8 rs, rvo_jit_context *ctx);
inline void emit_sexth(u8 rd, u8 rs, rvo_jit_context *ctx);
inline void emit_sextw(u8 rd, u8 rs, rvo_jit_context *ctx);
inline void emit_zexth(u8 rd, u8 rs, rvo_jit_context *ctx);
inline void emit_zextw(u8 rd, u8 rs, rvo_jit_context *ctx);

int bpf_jit_emit_insn(const struct bpf_insn *insn, rvo_jit_context *ctx,
		      bool extra_pass);

#endif //EBPF_OFFLOAD_RISCV_RV64_H
