//
// Created by Davide Collovigh on 08/07/24.
//

#ifndef EBPF_OFFLOAD_RISCV_RV64_H
#define EBPF_OFFLOAD_RISCV_RV64_H

#include <linux/bpf.h>
#include "base.h"
#include "rv_insn.h"
#include "jit.h"

void init_regs(u8 *rd, u8 *rs, const struct bpf_insn *insn, rvo_prog *prog);

/**
 * @brief Calculates the offset between two instructions in RISCV instruction
 * @param insn current instruction number
 * @param off offset to target instruction
 * @param ctx
 * @return
 */
int rv_offset(int insn, int off, rvo_prog *ctx);

int emit_jump_and_link(u8 rd, s64 rvoff, bool fixed_addr, rvo_prog *ctx);
void emit_branch(u8 cond, u8 rd, u8 rs, int rvoff, rvo_prog *ctx);
void emit_imm(u8 rd, s64 val, rvo_prog *ctx);


// TODO: implement these !
/* ----------------- START ------------------- */

int emit_call(u64 addr, bool fixed_addr, rvo_prog *ctx);
int emit_bpf_tail_call(int insn, rvo_prog *ctx);
inline int epilogue_offset(rvo_prog *ctx);

/* Emit fixed-length instructions for address */
int emit_addr(u8 rd, u64 addr, bool extra_pass, rvo_prog *ctx);

/* For accesses to BTF pointers, add an entry to the exception table */
int add_exception_handler(const struct bpf_insn *insn,
                          rvo_prog *ctx,
                          int dst_reg, int insn_len);

void emit_atomic(u8 rd, u8 rs, s16 off, s32 imm, bool is64,
                 rvo_prog *ctx);

/* ----------------- STOP ------------------- */




inline void emit_jalr(u8 rd, u8 rs, s32 imm, rvo_prog *ctx);
inline void emit_mv(u8 rd, u8 rs, rvo_prog *ctx);
inline void emit_add(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx);
inline void emit_addi(u8 rd, u8 rs, s32 imm, rvo_prog *ctx);
inline void emit_li(u8 rd, s32 imm, rvo_prog *ctx);
inline void emit_lui(u8 rd, s32 imm, rvo_prog *ctx);
inline void emit_slli(u8 rd, u8 rs, s32 imm, rvo_prog *ctx);
inline void emit_andi(u8 rd, u8 rs, s32 imm, rvo_prog *ctx);
inline void emit_srli(u8 rd, u8 rs, s32 imm, rvo_prog *ctx);
inline void emit_srai(u8 rd, u8 rs, s32 imm, rvo_prog *ctx);
inline void emit_sub(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx);
inline void emit_or(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx);
inline void emit_and(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx);
inline void emit_xor(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx);
inline void emit_lw(u8 rd, s32 off, u8 rs1, rvo_prog *ctx);
inline void emit_sw(u8 rs1, s32 off, u8 rs2, rvo_prog *ctx);

/* RV64-only instructions */
inline void emit_addiw(u8 rd, u8 rs, s32 imm, rvo_prog *ctx);
inline void emit_ld(u8 rd, s32 off, u8 rs1, rvo_prog *ctx);
inline void emit_sd(u8 rs1, s32 off, u8 rs2, rvo_prog *ctx);
inline void emit_subw(u8 rd, u8 rs1, u8 rs2, rvo_prog *ctx);

inline void emit_zext_32(u8 reg, rvo_prog *ctx);
void emit_zext_32_rd_rs(u8 *rd, u8 *rs, rvo_prog *ctx);
void emit_sext_32_rd_rs(u8 *rd, u8 *rs, rvo_prog *ctx);
void emit_zext_32_rd_t1(u8 *rd, rvo_prog *ctx);
void emit_sext_32_rd(u8 *rd, rvo_prog *ctx);
void emit_bcc(u8 cond, u8 rd, u8 rs, int rvoff, rvo_prog *ctx);

// rvzbb (not in 6.8.x)
//inline void emit_sextb(u8 rd, u8 rs, rvo_prog *ctx);
//inline void emit_sexth(u8 rd, u8 rs, rvo_prog *ctx);
//inline void emit_sextw(u8 rd, u8 rs, rvo_prog *ctx);
//inline void emit_zexth(u8 rd, u8 rs, rvo_prog *ctx);
//inline void emit_zextw(u8 rd, u8 rs, rvo_prog *ctx);

int bpf_jit_emit_insn(const struct bpf_insn *insn, rvo_prog *ctx,
		      bool extra_pass);

void mark_call(rvo_prog *prog);

#endif //EBPF_OFFLOAD_RISCV_RV64_H
