//
// Created by Davide Collovigh on 24/05/24.
//

#ifndef EBPF_OFFLOAD_RISCV_JIT_H
#define EBPF_OFFLOAD_RISCV_JIT_H

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kernel.h> // for print_hex_dump()

// constants

#define NR_JIT_ITERATIONS \
	32 // Number of iterations to try until offsets converge.
#define __riscv_xlen 64 //TODO: make dynamic
#define CONFIG_RISCV_ISA_C 1

#define BPF_IMAGE_ALIGNMENT 8
#define ARENA_SIZE (1 * 1024 * 1024)

// data structs

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

struct rv_jit_context {
	struct bpf_prog *prog;
	u16 *insns; /* RV insns */
	u16 *ro_insns;
	int ninsns;
	int prologue_len;
	int epilogue_offset;
	int *offset; /* BPF to RV */
	int nexentries;
	unsigned long flags;
	int stack_size;
};

struct rv_jit_data {
	struct bpf_binary_header *header;
	struct bpf_binary_header *ro_header;
	u8 *image;
	u8 *ro_image;
	struct rv_jit_context ctx;
};

/*
 * The exception table consists of pairs of relative offsets: the first
 * is the relative offset to an instruction that is allowed to fault,
 * and the second is the relative offset at which the program should
 * continue. No registers are modified, so it is entirely up to the
 * continuation code to figure out what to do.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 */
struct rv_exception_table_entry {
	int insn, fixup;
	short type, data;
};

/**
 * Entry of the array to place inside the arena to keep track of used space for thread safe version
*/
typedef struct arena_entry {
	unsigned char *base;
	size_t size;
	spinlock_t lock;
} arena_entry_t;

/**
 * The memory arena is a simple memory allocator.
*/
struct memory_arena {
	unsigned char *base;
	size_t offset;
	spinlock_t lock;
};

/*
 * funcs
 */

// Arena mgmt funcs
int init_arena(void);
void destroy_arena(void);
void *alloc_arena(size_t size);
void *free_arena(size_t size);

// BPF program pack funcs
struct bpf_binary_header *
rv_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		    unsigned int alignment,
		    struct bpf_binary_header **rw_header, u8 **rw_image);
int rv_jit_binary_pack_finalize(struct bpf_prog *prog,
				struct bpf_binary_header *ro_header,
				struct bpf_binary_header *rw_header);

// core func

inline bool rvc_enabled(void)
{
	return CONFIG_RISCV_ISA_C; // TODO: what is this ?
}

/**
 * Compile the program.
 * @param prog
 * @return
 */
struct bpf_prog *my_bpf_jit_compile(struct bpf_prog *prog);

/**
 *
 * @param ctx
 * @param extra_pass
 * @param offset
 * @return
 */
int build_body(struct rv_jit_context *ctx, bool extra_pass, int *offset);

/**
 *
 * @param cond
 * @return -1 or inverted cond
 */
inline int invert_bpf_cond(u8 cond);

// regs func

/**
 * Check if a given register number reg is a callee-saved register or not.
 *
 * The callee-saved registers in RISC-V are:
 * - RV_REG_FP (Frame Pointer)
 * - RV_REG_S1 to RV_REG_S11 (Saved Registers)
 * - RV_REG_A0 to RV_REG_A5 (Function Arguments/Return Values
 *
 * @param reg is a register enum
 * @return true if the register value must be preserved across function calls
 */
inline bool is_creg(u8 reg);

// code gen

/**
 * Convert from ninsns to bytes.
 *
 * @param ninsns number of instructions
 * @return number of total bytes for the instructions
 */
inline int ninsns_rvoff(int ninsns);

/**
 * Fills specified area with non-executable instructions
 *
 * @param area pointer to area start
 * @param size of the area
 * @return void
 */
inline void bpf_fill_ill_insns(void *area, unsigned int size);

/**
 * Emit a 4-byte riscv instruction.
 *
 * @param insn
 * @param ctx
 */
inline void emit(const u32 insn, struct rv_jit_context *ctx);

/**
 * Emit a 2-byte riscv compressed instruction.
 * @param insn
 * @param ctx
 */
inline void emitc(const u16 insn, struct rv_jit_context *ctx);

/**
 * Calculates the offset (in bytes) between the current position in the JIT-compiled code and the epilogue code.
 * @param ctx A pointer to the rv_jit_context structure, which holds the context for the JIT compilation.
 * @return the byte offset between the current position and the epilogue code.
 */
inline int epilogue_offset(struct rv_jit_context *ctx);

/**
 * Calculate the offset (in instructions) between two points in the BPF program, taking into account the prologue instructions added by the JIT compiler.
 * @param insn The index of the current BPF instruction.
 * @param off The offset (in BPF instructions) from the current instruction.
 * @param ctx A pointer to the rv_jit_context structure, which holds the context for the JIT compilation.
 * @return
 */
inline int rv_offset(int insn, int off, struct rv_jit_context *ctx);

inline bool is_6b_int(long val);
inline bool is_7b_uint(unsigned long val);
inline bool is_8b_uint(unsigned long val);
inline bool is_9b_uint(unsigned long val);
inline bool is_10b_int(long val);
inline bool is_10b_uint(unsigned long val);
inline bool is_12b_int(long val);
inline int is_12b_check(int off, int insn);
inline bool is_13b_int(long val);
inline bool is_21b_int(long val);

/* Instruction formats. */

inline u32 rv_r_insn(u8 funct7, u8 rs2, u8 rs1, u8 funct3, u8 rd, u8 opcode);
inline u32 rv_i_insn(u16 imm11_0, u8 rs1, u8 funct3, u8 rd, u8 opcode);
inline u32 rv_s_insn(u16 imm11_0, u8 rs2, u8 rs1, u8 funct3, u8 opcode);
inline u32 rv_b_insn(u16 imm12_1, u8 rs2, u8 rs1, u8 funct3, u8 opcode);
inline u32 rv_u_insn(u32 imm31_12, u8 rd, u8 opcode);
inline u32 rv_j_insn(u32 imm20_1, u8 rd, u8 opcode);
inline u32 rv_amo_insn(u8 funct5, u8 aq, u8 rl, u8 rs2, u8 rs1, u8 funct3,
		       u8 rd, u8 opcode);

// compressed insn
inline u16 rv_cr_insn(u8 funct4, u8 rd, u8 rs2, u8 op);
inline u16 rv_ci_insn(u8 funct3, u32 imm6, u8 rd, u8 op);
inline u16 rv_css_insn(u8 funct3, u32 uimm, u8 rs2, u8 op);
inline u16 rv_ciw_insn(u8 funct3, u32 uimm, u8 rd, u8 op);
inline u16 rv_cl_insn(u8 funct3, u32 imm_hi, u8 rs1, u32 imm_lo, u8 rd, u8 op);
inline u16 rv_cs_insn(u8 funct3, u32 imm_hi, u8 rs1, u32 imm_lo, u8 rs2, u8 op);
inline u16 rv_ca_insn(u8 funct6, u8 rd, u8 funct2, u8 rs2, u8 op);
inline u16 rv_cb_insn(u8 funct3, u32 imm6, u8 funct2, u8 rd, u8 op);

// shared RV32 & RV64 instructions
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

// compressed instructions.
inline u16 rvc_addi4spn(u8 rd, u32 imm10);
inline u16 rvc_lw(u8 rd, u32 imm7, u8 rs1);
inline u16 rvc_sw(u8 rs1, u32 imm7, u8 rs2);
inline u16 rvc_addi(u8 rd, u32 imm6);
inline u16 rvc_li(u8 rd, u32 imm6);
inline u16 rvc_addi16sp(u32 imm10);
inline u16 rvc_lui(u8 rd, u32 imm6);
inline u16 rvc_srli(u8 rd, u32 imm6);
inline u16 rvc_srai(u8 rd, u32 imm6);
inline u16 rvc_andi(u8 rd, u32 imm6);
inline u16 rvc_sub(u8 rd, u8 rs);
inline u16 rvc_xor(u8 rd, u8 rs);
inline u16 rvc_or(u8 rd, u8 rs);
inline u16 rvc_and(u8 rd, u8 rs);
inline u16 rvc_slli(u8 rd, u32 imm6);
inline u16 rvc_lwsp(u8 rd, u32 imm8);
inline u16 rvc_jr(u8 rs1);
inline u16 rvc_mv(u8 rd, u8 rs);
inline u16 rvc_jalr(u8 rs1);
inline u16 rvc_add(u8 rd, u8 rs);
inline u16 rvc_swsp(u32 imm8, u8 rs2);

// RV64-only instructions
#if __riscv_xlen == 64

inline u32 rv_addiw(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_slliw(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_srliw(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_sraiw(u8 rd, u8 rs1, u16 imm11_0);
inline u32 rv_addw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_subw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_sllw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_srlw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_sraw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_mulw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_divw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_divuw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_remw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_remuw(u8 rd, u8 rs1, u8 rs2);
inline u32 rv_ld(u8 rd, u16 imm11_0, u8 rs1);
inline u32 rv_lwu(u8 rd, u16 imm11_0, u8 rs1);
inline u32 rv_sd(u8 rs1, u16 imm11_0, u8 rs2);
inline u32 rv_amoadd_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_amoand_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_amoor_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_amoxor_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_amoswap_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_lr_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
inline u32 rv_sc_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);

// RV64-only RVC instructions.

inline u16 rvc_ld(u8 rd, u32 imm8, u8 rs1);
inline u16 rvc_sd(u8 rs1, u32 imm8, u8 rs2);
inline u16 rvc_subw(u8 rd, u8 rs);
inline u16 rvc_addiw(u8 rd, u32 imm6);
inline u16 rvc_ldsp(u8 rd, u32 imm9);
inline u16 rvc_sdsp(u32 imm9, u8 rs2);

#endif /* __riscv_xlen == 64 */

// Helper functions that emit RVC instructions when possible.

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

// RV64-only helper functions.
#if __riscv_xlen == 64

inline void emit_addiw(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx);
inline void emit_ld(u8 rd, s32 off, u8 rs1, struct rv_jit_context *ctx);
inline void emit_sd(u8 rs1, s32 off, u8 rs2, struct rv_jit_context *ctx);
inline void emit_subw(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx);

#endif /* __riscv_xlen == 64 */

void bpf_jit_build_prologue(struct rv_jit_context *ctx);
void bpf_jit_build_epilogue(struct rv_jit_context *ctx);

int bpf_jit_emit_insn(const struct bpf_insn *insn, struct rv_jit_context *ctx,
		      bool extra_pass);

// utils

inline void rv_bpf_jit_dump(unsigned int flen, unsigned int proglen, u32 pass,
			    void *image);

#endif //EBPF_OFFLOAD_RISCV_JIT_H
