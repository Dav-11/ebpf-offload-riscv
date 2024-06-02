// SPDX-License-Identifier: GPL-2.0
/* BPF JIT compiler for RV64G
 *
 * Copyright(c) 2019 Björn Töpel <bjorn.topel@gmail.com>
 *
 */

//#include <linux/bitfield.h>
//#include <linux/memory.h>
//#include <linux/stop_machine.h>
//#include <asm/patch.h>
#include "jit.h"
#include "rv_asm.h"

#define RV_FENTRY_NINSNS 2

#define RV_REG_TCC RV_REG_A6
#define RV_REG_TCC_SAVED RV_REG_S6 /* Store A6 in S6 if program do calls */

/**
 * regmap - An array mapping BPF register numbers to RISC-V registers
 *
 * This array maps BPF register numbers (e.g., BPF_REG_1, BPF_REG_2, etc.)
 * to the corresponding RISC-V registers (e.g., RV_REG_A0, RV_REG_A1, etc.).
 * It is used by the BPF JIT compiler to translate BPF register operations
 * into RISC-V instructions that operate on the appropriate RISC-V registers.
 *
 * The mapping is as follows:
 *   BPF_REG_0  -> RV_REG_A5
 *   BPF_REG_1  -> RV_REG_A0
 *   BPF_REG_2  -> RV_REG_A1
 *   BPF_REG_3  -> RV_REG_A2
 *   BPF_REG_4  -> RV_REG_A3
 *   BPF_REG_5  -> RV_REG_A4
 *   BPF_REG_6  -> RV_REG_S1
 *   BPF_REG_7  -> RV_REG_S2
 *   BPF_REG_8  -> RV_REG_S3
 *   BPF_REG_9  -> RV_REG_S4
 *   BPF_REG_FP -> RV_REG_S5
 *   BPF_REG_AX -> RV_REG_T0
 */
static const int regmap[] = {
	[BPF_REG_0] = RV_REG_A5,  [BPF_REG_1] = RV_REG_A0,
	[BPF_REG_2] = RV_REG_A1,  [BPF_REG_3] = RV_REG_A2,
	[BPF_REG_4] = RV_REG_A3,  [BPF_REG_5] = RV_REG_A4,
	[BPF_REG_6] = RV_REG_S1,  [BPF_REG_7] = RV_REG_S2,
	[BPF_REG_8] = RV_REG_S3,  [BPF_REG_9] = RV_REG_S4,
	[BPF_REG_FP] = RV_REG_S5, [BPF_REG_AX] = RV_REG_T0,
};

/**
 * pt_regmap - An array mapping RISC-V registers to offsets in the pt_regs struct
 *
 * This array maps RISC-V registers (e.g., RV_REG_A0, RV_REG_A1, etc.) to the
 * corresponding offsets of the register values in the `struct pt_regs` structure.
 * The `struct pt_regs` is used to represent the register state of a thread or
 * process on the RISC-V architecture.
 *
 * The mapping is as follows:
 *   RV_REG_A0 -> offsetof(struct pt_regs, a0)
 *   RV_REG_A1 -> offsetof(struct pt_regs, a1)
 *   RV_REG_A2 -> offsetof(struct pt_regs, a2)
 *   RV_REG_A3 -> offsetof(struct pt_regs, a3)
 *   RV_REG_A4 -> offsetof(struct pt_regs, a4)
 *   RV_REG_A5 -> offsetof(struct pt_regs, a5)
 *   RV_REG_S1 -> offsetof(struct pt_regs, s1)
 *   RV_REG_S2 -> offsetof(struct pt_regs, s2)
 *   RV_REG_S3 -> offsetof(struct pt_regs, s3)
 *   RV_REG_S4 -> offsetof(struct pt_regs, s4)
 *   RV_REG_S5 -> offsetof(struct pt_regs, s5)
 *   RV_REG_T0 -> offsetof(struct pt_regs, t0)
 *
 * This mapping is used by the BPF JIT compiler to access and manipulate the
 * register values in the `struct pt_regs` when performing context switching,
 * signal handling, or other operations that require access to the register
 * state of a thread or process.
 */
static const int pt_regmap[] = {
	[RV_REG_A0] = offsetof(struct rv_pt_regs, a0),
	[RV_REG_A1] = offsetof(struct rv_pt_regs, a1),
	[RV_REG_A2] = offsetof(struct rv_pt_regs, a2),
	[RV_REG_A3] = offsetof(struct rv_pt_regs, a3),
	[RV_REG_A4] = offsetof(struct rv_pt_regs, a4),
	[RV_REG_A5] = offsetof(struct rv_pt_regs, a5),
	[RV_REG_S1] = offsetof(struct rv_pt_regs, s1),
	[RV_REG_S2] = offsetof(struct rv_pt_regs, s2),
	[RV_REG_S3] = offsetof(struct rv_pt_regs, s3),
	[RV_REG_S4] = offsetof(struct rv_pt_regs, s4),
	[RV_REG_S5] = offsetof(struct rv_pt_regs, s5),
	[RV_REG_T0] = offsetof(struct rv_pt_regs, t0),
};

enum {
	RV_CTX_F_SEEN_TAIL_CALL = 0,
	RV_CTX_F_SEEN_CALL = RV_REG_RA,
	RV_CTX_F_SEEN_S1 = RV_REG_S1,
	RV_CTX_F_SEEN_S2 = RV_REG_S2,
	RV_CTX_F_SEEN_S3 = RV_REG_S3,
	RV_CTX_F_SEEN_S4 = RV_REG_S4,
	RV_CTX_F_SEEN_S5 = RV_REG_S5,
	RV_CTX_F_SEEN_S6 = RV_REG_S6,
};

/**
 * bpf_to_rv_reg - Map a BPF register to a RISC-V register
 * @param bpf_reg: The BPF register number to be mapped
 * @param ctx: The RISC-V JIT context
 *
 * This function maps a BPF register number (e.g., BPF_REG_1, BPF_REG_2, etc.)
 * to the corresponding RISC-V register using the `regmap` array. It also
 * updates the `ctx->flags` bitmap to mark the RISC-V register as seen if it
 * is one of the callee-saved registers (S1-S6).
 *
 * The mapping between BPF registers and RISC-V registers is as follows:
 *   BPF_REG_0  -> RV_REG_A5
 *   BPF_REG_1  -> RV_REG_A0
 *   BPF_REG_2  -> RV_REG_A1
 *   BPF_REG_3  -> RV_REG_A2
 *   BPF_REG_4  -> RV_REG_A3
 *   BPF_REG_5  -> RV_REG_A4
 *   BPF_REG_6  -> RV_REG_S1
 *   BPF_REG_7  -> RV_REG_S2
 *   BPF_REG_8  -> RV_REG_S3
 *   BPF_REG_9  -> RV_REG_S4
 *   BPF_REG_FP -> RV_REG_S5
 *   BPF_REG_AX -> RV_REG_T0
 *
 * The `ctx->flags` bitmap is used to track which callee-saved registers
 * (S1-S6) have been used by the BPF program, so that the JIT compiler can
 * properly save and restore these registers during function calls or context
 * switches.
 *
 * @return: The RISC-V register number corresponding to the given BPF register.
 */
static u8 bpf_to_rv_reg(int bpf_reg, struct rv_jit_context *ctx)
{
	u8 reg = regmap[bpf_reg];

	switch (reg) {
	case RV_CTX_F_SEEN_S1:
	case RV_CTX_F_SEEN_S2:
	case RV_CTX_F_SEEN_S3:
	case RV_CTX_F_SEEN_S4:
	case RV_CTX_F_SEEN_S5:
	case RV_CTX_F_SEEN_S6:
		__set_bit(reg, &ctx->flags); // TODO: __set_bit() - keep x86
	}
	return reg;
};

/**
 * seen_reg - Check if a given register has been seen (used) in the BPF program
 * @param reg: The RISC-V register number to check
 * @param ctx: The RISC-V JIT context
 *
 * This function checks if a given RISC-V register has been marked as "seen"
 * (used) in the BPF program being compiled. It does this by checking the
 * corresponding bit in the `ctx->flags` bitmap.
 *
 * The registers that are tracked by this function are:
 *   RV_CTX_F_SEEN_CALL   - The return address register (RA)
 *   RV_CTX_F_SEEN_S1     - Callee-saved register S1
 *   RV_CTX_F_SEEN_S2     - Callee-saved register S2
 *   RV_CTX_F_SEEN_S3     - Callee-saved register S3
 *   RV_CTX_F_SEEN_S4     - Callee-saved register S4
 *   RV_CTX_F_SEEN_S5     - Callee-saved register S5 (frame pointer)
 *   RV_CTX_F_SEEN_S6     - Callee-saved register S6
 *
 * Tracking the usage of these registers is important for the JIT compiler
 * to properly save and restore them during function calls or context switches.
 *
 * @return: `true` if the given register has been seen (used), `false` otherwise.
 */
static bool seen_reg(int reg, struct rv_jit_context *ctx)
{
	switch (reg) {
	case RV_CTX_F_SEEN_CALL:
	case RV_CTX_F_SEEN_S1:
	case RV_CTX_F_SEEN_S2:
	case RV_CTX_F_SEEN_S3:
	case RV_CTX_F_SEEN_S4:
	case RV_CTX_F_SEEN_S5:
	case RV_CTX_F_SEEN_S6:
		return test_bit(reg, &ctx->flags); // TODO: test_bit() - keep x86
	}
	return false;
}

// __set_bit(nr, addr)
// The function sets the bit at the specified index nr in the bit array pointed to by addr to 1.

/**
 * mark_fp - Mark the frame pointer register (S5) as seen (used)
 * @param ctx: The RISC-V JIT context
 *
 * This function marks the frame pointer register (S5) as "seen" (used) in the
 * BPF program being compiled. It does this by setting the corresponding bit
 * (RV_CTX_F_SEEN_S5) in the `ctx->flags` bitmap.
 *
 * Marking the frame pointer register as seen is important for the JIT compiler
 * to properly save and restore it during function calls or context switches.
 * The frame pointer register is typically used to access stack-based variables
 * and maintain the call stack.
 *
 * This function should be called whenever the BPF program being compiled uses
 * the frame pointer register (BPF_REG_FP) or performs operations that modify
 * the frame pointer register.
 */
static void mark_fp(struct rv_jit_context *ctx)
{
	__set_bit(RV_CTX_F_SEEN_S5, &ctx->flags);
}

/**
 * mark_call - Mark that the BPF program being compiled has a function call
 * @param ctx: The RISC-V JIT context
 *
 * This function marks that the BPF program being compiled contains a function
 * call by setting the `RV_CTX_F_SEEN_CALL` bit in the `ctx->flags` bitmap.
 *
 * Marking the presence of function calls is important for the JIT compiler
 * to properly save and restore the return address register (RA) during the
 * function call. The return address register is used to store the address
 * to which the program should return after the function call is completed.
 *
 * This function should be called whenever the BPF program being compiled
 * encounters an instruction that performs a function call, such as the
 * `BPF_CALL` instruction.
 */
static void mark_call(struct rv_jit_context *ctx)
{
	__set_bit(RV_CTX_F_SEEN_CALL, &ctx->flags);
}

/**
 * seen_call - Check if the BPF program being compiled has a function call
 * @param ctx: The RISC-V JIT context
 *
 * This function checks if the BPF program being compiled contains a function
 * call by examining the `RV_CTX_F_SEEN_CALL` bit in the `ctx->flags` bitmap.
 *
 * The `RV_CTX_F_SEEN_CALL` bit is set by the `mark_call` function whenever
 * the BPF program encounters an instruction that performs a function call,
 * such as the `BPF_CALL` instruction.
 *
 * Tracking the presence of function calls is important for the JIT compiler
 * to properly save and restore the return address register (RA) during the
 * function call. The return address register is used to store the address
 * to which the program should return after the function call is completed.
 *
 * @return: `true` if the BPF program being compiled has a function call,
 *         `false` otherwise.
 */
static bool seen_call(struct rv_jit_context *ctx)
{
	return test_bit(RV_CTX_F_SEEN_CALL, &ctx->flags);
}

/**
 * mark_tail_call - Mark that the BPF program being compiled has a tail call
 * @param ctx: The RISC-V JIT context
 *
 * This function marks that the BPF program being compiled contains a tail
 * call by setting the `RV_CTX_F_SEEN_TAIL_CALL` bit in the `ctx->flags`
 * bitmap.
 *
 * Marking the presence of tail calls is important for the JIT compiler to
 * properly handle the tail call optimization. A tail call is a function call
 * that is performed as the final instruction of a function, allowing the
 * caller's stack frame to be reused for the callee, thereby reducing stack
 * usage and improving performance.
 *
 * This function should be called whenever the BPF program being compiled
 * encounters an instruction that performs a tail call, such as the
 * `BPF_CALL` instruction with the `BPF_CALL_TAIL` flag set.
 */
static void mark_tail_call(struct rv_jit_context *ctx)
{
	__set_bit(RV_CTX_F_SEEN_TAIL_CALL, &ctx->flags);
}

/**
 * seen_tail_call - Check if the BPF program being compiled has a tail call
 * @param ctx: The RISC-V JIT context
 *
 * This function checks if the BPF program being compiled contains a tail
 * call by examining the `RV_CTX_F_SEEN_TAIL_CALL` bit in the `ctx->flags`
 * bitmap.
 *
 * The `RV_CTX_F_SEEN_TAIL_CALL` bit is set by the `mark_tail_call` function
 * whenever the BPF program encounters an instruction that performs a tail
 * call, such as the `BPF_CALL` instruction with the `BPF_CALL_TAIL` flag set.
 *
 * Tracking the presence of tail calls is important for the JIT compiler to
 * properly handle the tail call optimization. A tail call is a function call
 * that is performed as the final instruction of a function, allowing the
 * caller's stack frame to be reused for the callee, thereby reducing stack
 * usage and improving performance.
 *
 * @return: `true` if the BPF program being compiled has a tail call,
 *         `false` otherwise.
 */
static bool seen_tail_call(struct rv_jit_context *ctx)
{
	return test_bit(RV_CTX_F_SEEN_TAIL_CALL, &ctx->flags);
}

/**
 * rv_tail_call_reg - Get the register to be used for tail calls
 * @param ctx: The RISC-V JIT context
 *
 * This function determines the register to be used for tail calls in the
 * BPF program being compiled. A tail call is a function call that is
 * performed as the final instruction of a function, allowing the caller's
 * stack frame to be reused for the callee, thereby reducing stack usage
 * and improving performance.
 *
 * The function first marks that the BPF program contains a tail call by
 * calling `mark_tail_call(ctx)`.
 *
 * If the BPF program also contains regular function calls (as indicated by
 * `seen_call(ctx)`), the function returns `RV_REG_S6` (callee-saved register
 * S6) as the tail call register. This is because the regular function calls
 * may have already used the temporary register `RV_REG_A6` for other
 * purposes, so a different register must be used for tail calls to avoid
 * conflicts.
 *
 * If the BPF program does not contain regular function calls, the function
 * returns `RV_REG_A6` (temporary register A6) as the tail call register.
 *
 * The tail call register is used by the JIT compiler to emit the appropriate
 * instructions for performing tail calls in the generated RISC-V code.
 *
 * @return: The RISC-V register number to be used for tail calls.
 */
static u8 rv_tail_call_reg(struct rv_jit_context *ctx)
{
	mark_tail_call(ctx);

	if (seen_call(ctx)) {
		__set_bit(RV_CTX_F_SEEN_S6, &ctx->flags);
		return RV_REG_S6;
	}
	return RV_REG_A6;
}

/**
 * is_32b_int - Check if a 64-bit value can be represented as a 32-bit integer
 * @param val: The 64-bit value to check
 *
 * This function checks if the given 64-bit value `val` can be represented
 * as a 32-bit signed integer, i.e., if it falls within the range of
 * [-2^31, 2^31 - 1].
 *
 * This function is useful in the context of the RISC-V JIT compiler, where
 * certain instructions (e.g., `addiw`) operate on 32-bit signed integers.
 * By checking if a value can be represented as a 32-bit integer, the JIT
 * compiler can determine whether it needs to use 32-bit or 64-bit
 * instructions to handle the value.
 *
 * @return: `true` if `val` can be represented as a 32-bit signed integer,
 *         `false` otherwise.
 */
static bool is_32b_int(s64 val)
{
	return -(1L << 31) <= val && val < (1L << 31);
}

/**
 * in_auipc_jalr_range - Check if a value is within the range of auipc+jalr
 * @param val: The value to check
 *
 * This function checks if the given signed 64-bit value `val` falls within
 * the range that can be reached by the combination of the `auipc` (add
 * upper immediate to PC) and `jalr` (jump and link register) instructions
 * in the RISC-V instruction set.
 *
 * The `auipc` instruction is used to load a 32-bit offset into a register,
 * which is then added to the current program counter (PC) value. The `jalr`
 * instruction performs a jump to the address specified by the sum of the
 * register value and a 12-bit signed offset.
 *
 * Together, the `auipc` and `jalr` instructions can reach any signed
 * PC-relative offset in the range [-2^31 - 2^11, 2^31 - 2^11), where
 * 2^31 is the maximum value of a 32-bit signed integer, and 2^11 is the
 * maximum value of the 12-bit signed offset used by `jalr`.
 *
 * This function is useful in the context of the RISC-V JIT compiler, where
 * it can be used to determine if a target address can be reached using the
 * `auipc` and `jalr` instructions, or if alternative instruction sequences
 * are required.
 *
 * @return: `true` if `val` is within the range of `auipc+jalr`, `false`
 *         otherwise.
 */
static bool in_auipc_jalr_range(s64 val)
{
	/*
	 * auipc+jalr can reach any signed PC-relative offset in the range
	 * [-2^31 - 2^11, 2^31 - 2^11).
	 */
	return (-(1L << 31) - (1L << 11)) <= val &&
	       val < ((1L << 31) - (1L << 11));
}

/**
 * emit_addr - Emit fixed-length instructions to load an address
 * @param rd The destination register to load the address into
 * @param addr The 64-bit address value to load
 * @param extra_pass A flag indicating if this is an extra pass (for range check)
 * @param ctx The RISC-V JIT context
 *
 * This function emits a sequence of fixed-length instructions to load the
 * given 64-bit address `addr` into the specified destination register `rd`.
 * The instructions used are `auipc` (add upper immediate to PC) and `addi`
 * (add immediate to register).
 *
 * The function first calculates the offset `off` between the target address
 * `addr` and the current instruction pointer `ip`, which is determined by
 * the `ro_insns` (read-only instructions) pointer and the current number of
 * instructions `ninsns` in the JIT context. This offset is then split into
 * an upper part `upper` (bits 12 and above) and a lower part `lower` (bits
 * 0-11).
 *
 * If the `extra_pass` flag is set, the function checks if the calculated
 * offset `off` is within the range that can be reached by the combination
 * of `auipc` and `jalr` (jump and link register) instructions. If the offset
 * is out of range, an error message is printed, and the function returns
 * `-ERANGE`.
 *
 * If the offset is within range, the function emits the `auipc` instruction
 * to load the upper part of the offset into the destination register `rd`,
 * and then emits the `addi` instruction to add the lower part of the offset
 * to `rd`.
 *
 * This function is used by the RISC-V JIT compiler to load target addresses
 * for branch instructions, function calls, and other operations that require
 * loading an absolute address.
 *
 * @return: 0 on success, -ERANGE if the target address is out of range.
 */
static int emit_addr(u8 rd, u64 addr, bool extra_pass,
		     struct rv_jit_context *ctx)
{
	/*
	 * Use the ro_insns(RX) to calculate the offset as the BPF program will
	 * finally run from this memory region.
	 */
	u64 ip = (u64)(ctx->ro_insns + ctx->ninsns);
	s64 off = addr - ip;
	s64 upper = (off + (1 << 11)) >> 12;
	s64 lower = off & 0xfff;

	if (extra_pass && !in_auipc_jalr_range(off)) {
		pr_err("bpf-jit: target offset 0x%llx is out of range\n", off);
		return -ERANGE;
	}

	emit(rv_auipc(rd, upper), ctx);
	emit(rv_addi(rd, rd, lower), ctx);
	return 0;
}

/**
 * @brief Emit fixed-length instructions to load an address
 *
 * @param rd The destination register to load the address into
 * @param addr The 64-bit address value to load
 * @param extra_pass A flag indicating if this is an extra pass (for range check)
 * @param ctx The RISC-V JIT context
 *
 * This function emits a sequence of fixed-length instructions to load the
 * given 64-bit address `addr` into the specified destination register `rd`.
 * The instructions used are `auipc` (add upper immediate to PC) and `addi`
 * (add immediate to register).
 *
 * The function first calculates the offset `off` between the target address
 * `addr` and the current instruction pointer `ip`, which is determined by
 * the `ro_insns` (read-only instructions) pointer and the current number of
 * instructions `ninsns` in the JIT context. This offset is then split into
 * an upper part `upper` (bits 12 and above) and a lower part `lower` (bits
 * 0-11).
 *
 * If the `extra_pass` flag is set, the function checks if the calculated
 * offset `off` is within the range that can be reached by the combination
 * of `auipc` and `jalr` (jump and link register) instructions. If the offset
 * is out of range, an error message is printed, and the function returns
 * `-ERANGE`.
 *
 * If the offset is within range, the function emits the `auipc` instruction
 * to load the upper part of the offset into the destination register `rd`,
 * and then emits the `addi` instruction to add the lower part of the offset
 * to `rd`.
 *
 * This function is used by the RISC-V JIT compiler to load target addresses
 * for branch instructions, function calls, and other operations that require
 * loading an absolute address.
 *
 * @return 0 on success, -ERANGE if the target address is out of range.
 */
static void emit_imm(u8 rd, s64 val, struct rv_jit_context *ctx)
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

/**
 * @brief Build the epilogue for the JIT-compiled BPF program
 * @param ctx The RISC-V JIT context
 * @param is_tail_call A flag indicating if this is a tail call
 *
 * This function builds the epilogue for the JIT-compiled BPF program,
 * which is responsible for restoring the callee-saved registers and
 * returning from the function.
 *
 * The epilogue performs the following steps:
 *
 * 1. Restore the callee-saved registers (`ra`, `fp`, `s1`, `s2`, `s3`,
 *    `s4`, `s5`, `s6`, and the `arena` pointer if applicable) from the
 *    stack frame.
 * 2. Adjust the stack pointer (`sp`) to release the stack frame.
 * 3. If this is not a tail call, set the return value (`a0`) to the value
 *    in `a5` (which holds the BPF program's return value).
 * 4. Jump to the return address (`ra`) or the tail call target (`t3`),
 *    depending on whether this is a tail call or not.
 *
 * The function emits the appropriate RISC-V instructions to perform these
 * steps, including `ld` (load), `addi` (add immediate), `addiw` (add word
 * immediate), and `jalr` (jump and link register).
 *
 * If this is a tail call, the function skips the first `RV_FENTRY_NINSNS + 1`
 * instructions in the target function, which are reserved for the function
 * entry prologue and tail call initialization.
 *
 * This function is an essential part of the RISC-V JIT compiler, as it
 * ensures that the JIT-compiled BPF program follows the standard calling
 * conventions and properly returns control to the caller.
 */
static void __build_epilogue(bool is_tail_call, struct rv_jit_context *ctx)
{
	int stack_adjust = ctx->stack_size, store_offset = stack_adjust - 8;

	if (seen_reg(RV_REG_RA, ctx)) {
		emit_ld(RV_REG_RA, store_offset, RV_REG_SP, ctx);
		store_offset -= 8;
	}
	emit_ld(RV_REG_FP, store_offset, RV_REG_SP, ctx);
	store_offset -= 8;
	if (seen_reg(RV_REG_S1, ctx)) {
		emit_ld(RV_REG_S1, store_offset, RV_REG_SP, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S2, ctx)) {
		emit_ld(RV_REG_S2, store_offset, RV_REG_SP, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S3, ctx)) {
		emit_ld(RV_REG_S3, store_offset, RV_REG_SP, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S4, ctx)) {
		emit_ld(RV_REG_S4, store_offset, RV_REG_SP, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S5, ctx)) {
		emit_ld(RV_REG_S5, store_offset, RV_REG_SP, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S6, ctx)) {
		emit_ld(RV_REG_S6, store_offset, RV_REG_SP, ctx);
		store_offset -= 8;
	}

	emit_addi(RV_REG_SP, RV_REG_SP, stack_adjust, ctx);
	/* Set return value. */
	if (!is_tail_call)
		emit_addiw(RV_REG_A0, RV_REG_A5, 0, ctx);
	emit_jalr(RV_REG_ZERO, is_tail_call ? RV_REG_T3 : RV_REG_RA,
		  is_tail_call ? (RV_FENTRY_NINSNS + 1) * 4 :
				 0, /* skip reserved nops and TCC init */
		  ctx);
}

/**
 * @brief Emit a branch conditional instruction
 * @param cond The branch condition code (e.g., BPF_JEQ, BPF_JGT, etc.)
 * @param rd The register containing the first operand
 * @param rs The register containing the second operand
 * @param rvoff The relative offset (in bytes) to branch to
 * @param ctx The RISC-V JIT context
 *
 * This function emits a branch conditional instruction based on the given
 * condition code `cond`, comparing the values in registers `rd` and `rs`.
 * The branch target is determined by the relative offset `rvoff`, which
 * is shifted right by 1 bit (divided by 2) to account for the compressed
 * instruction format.
 *
 * The function supports the following branch condition codes:
 *   - BPF_JEQ: Branch if `rd` is equal to `rs`
 *   - BPF_JGT: Branch if `rd` is unsigned greater than `rs`
 *   - BPF_JLT: Branch if `rd` is unsigned less than `rs`
 *   - BPF_JGE: Branch if `rd` is unsigned greater than or equal to `rs`
 *   - BPF_JLE: Branch if `rd` is unsigned less than or equal to `rs`
 *   - BPF_JNE: Branch if `rd` is not equal to `rs`
 *   - BPF_JSGT: Branch if `rd` is signed greater than `rs`
 *   - BPF_JSLT: Branch if `rd` is signed less than `rs`
 *   - BPF_JSGE: Branch if `rd` is signed greater than or equal to `rs`
 *   - BPF_JSLE: Branch if `rd` is signed less than or equal to `rs`
 *
 * The appropriate RISC-V branch instruction is emitted based on the
 * condition code, such as `beq` (branch if equal), `bltu` (branch if
 * unsigned less than), `blt` (branch if signed less than), etc.
 *
 * This function is used by the RISC-V JIT compiler to generate conditional
 * branch instructions for BPF programs.
 */
static void emit_bcc(u8 cond, u8 rd, u8 rs, int rvoff,
		     struct rv_jit_context *ctx)
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

/**
 * @brief Emit a conditional branch instruction
 *
 * @param cond The branch condition code (e.g., BPF_JEQ, BPF_JGT, etc.)
 * @param rd The register containing the first operand
 * @param rs The register containing the second operand
 * @param rvoff The relative offset (in bytes) to branch to
 * @param ctx The RISC-V JIT context
 *
 * This function emits a conditional branch instruction based on the given
 * condition code `cond`, comparing the values in registers `rd` and `rs`.
 * The branch target is determined by the relative offset `rvoff`.
 *
 * The function first checks if the branch offset `rvoff` can be encoded
 * within the 13-bit signed immediate field of the RISC-V branch instructions.
 * If so, it emits the appropriate branch instruction (e.g., `beq`, `bltu`,
 * `blt`, etc.) with the offset `rvoff` shifted right by 1 bit (divided by 2)
 * to account for the compressed instruction format.
 *
 * If the branch offset `rvoff` cannot be encoded within the 13-bit immediate
 * field, the function adjusts the offset by subtracting 4 bytes to account
 * for the `jal` (jump and link) instruction that will be used. It then
 * inverts the branch condition code `cond` and checks if the adjusted offset
 * can be encoded within the 21-bit signed immediate field of the `jal`
 * instruction. If so, it emits the inverted branch condition, followed by
 * the `jal` instruction with the adjusted offset shifted right by 1 bit.
 *
 * If the adjusted offset still cannot be encoded within the 21-bit immediate
 * field, the function splits the offset into an upper part `upper` (bits 12
 * and above) and a lower part `lower` (bits 0-11). It then emits the inverted
 * branch condition with a short offset of 12 bytes, followed by the `auipc`
 * (add upper immediate to PC) instruction to load the upper part of the
 * offset into the temporary register `t1`, and finally the `jalr` (jump and
 * link register) instruction to jump to the target address using the lower
 * part of the offset and the value in `t1`.
 *
 * This function is used by the RISC-V JIT compiler to generate conditional
 * branch instructions for BPF programs, handling both short and long branch
 * offsets.
 */
static void emit_branch(u8 cond, u8 rd, u8 rs, int rvoff,
			struct rv_jit_context *ctx)
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
	cond = invert_bpf_cond(cond); // from jit.h
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

/**
 * Emit a zero-extend operation on a 32-bit register.
 *
 * This function takes a 32-bit register and zero-extends it to 64 bits by
 * shifting the register left by 32 bits and then shifting it right by 32 bits.
 * This effectively clears the upper 32 bits of the register, leaving only the
 * lower 32 bits.
 *
 * @param reg The 32-bit register to zero-extend.
 * @param ctx The JIT context to emit the instructions to.
 */
static void emit_zext_32(u8 reg, struct rv_jit_context *ctx)
{
	emit_slli(reg, reg, 32, ctx);
	emit_srli(reg, reg, 32, ctx);
}

/**
 * @brief Emit instructions for a BPF tail call
 *
 * @param insn The BPF instruction for the tail call
 * @param ctx The RISC-V JIT context
 *
 * This function emits the necessary instructions to perform a BPF tail call.
 * It assumes the following register assignments:
 *   - `a0`: Pointer to the BPF context
 *   - `a1`: Pointer to the BPF array
 *   - `a2`: Index into the BPF array
 *
 * The function performs the following steps:
 *
 * 1. Check if the index `a2` is greater than or equal to the maximum number
 *    of entries in the BPF array (`array->map.max_entries`). If so, jump to
 *    the `out` label.
 * 2. Decrement the tail call count (`TCC`) and check if it becomes negative.
 *    If so, jump to the `out` label.
 * 3. Load the BPF program pointer (`prog`) from the array (`array->ptrs[index]`)
 *    and check if it is null. If so, jump to the `out` label.
 * 4. Load the address of the BPF program's function (`prog->bpf_func`) into
 *    the `t3` register and jump to that address, skipping the first
 *    `RV_FENTRY_NINSNS + 1` instructions (reserved for function entry prologue
 *    and tail call initialization).
 *
 * The function uses various RISC-V instructions such as `lwu` (load word
 * unsigned), `slli` (shift left logical immediate), `add`, `ld` (load double),
 * and `jalr` (jump and link register) to perform the necessary operations.
 *
 * If any error occurs during the tail call setup (e.g., out-of-range offsets),
 * the function returns -1 to indicate failure. Otherwise, it returns 0 on
 * success.
 *
 * @return 0 on success, -1 on failure.
 */
static int emit_bpf_tail_call(int insn, struct rv_jit_context *ctx)
{
	int tc_ninsn, off, start_insn = ctx->ninsns;
	u8 tcc = rv_tail_call_reg(ctx);

	/* a0: &ctx
	 * a1: &array
	 * a2: index
	 *
	 * if (index >= array->map.max_entries)
	 *	goto out;
	 */
	tc_ninsn = insn ? ctx->offset[insn] - ctx->offset[insn - 1] :
			  ctx->offset[0];
	emit_zext_32(RV_REG_A2, ctx);

	off = offsetof(struct bpf_array, map.max_entries);
	if (is_12b_check(off, insn)) //from jit.h
		return -1;
	emit(rv_lwu(RV_REG_T1, off, RV_REG_A1), ctx);
	off = ninsns_rvoff(tc_ninsn - (ctx->ninsns - start_insn));
	emit_branch(BPF_JGE, RV_REG_A2, RV_REG_T1, off, ctx);

	/* if (--TCC < 0)
	 *     goto out;
	 */
	emit_addi(RV_REG_TCC, tcc, -1, ctx);
	off = ninsns_rvoff(tc_ninsn - (ctx->ninsns - start_insn));
	emit_branch(BPF_JSLT, RV_REG_TCC, RV_REG_ZERO, off, ctx);

	/* prog = array->ptrs[index];
	 * if (!prog)
	 *     goto out;
	 */
	emit_slli(RV_REG_T2, RV_REG_A2, 3, ctx);
	emit_add(RV_REG_T2, RV_REG_T2, RV_REG_A1, ctx);
	off = offsetof(struct bpf_array, ptrs);
	if (is_12b_check(off, insn))
		return -1;
	emit_ld(RV_REG_T2, off, RV_REG_T2, ctx);
	off = ninsns_rvoff(tc_ninsn - (ctx->ninsns - start_insn));
	emit_branch(BPF_JEQ, RV_REG_T2, RV_REG_ZERO, off, ctx);

	/* goto *(prog->bpf_func + 4); */
	off = offsetof(struct bpf_prog, bpf_func);
	if (is_12b_check(off, insn))
		return -1;
	emit_ld(RV_REG_T3, off, RV_REG_T2, ctx);
	__build_epilogue(true, ctx);
	return 0;
}

/**
 * @brief Initialize the RISC-V JIT context registers
 *
 * @param ctx The RISC-V JIT context
 *
 * This function initializes the registers in the RISC-V JIT context `ctx`
 * with their respective initial values. The registers and their initial
 * values are as follows:
 *
 * - `RV_REG_A0`: Initialized with the address of the BPF context.
 * - `RV_REG_A1`: Initialized with the address of the BPF array.
 * - `RV_REG_A2`: Initialized with the index into the BPF array.
 * - `RV_REG_A3`: Initialized with the address of the BPF stack.
 * - `RV_REG_TCC`: Initialized with the tail call count.
 * - `RV_REG_FP`: Initialized with the address of the BPF frame pointer.
 * - `RV_REG_SP`: Initialized with the address of the BPF stack pointer.
 *
 * The function also initializes the `ninsns` field of the JIT context to
 * zero, indicating that no instructions have been emitted yet.
 *
 * This function is called at the beginning of the JIT compilation process
 * to set up the initial register values and prepare the JIT context for
 * instruction emission.
 */
static void init_regs(u8 *rd, u8 *rs, const struct bpf_insn *insn,
		      struct rv_jit_context *ctx)
{
	u8 code = insn->code;

	switch (code) {
	case BPF_JMP | BPF_JA:
	case BPF_JMP | BPF_CALL:
	case BPF_JMP | BPF_EXIT:
	case BPF_JMP | BPF_TAIL_CALL:
		break;
	default:
		*rd = bpf_to_rv_reg(insn->dst_reg, ctx);
	}

	if (code & (BPF_ALU | BPF_X) || code & (BPF_ALU64 | BPF_X) ||
	    code & (BPF_JMP | BPF_X) || code & (BPF_JMP32 | BPF_X) ||
	    code & BPF_LDX || code & BPF_STX)
		*rs = bpf_to_rv_reg(insn->src_reg, ctx);
}

/**
 * Emit instructions to zero-extend a 32-bit value to 64 bits.
 *
 * This function takes two 32-bit registers, zero-extends them to 64 bits, and
 * stores the results back in the original registers.
 *
 * @param rd Pointer to the destination 32-bit register.
 * @param rs Pointer to the source 32-bit register.
 * @param ctx The JIT context.
 */
static void emit_zext_32_rd_rs(u8 *rd, u8 *rs, struct rv_jit_context *ctx)
{
	emit_mv(RV_REG_T2, *rd, ctx);
	emit_zext_32(RV_REG_T2, ctx);
	emit_mv(RV_REG_T1, *rs, ctx);
	emit_zext_32(RV_REG_T1, ctx);
	*rd = RV_REG_T2;
	*rs = RV_REG_T1;
}

/**
 * Emit sign-extend 32-bit operation from register to register.
 *
 * This function emits the necessary instructions to sign-extend a 32-bit value
 * from one register to another. It uses the ADDIW instruction to perform the
 * sign-extension.
 *
 * @param rd Pointer to the destination register.
 * @param rs Pointer to the source register.
 * @param ctx The JIT context.
 */
static void emit_sext_32_rd_rs(u8 *rd, u8 *rs, struct rv_jit_context *ctx)
{
	emit_addiw(RV_REG_T2, *rd, 0, ctx);
	emit_addiw(RV_REG_T1, *rs, 0, ctx);
	*rd = RV_REG_T2;
	*rs = RV_REG_T1;
}

/**
 * Emit a 32-bit zero-extension operation for the given register.
 *
 * This function takes a pointer to a register (rd) and a JIT context (ctx),
 * and performs the following steps:
 *
 * 1. Moves the value from the register pointed to by rd into the T2 register.
 * 2. Zero-extends the value in the T2 register to 32 bits.
 * 3. Zero-extends the value in the T1 register to 32 bits.
 * 4. Stores the zero-extended value from the T2 register back into the register
 *    pointed to by rd.
 *
 * This function is used to ensure that 32-bit values are properly zero-extended
 * before performing operations on them.
 *
 * @param rd   Pointer to the register to be zero-extended
 * @param ctx  The JIT context
 */
static void emit_zext_32_rd_t1(u8 *rd, struct rv_jit_context *ctx)
{
	emit_mv(RV_REG_T2, *rd, ctx);
	emit_zext_32(RV_REG_T2, ctx);
	emit_zext_32(RV_REG_T1, ctx);
	*rd = RV_REG_T2;
}

/**
 * Emit sign-extended 32-bit value to a register.
 *
 * This function takes a pointer to a register and a JIT context, and emits
 * instructions to sign-extend a 32-bit value to 64 bits and store the result
 * in the specified register.
 *
 * @param rd Pointer to the destination register.
 * @param ctx The JIT context.
 */
static void emit_sext_32_rd(u8 *rd, struct rv_jit_context *ctx)
{
	emit_addiw(RV_REG_T2, *rd, 0, ctx);
	*rd = RV_REG_T2;
}

/**
 * @brief Emit a jump and link instruction
 *
 * @param rd The destination register to store the return address
 * @param rvoff The relative offset (in bytes) to jump to
 * @param fixed_addr A flag indicating if the target address is fixed
 * @param ctx The RISC-V JIT context
 *
 * @return 0 on success, -ERANGE if the target offset is out of range
 *
 * This function emits a jump and link instruction to transfer control to
 * a target address specified by the relative offset `rvoff`. The return
 * address is stored in the destination register `rd`.
 *
 * The function first checks if the target offset `rvoff` can be encoded
 * within the 21-bit signed immediate field of the `jal` (jump and link)
 * instruction, and if the `fixed_addr` flag is set (indicating that the
 * target address is fixed and not relative to the current instruction
 * pointer). If both conditions are met, it emits the `jal` instruction
 * with the offset `rvoff` shifted right by 1 bit (divided by 2) to account
 * for the compressed instruction format.
 *
 * If the target offset `rvoff` cannot be encoded within the 21-bit immediate
 * field, or if the `fixed_addr` flag is not set, the function checks if the
 * offset falls within the range that can be reached by the combination of
 * `auipc` (add upper immediate to PC) and `jalr` (jump and link register)
 * instructions. If so, it splits the offset into an upper part `upper`
 * (bits 12 and above) and a lower part `lower` (bits 0-11). It then emits
 * the `auipc` instruction to load the upper part of the offset into the
 * temporary register `t1`, followed by the `jalr` instruction to jump to
 * the target address using the lower part of the offset and the value in
 * `t1`.
 *
 * If the target offset `rvoff` is out of range for both the `jal` and the
 * `auipc`/`jalr` combination, the function prints an error message and
 * returns `-ERANGE` to indicate failure.
 *
 * This function is used by the RISC-V JIT compiler to generate jump and
 * link instructions for function calls and other control transfer operations.
 */
static int emit_jump_and_link(u8 rd, s64 rvoff, bool fixed_addr,
			      struct rv_jit_context *ctx)
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

/**
 * @brief Check if a BPF condition code represents a signed comparison
 * @param cond The BPF condition code
 * @return true if the condition code represents a signed comparison,
 *         false otherwise
 *
 * This function checks if the given BPF condition code `cond` represents
 * a signed comparison operation. It returns true if the condition code is
 * one of the following:
 *
 *   - BPF_JSGT: Jump if signed greater than
 *   - BPF_JSLT: Jump if signed less than
 *   - BPF_JSGE: Jump if signed greater than or equal
 *   - BPF_JSLE: Jump if signed less than or equal
 *
 * These condition codes are used for signed comparisons between two
 * operands, treating them as signed values.
 *
 * The function returns false for all other BPF condition codes, which
 * represent unsigned comparisons or other operations.
 *
 * This function is used by the RISC-V JIT compiler to determine whether
 * a signed or unsigned comparison instruction should be emitted for a
 * given BPF condition code.
 */
static bool is_signed_bpf_cond(u8 cond)
{
	return cond == BPF_JSGT || cond == BPF_JSLT || cond == BPF_JSGE ||
	       cond == BPF_JSLE;
}

/**
 * @brief Emit a function call instruction
 *
 * @param addr The target address of the function to call
 * @param fixed_addr A flag indicating if the target address is fixed
 * @param ctx The RISC-V JIT context
 *
 * @return 0 on success, -ERANGE if the target address is out of range
 *
 * This function emits a function call instruction to transfer control to
 * the specified target address `addr`. The `fixed_addr` flag indicates
 * whether the target address is a fixed absolute address or a relative
 * offset from the current instruction pointer.
 *
 * The function first calculates the offset `off` between the target address
 * `addr` and the current instruction pointer. If `fixed_addr` is true, the
 * offset is calculated directly from `addr`. If `fixed_addr` is false, the
 * offset is calculated as the difference between `addr` and the address of
 * the read-only instruction memory region (`ctx->ro_insns + ctx->ninsns`),
 * assuming that the BPF program will run from this memory region.
 *
 * After calculating the offset `off`, the function calls `emit_jump_and_link`
 * to emit the appropriate jump and link instruction(s) to transfer control
 * to the target address. The `emit_jump_and_link` function handles the
 * details of encoding the offset and emitting the necessary instructions
 * (e.g., `jal`, `auipc`, `jalr`) based on the offset range and the `fixed_addr`
 * flag.
 *
 * If the target address `addr` is out of range for the available jump and
 * link instructions, the function returns `-ERANGE` to indicate failure.
 * Otherwise, it returns 0 on success.
 *
 * This function is used by the RISC-V JIT compiler to generate function
 * call instructions for BPF helper functions and other external functions.
 */
static int emit_call(u64 addr, bool fixed_addr, struct rv_jit_context *ctx)
{
	s64 off = 0;
	u64 ip;

	if (addr && ctx->insns && ctx->ro_insns) {
		/*
		 * Use the ro_insns(RX) to calculate the offset as the BPF
		 * program will finally run from this memory region.
		 */
		ip = (u64)(long)(ctx->ro_insns + ctx->ninsns);
		off = addr - ip;
	}

	return emit_jump_and_link(RV_REG_RA, off, fixed_addr, ctx);
}

/**
 * @brief Emit instructions for an atomic operation
 *
 * @param rd The destination register
 * @param rs The source register
 * @param off The offset from the base register
 * @param imm The atomic operation code (BPF_ADD, BPF_AND, BPF_OR, etc.)
 * @param is64 A flag indicating whether the operation is 64-bit or 32-bit
 * @param ctx The RISC-V JIT context
 *
 * This function emits the necessary instructions to perform an atomic
 * operation on a memory location specified by the base register `rd` and
 * the offset `off`. The operation is determined by the `imm` parameter,
 * which can be one of the following:
 *
 *   - `BPF_ADD`: Atomic addition (`rd += rs`)
 *   - `BPF_AND`: Atomic bitwise AND (`rd &= rs`)
 *   - `BPF_OR`: Atomic bitwise OR (`rd |= rs`)
 *   - `BPF_XOR`: Atomic bitwise XOR (`rd ^= rs`)
 *   - `BPF_ADD | BPF_FETCH`: Atomic fetch-and-add (`rs = rd; rd += rs`)
 *   - `BPF_AND | BPF_FETCH`: Atomic fetch-and-and (`rs = rd; rd &= rs`)
 *   - `BPF_OR | BPF_FETCH`: Atomic fetch-and-or (`rs = rd; rd |= rs`)
 *   - `BPF_XOR | BPF_FETCH`: Atomic fetch-and-xor (`rs = rd; rd ^= rs`)
 *   - `BPF_XCHG`: Atomic exchange (`rs = rd; rd = rs`)
 *   - `BPF_CMPXCHG`: Atomic compare-and-exchange (`r0 = atomic_cmpxchg(rd, r0, rs)`)
 *
 * The `is64` flag indicates whether the operation should be performed on
 * 64-bit (true) or 32-bit (false) values.
 *
 * The function first checks if the offset `off` is non-zero. If so, it
 * calculates the effective address by adding the offset to the base register
 * `rd` and stores the result in the temporary register `RV_REG_T1`.
 *
 * Then, based on the operation code `imm`, the function emits the
 * appropriate RISC-V atomic instruction (`amoadd`, `amoand`, `amoor`,
 * `amoxor`, `amoswap`, or `amocmpxchg`) with the necessary operands and
 * flags. The atomic instructions are performed on the memory location
 * specified by the effective address (`rd` or `RV_REG_T1`) and the source
 * register `rs`.
 *
 * For fetch-and-op operations (`BPF_ADD | BPF_FETCH`, `BPF_AND | BPF_FETCH`,
 * etc.), the function emits an additional instruction to zero-extend the
 * result from 32 bits to 64 bits if the operation is performed on 32-bit
 * values (`!is64`).
 *
 * This function is used by the RISC-V JIT compiler to generate atomic
 * instructions for BPF programs that perform atomic operations on memory
 * locations.
 */
static void emit_atomic(u8 rd, u8 rs, s16 off, s32 imm, bool is64,
			struct rv_jit_context *ctx)
{
	u8 r0;
	int jmp_offset;

	if (off) {
		if (is_12b_int(off)) {
			emit_addi(RV_REG_T1, rd, off, ctx);
		} else {
			emit_imm(RV_REG_T1, off, ctx);
			emit_add(RV_REG_T1, RV_REG_T1, rd, ctx);
		}
		rd = RV_REG_T1;
	}

	switch (imm) {
	/* lock *(u32/u64 *)(dst_reg + off16) <op>= src_reg */
	case BPF_ADD:
		emit(is64 ? rv_amoadd_d(RV_REG_ZERO, rs, rd, 0, 0) :
			    rv_amoadd_w(RV_REG_ZERO, rs, rd, 0, 0),
		     ctx);
		break;
	case BPF_AND:
		emit(is64 ? rv_amoand_d(RV_REG_ZERO, rs, rd, 0, 0) :
			    rv_amoand_w(RV_REG_ZERO, rs, rd, 0, 0),
		     ctx);
		break;
	case BPF_OR:
		emit(is64 ? rv_amoor_d(RV_REG_ZERO, rs, rd, 0, 0) :
			    rv_amoor_w(RV_REG_ZERO, rs, rd, 0, 0),
		     ctx);
		break;
	case BPF_XOR:
		emit(is64 ? rv_amoxor_d(RV_REG_ZERO, rs, rd, 0, 0) :
			    rv_amoxor_w(RV_REG_ZERO, rs, rd, 0, 0),
		     ctx);
		break;
	/* src_reg = atomic_fetch_<op>(dst_reg + off16, src_reg) */
	case BPF_ADD | BPF_FETCH:
		emit(is64 ? rv_amoadd_d(rs, rs, rd, 0, 0) :
			    rv_amoadd_w(rs, rs, rd, 0, 0),
		     ctx);
		if (!is64)
			emit_zext_32(rs, ctx);
		break;
	case BPF_AND | BPF_FETCH:
		emit(is64 ? rv_amoand_d(rs, rs, rd, 0, 0) :
			    rv_amoand_w(rs, rs, rd, 0, 0),
		     ctx);
		if (!is64)
			emit_zext_32(rs, ctx);
		break;
	case BPF_OR | BPF_FETCH:
		emit(is64 ? rv_amoor_d(rs, rs, rd, 0, 0) :
			    rv_amoor_w(rs, rs, rd, 0, 0),
		     ctx);
		if (!is64)
			emit_zext_32(rs, ctx);
		break;
	case BPF_XOR | BPF_FETCH:
		emit(is64 ? rv_amoxor_d(rs, rs, rd, 0, 0) :
			    rv_amoxor_w(rs, rs, rd, 0, 0),
		     ctx);
		if (!is64)
			emit_zext_32(rs, ctx);
		break;
	/* src_reg = atomic_xchg(dst_reg + off16, src_reg); */
	case BPF_XCHG:
		emit(is64 ? rv_amoswap_d(rs, rs, rd, 0, 0) :
			    rv_amoswap_w(rs, rs, rd, 0, 0),
		     ctx);
		if (!is64)
			emit_zext_32(rs, ctx);
		break;
	/* r0 = atomic_cmpxchg(dst_reg + off16, r0, src_reg); */
	case BPF_CMPXCHG:
		r0 = bpf_to_rv_reg(BPF_REG_0, ctx);
		emit(is64 ? rv_addi(RV_REG_T2, r0, 0) :
			    rv_addiw(RV_REG_T2, r0, 0),
		     ctx);
		emit(is64 ? rv_lr_d(r0, 0, rd, 0, 0) : rv_lr_w(r0, 0, rd, 0, 0),
		     ctx);
		jmp_offset = ninsns_rvoff(8);
		emit(rv_bne(RV_REG_T2, r0, jmp_offset >> 1), ctx);
		emit(is64 ? rv_sc_d(RV_REG_T3, rs, rd, 0, 0) :
			    rv_sc_w(RV_REG_T3, rs, rd, 0, 0),
		     ctx);
		jmp_offset = ninsns_rvoff(-6);
		emit(rv_bne(RV_REG_T3, 0, jmp_offset >> 1), ctx);
		emit(rv_fence(0x3, 0x3), ctx);
		break;
	}
}

#define BPF_FIXUP_OFFSET_MASK GENMASK(26, 0)
#define BPF_FIXUP_REG_MASK GENMASK(31, 27)

/**
 * @brief Handle exceptions in BPF JIT compiled code
 *
 * This function is called when an exception occurs in BPF JIT compiled code.
 * It sets the program counter (epc) to the address of the fixup code and
 * clears the register value that caused the exception.
 *
 * @param ex Pointer to the exception table entry containing the fixup information
 * @param regs Pointer to the register state at the time of the exception
 *
 * Returns: true to indicate the exception has been handled
 */
bool ex_handler_bpf(const struct rv_exception_table_entry *ex,
		    struct rv_pt_regs *regs)
{
	off_t offset = FIELD_GET(BPF_FIXUP_OFFSET_MASK, ex->fixup);
	int regs_offset = FIELD_GET(BPF_FIXUP_REG_MASK, ex->fixup);

	*(unsigned long *)((void *)regs + pt_regmap[regs_offset]) = 0;
	regs->epc = (unsigned long)&ex->fixup - offset;

	return true;
}

/* For accesses to BTF pointers, add an entry to the exception table */
static int add_exception_handler(const struct bpf_insn *insn,
				 struct rv_jit_context *ctx, int dst_reg,
				 int insn_len)
{
	struct rv_exception_table_entry *ex;
	unsigned long pc;
	off_t ins_offset; //TODO: off_t
	off_t fixup_offset;

	if (!ctx->insns || !ctx->ro_insns || !ctx->prog->aux->extable ||
	    (BPF_MODE(insn->code) != BPF_PROBE_MEM &&
	     BPF_MODE(insn->code) != BPF_PROBE_MEMSX))
		return 0;

	if (WARN_ON_ONCE(ctx->nexentries >= ctx->prog->aux->num_exentries))
		return -EINVAL;

	if (WARN_ON_ONCE(insn_len > ctx->ninsns))
		return -EINVAL;

	if (WARN_ON_ONCE(!rvc_enabled() && insn_len == 1))
		return -EINVAL;

	ex = &ctx->prog->aux->extable[ctx->nexentries];
	pc = (unsigned long)&ctx->ro_insns[ctx->ninsns - insn_len];

	/*
	 * This is the relative offset of the instruction that may fault from
	 * the exception table itself. This will be written to the exception
	 * table and if this instruction faults, the destination register will
	 * be set to '0' and the execution will jump to the next instruction.
	 */
	ins_offset = pc - (long)&ex->insn;
	if (WARN_ON_ONCE(ins_offset >= 0 || ins_offset < INT_MIN))
		return -ERANGE;

	/*
	 * Since the extable follows the program, the fixup offset is always
	 * negative and limited to BPF_JIT_REGION_SIZE. Store a positive value
	 * to keep things simple, and put the destination register in the upper
	 * bits. We don't need to worry about buildtime or runtime sort
	 * modifying the upper bits because the table is already sorted, and
	 * isn't part of the main exception table.
	 *
	 * The fixup_offset is set to the next instruction from the instruction
	 * that may fault. The execution will jump to this after handling the
	 * fault.
	 */
	fixup_offset = (long)&ex->fixup - (pc + insn_len * sizeof(u16));
	if (!FIELD_FIT(BPF_FIXUP_OFFSET_MASK, fixup_offset)) //TODO: FIELD_FIT - okish
		return -ERANGE;

	/*
	 * The offsets above have been calculated using the RO buffer but we
	 * need to use the R/W buffer for writes.
	 * switch ex to rw buffer for writing.
	 */
	ex = (void *)ctx->insns + ((void *)ex - (void *)ctx->ro_insns);

	ex->insn = ins_offset;

	ex->fixup = FIELD_PREP(BPF_FIXUP_OFFSET_MASK, fixup_offset) | //TODO: FIELD_PREP - okish
		    FIELD_PREP(BPF_FIXUP_REG_MASK, dst_reg);
	ex->type = EX_TYPE_BPF;

	ctx->nexentries++;
	return 0;
}

static int gen_jump_or_nops(void *target, void *ip, u32 *insns, bool is_call)
{
	s64 rvoff;
	struct rv_jit_context ctx;

	ctx.ninsns = 0;
	ctx.insns = (u16 *)insns;

	if (!target) {
		emit(rv_nop(), &ctx);
		emit(rv_nop(), &ctx);
		return 0;
	}

	rvoff = (s64)(target - ip);
	return emit_jump_and_link(is_call ? RV_REG_T0 : RV_REG_ZERO, rvoff,
				  false, &ctx);
}

int rv_bpf_arch_text_poke(void *ip, enum bpf_text_poke_type poke_type, // from bpf.h
		       void *old_addr, void *new_addr)
{
	u32 old_insns[RV_FENTRY_NINSNS], new_insns[RV_FENTRY_NINSNS];
	bool is_call = poke_type == BPF_MOD_CALL;
	int ret;

	if (!is_kernel_text((unsigned long)ip) && //TODO: is_kernel_text
	    !is_bpf_text_address((unsigned long)ip)) //TODO: is_bpf_text_address
		return -ENOTSUPP;

	ret = gen_jump_or_nops(old_addr, ip, old_insns, is_call);
	if (ret)
		return ret;

	if (memcmp(ip, old_insns, RV_FENTRY_NINSNS * 4)) //TODO: memcmp
		return -EFAULT;

	ret = gen_jump_or_nops(new_addr, ip, new_insns, is_call);
	if (ret)
		return ret;

	cpus_read_lock(); //TODO: cpus_read_lock, cpus_read_unlock
	mutex_lock(&text_mutex); //TODO: mutex_lock, text_mutex, mutex_unlock
	if (memcmp(ip, new_insns, RV_FENTRY_NINSNS * 4))
		ret = patch_text(ip, new_insns, RV_FENTRY_NINSNS); //TODO: patch_text
	mutex_unlock(&text_mutex);
	cpus_read_unlock();

	return ret;
}

/**
 * Stores the function arguments in the stack frame.
 *
 * This function is responsible for storing the function arguments in the stack
 * frame, starting from the base pointer (RV_REG_FP) and moving downwards in
 * memory. The number of arguments to store is specified by the `nregs`
 * parameter, and the starting offset from the base pointer is specified by the
 * `args_off` parameter.
 *
 * @param nregs The number of function arguments to store.
 * @param args_off The starting offset from the base pointer to store the
 *                 arguments.
 * @param ctx The JIT context, which contains information about the current
 *            compilation state.
 */
static void store_args(int nregs, int args_off, struct rv_jit_context *ctx)
{
	int i;

	for (i = 0; i < nregs; i++) {
		emit_sd(RV_REG_FP, -args_off, RV_REG_A0 + i, ctx);
		args_off -= 8;
	}
}

/**
 * Restores the function arguments from the stack frame.
 *
 * This function is responsible for restoring the function arguments that were
 * previously saved on the stack frame. It iterates over the number of registers
 * specified by `nregs` and loads the argument values from the stack frame
 * starting at the offset specified by `args_off`. The loaded values are stored
 * in the corresponding registers (A0 to A0 + nregs - 1).
 *
 * @param nregs The number of registers to restore.
 * @param args_off The offset from the frame pointer (FP) where the arguments
 *                 are stored on the stack.
 * @param ctx The JIT context used for emitting the load instructions.
 */
static void restore_args(int nregs, int args_off, struct rv_jit_context *ctx)
{
	int i;

	for (i = 0; i < nregs; i++) {
		emit_ld(RV_REG_A0 + i, -args_off, RV_REG_FP, ctx);
		args_off -= 8;
	}
}

/**
 * invoke_bpf_prog - Invoke a BPF program in the context of a trampoline
 *
 * This function is responsible for setting up the necessary context and
 * calling the BPF program's entry point. It handles saving and restoring
 * the return value, as well as invoking the program's enter and exit hooks.
 *
 * @param l: The BPF trampoline link associated with the program to be executed
 * @param args_off: The offset of the arguments in the run context
 * @param retval_off: The offset of the return value in the run context
 * @param run_ctx_off: The offset of the run context in the stack frame
 * @param save_ret: Whether to save the return value in the run context
 * @param ctx: The JIT context for the current trampoline
 *
 * @return 0 on success, or a negative error code on failure
 */
static int invoke_bpf_prog(struct bpf_tramp_link *l, int args_off, //TODO: understand if tries to run code in kernel (bc it cannot if it is compiled for riscv)
			   int retval_off, int run_ctx_off, bool save_ret,
			   struct rv_jit_context *ctx)
{
	int ret, branch_off;
	struct bpf_prog *p = l->link.prog;
	int cookie_off = offsetof(struct bpf_tramp_run_ctx, bpf_cookie); //TODO: bpf_tramp_run_ctx

	if (l->cookie) {
		emit_imm(RV_REG_T1, l->cookie, ctx);
		emit_sd(RV_REG_FP, -run_ctx_off + cookie_off, RV_REG_T1, ctx);
	} else {
		emit_sd(RV_REG_FP, -run_ctx_off + cookie_off, RV_REG_ZERO, ctx);
	}

	/* arg1: prog */
	emit_imm(RV_REG_A0, (const s64)p, ctx);
	/* arg2: &run_ctx */
	emit_addi(RV_REG_A1, RV_REG_FP, -run_ctx_off, ctx);
	ret = emit_call((const u64)bpf_trampoline_enter(p), true, ctx);
	if (ret)
		return ret;

	/* if (__bpf_prog_enter(prog) == 0)
	 *	goto skip_exec_of_prog;
	 */
	branch_off = ctx->ninsns;
	/* nop reserved for conditional jump */
	emit(rv_nop(), ctx);

	/* store prog start time */
	emit_mv(RV_REG_S1, RV_REG_A0, ctx);

	/* arg1: &args_off */
	emit_addi(RV_REG_A0, RV_REG_FP, -args_off, ctx);
	if (!p->jited)
		/* arg2: progs[i]->insnsi for interpreter */
		emit_imm(RV_REG_A1, (const s64)p->insnsi, ctx);
	ret = emit_call((const u64)p->bpf_func, true, ctx);
	if (ret)
		return ret;

	if (save_ret) {
		emit_sd(RV_REG_FP, -retval_off, RV_REG_A0, ctx);
		emit_sd(RV_REG_FP, -(retval_off - 8), regmap[BPF_REG_0], ctx);
	}

	/* update branch with beqz */
	if (ctx->insns) {
		int offset = ninsns_rvoff(ctx->ninsns - branch_off); //TODO: ninsns_rvoff
		u32 insn = rv_beq(RV_REG_A0, RV_REG_ZERO, offset >> 1);
		*(u32 *)(ctx->insns + branch_off) = insn;
	}

	/* arg1: prog */
	emit_imm(RV_REG_A0, (const s64)p, ctx);
	/* arg2: prog start time */
	emit_mv(RV_REG_A1, RV_REG_S1, ctx);
	/* arg3: &run_ctx */
	emit_addi(RV_REG_A2, RV_REG_FP, -run_ctx_off, ctx);
	ret = emit_call((const u64)bpf_trampoline_exit(p), true, ctx);

	return ret;
}

/**
 * @brief Prepare a BPF trampoline for a given function
 * @param im: The BPF trampoline image
 * @param m: The BTF function model for the traced function
 * @param tlinks: The BPF trampoline links
 * @param func_addr: The address of the traced function
 * @param flags: Flags that control the trampoline behavior
 * @param ctx: The JIT context
 *
 * This function generates the assembly code for a BPF trampoline that can be
 * used to call the traced function and handle various BPF hooks (e.g., fentry,
 * fexit, modify_return). The trampoline is responsible for setting up the
 * stack frame, saving and restoring registers, and invoking the BPF programs
 * associated with the trampoline hooks.
 *
 * @return: The number of instructions in the generated trampoline, or a negative
 * error code on failure.
 */
static int __arch_prepare_bpf_trampoline(struct bpf_tramp_image *im,
					 const struct btf_func_model *m,
					 struct bpf_tramp_links *tlinks,
					 void *func_addr, u32 flags,
					 struct rv_jit_context *ctx)
{
	int i, ret, offset;
	int *branches_off = NULL;
	int stack_size = 0, nregs = m->nr_args;
	int retval_off, args_off, nregs_off, ip_off, run_ctx_off, sreg_off;
	struct bpf_tramp_links *fentry = &tlinks[BPF_TRAMP_FENTRY]; //TODO: bpf_tramp_links
	struct bpf_tramp_links *fexit = &tlinks[BPF_TRAMP_FEXIT];
	struct bpf_tramp_links *fmod_ret = &tlinks[BPF_TRAMP_MODIFY_RETURN];
	bool is_struct_ops = flags & BPF_TRAMP_F_INDIRECT;
	void *orig_call = func_addr;
	bool save_ret;
	u32 insn;

	/* Two types of generated trampoline stack layout:
	 *
	 * 1. trampoline called from function entry
	 * --------------------------------------
	 * FP + 8	    [ RA to parent func	] return address to parent
	 *					  function
	 * FP + 0	    [ FP of parent func ] frame pointer of parent
	 *					  function
	 * FP - 8           [ T0 to traced func ] return address of traced
	 *					  function
	 * FP - 16	    [ FP of traced func ] frame pointer of traced
	 *					  function
	 * --------------------------------------
	 *
	 * 2. trampoline called directly
	 * --------------------------------------
	 * FP - 8	    [ RA to caller func ] return address to caller
	 *					  function
	 * FP - 16	    [ FP of caller func	] frame pointer of caller
	 *					  function
	 * --------------------------------------
	 *
	 * FP - retval_off  [ return value      ] BPF_TRAMP_F_CALL_ORIG or
	 *					  BPF_TRAMP_F_RET_FENTRY_RET
	 *                  [ argN              ]
	 *                  [ ...               ]
	 * FP - args_off    [ arg1              ]
	 *
	 * FP - nregs_off   [ regs count        ]
	 *
	 * FP - ip_off      [ traced func	] BPF_TRAMP_F_IP_ARG
	 *
	 * FP - run_ctx_off [ bpf_tramp_run_ctx ]
	 *
	 * FP - sreg_off    [ callee saved reg	]
	 *
	 *		    [ pads              ] pads for 16 bytes alignment
	 */

	if (flags & (BPF_TRAMP_F_ORIG_STACK | BPF_TRAMP_F_SHARE_IPMODIFY)) //TODO: BPF_TRAMP_F_ORIG_STACK, BPF_TRAMP_F_SHARE_IPMODIFY
		return -ENOTSUPP;

	/* extra regiters for struct arguments */
	for (i = 0; i < m->nr_args; i++)
		if (m->arg_flags[i] & BTF_FMODEL_STRUCT_ARG)
			nregs += round_up(m->arg_size[i], 8) / 8 - 1;

	/* 8 arguments passed by registers */
	if (nregs > 8)
		return -ENOTSUPP;

	/* room of trampoline frame to store return address and frame pointer */
	stack_size += 16;

	save_ret = flags & (BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_RET_FENTRY_RET);
	if (save_ret) {
		stack_size += 16; /* Save both A5 (BPF R0) and A0 */
		retval_off = stack_size;
	}

	stack_size += nregs * 8;
	args_off = stack_size;

	stack_size += 8;
	nregs_off = stack_size;

	if (flags & BPF_TRAMP_F_IP_ARG) {
		stack_size += 8;
		ip_off = stack_size;
	}

	stack_size += round_up(sizeof(struct bpf_tramp_run_ctx), 8);
	run_ctx_off = stack_size;

	stack_size += 8;
	sreg_off = stack_size;

	stack_size = round_up(stack_size, 16);

	if (!is_struct_ops) {
		/* For the trampoline called from function entry,
		 * the frame of traced function and the frame of
		 * trampoline need to be considered.
		 */
		emit_addi(RV_REG_SP, RV_REG_SP, -16, ctx);
		emit_sd(RV_REG_SP, 8, RV_REG_RA, ctx);
		emit_sd(RV_REG_SP, 0, RV_REG_FP, ctx);
		emit_addi(RV_REG_FP, RV_REG_SP, 16, ctx);

		emit_addi(RV_REG_SP, RV_REG_SP, -stack_size, ctx);
		emit_sd(RV_REG_SP, stack_size - 8, RV_REG_T0, ctx);
		emit_sd(RV_REG_SP, stack_size - 16, RV_REG_FP, ctx);
		emit_addi(RV_REG_FP, RV_REG_SP, stack_size, ctx);
	} else {
		/* For the trampoline called directly, just handle
		 * the frame of trampoline.
		 */
		emit_addi(RV_REG_SP, RV_REG_SP, -stack_size, ctx);
		emit_sd(RV_REG_SP, stack_size - 8, RV_REG_RA, ctx);
		emit_sd(RV_REG_SP, stack_size - 16, RV_REG_FP, ctx);
		emit_addi(RV_REG_FP, RV_REG_SP, stack_size, ctx);
	}

	/* callee saved register S1 to pass start time */
	emit_sd(RV_REG_FP, -sreg_off, RV_REG_S1, ctx);

	/* store ip address of the traced function */
	if (flags & BPF_TRAMP_F_IP_ARG) {
		emit_imm(RV_REG_T1, (const s64)func_addr, ctx);
		emit_sd(RV_REG_FP, -ip_off, RV_REG_T1, ctx);
	}

	emit_li(RV_REG_T1, nregs, ctx);
	emit_sd(RV_REG_FP, -nregs_off, RV_REG_T1, ctx);

	store_args(nregs, args_off, ctx);

	/* skip to actual body of traced function */
	if (flags & BPF_TRAMP_F_SKIP_FRAME)
		orig_call += RV_FENTRY_NINSNS * 4;

	if (flags & BPF_TRAMP_F_CALL_ORIG) {
		emit_imm(RV_REG_A0, (const s64)im, ctx);
		ret = emit_call((const u64)__bpf_tramp_enter, true, ctx);
		if (ret)
			return ret;
	}

	for (i = 0; i < fentry->nr_links; i++) {
		ret = invoke_bpf_prog(fentry->links[i], args_off, retval_off,
				      run_ctx_off,
				      flags & BPF_TRAMP_F_RET_FENTRY_RET, ctx);
		if (ret)
			return ret;
	}

	if (fmod_ret->nr_links) {
		branches_off =
			kcalloc(fmod_ret->nr_links, sizeof(int), GFP_KERNEL);
		if (!branches_off)
			return -ENOMEM;

		/* cleanup to avoid garbage return value confusion */
		emit_sd(RV_REG_FP, -retval_off, RV_REG_ZERO, ctx);
		for (i = 0; i < fmod_ret->nr_links; i++) {
			ret = invoke_bpf_prog(fmod_ret->links[i], args_off,
					      retval_off, run_ctx_off, true,
					      ctx);
			if (ret)
				goto out;
			emit_ld(RV_REG_T1, -retval_off, RV_REG_FP, ctx);
			branches_off[i] = ctx->ninsns;
			/* nop reserved for conditional jump */
			emit(rv_nop(), ctx);
		}
	}

	if (flags & BPF_TRAMP_F_CALL_ORIG) {
		restore_args(nregs, args_off, ctx);
		ret = emit_call((const u64)orig_call, true, ctx);
		if (ret)
			goto out;
		emit_sd(RV_REG_FP, -retval_off, RV_REG_A0, ctx);
		emit_sd(RV_REG_FP, -(retval_off - 8), regmap[BPF_REG_0], ctx);
		im->ip_after_call = ctx->insns + ctx->ninsns;
		/* 2 nops reserved for auipc+jalr pair */
		emit(rv_nop(), ctx);
		emit(rv_nop(), ctx);
	}

	/* update branches saved in invoke_bpf_mod_ret with bnez */
	for (i = 0; ctx->insns && i < fmod_ret->nr_links; i++) {
		offset = ninsns_rvoff(ctx->ninsns - branches_off[i]);
		insn = rv_bne(RV_REG_T1, RV_REG_ZERO, offset >> 1);
		*(u32 *)(ctx->insns + branches_off[i]) = insn;
	}

	for (i = 0; i < fexit->nr_links; i++) {
		ret = invoke_bpf_prog(fexit->links[i], args_off, retval_off,
				      run_ctx_off, false, ctx);
		if (ret)
			goto out;
	}

	if (flags & BPF_TRAMP_F_CALL_ORIG) {
		im->ip_epilogue = ctx->insns + ctx->ninsns;
		emit_imm(RV_REG_A0, (const s64)im, ctx);
		ret = emit_call((const u64)__bpf_tramp_exit, true, ctx);
		if (ret)
			goto out;
	}

	if (flags & BPF_TRAMP_F_RESTORE_REGS)
		restore_args(nregs, args_off, ctx);

	if (save_ret) {
		emit_ld(RV_REG_A0, -retval_off, RV_REG_FP, ctx);
		emit_ld(regmap[BPF_REG_0], -(retval_off - 8), RV_REG_FP, ctx);
	}

	emit_ld(RV_REG_S1, -sreg_off, RV_REG_FP, ctx);

	if (!is_struct_ops) {
		/* trampoline called from function entry */
		emit_ld(RV_REG_T0, stack_size - 8, RV_REG_SP, ctx);
		emit_ld(RV_REG_FP, stack_size - 16, RV_REG_SP, ctx);
		emit_addi(RV_REG_SP, RV_REG_SP, stack_size, ctx);

		emit_ld(RV_REG_RA, 8, RV_REG_SP, ctx);
		emit_ld(RV_REG_FP, 0, RV_REG_SP, ctx);
		emit_addi(RV_REG_SP, RV_REG_SP, 16, ctx);

		if (flags & BPF_TRAMP_F_SKIP_FRAME)
			/* return to parent function */
			emit_jalr(RV_REG_ZERO, RV_REG_RA, 0, ctx);
		else
			/* return to traced function */
			emit_jalr(RV_REG_ZERO, RV_REG_T0, 0, ctx);
	} else {
		/* trampoline called directly */
		emit_ld(RV_REG_RA, stack_size - 8, RV_REG_SP, ctx);
		emit_ld(RV_REG_FP, stack_size - 16, RV_REG_SP, ctx);
		emit_addi(RV_REG_SP, RV_REG_SP, stack_size, ctx);

		emit_jalr(RV_REG_ZERO, RV_REG_RA, 0, ctx);
	}

	ret = ctx->ninsns;
out:
	kfree(branches_off);
	return ret;
}

/**
 * @brief Calculate the size of the BPF trampoline for the
 * given architecture.
 *
 * @param m: The BTF function model for the trampoline.
 * @param flags: Flags to control the trampoline generation.
 * @param tlinks: The BPF trampoline links.
 * @param func_addr: The address of the function to be called by the trampoline.
 *
 * Returns the size of the trampoline in bytes, or a negative error code on
 * failure.
 */
int arch_bpf_trampoline_size(const struct btf_func_model *m, u32 flags,
			     struct bpf_tramp_links *tlinks, void *func_addr)
{
	struct bpf_tramp_image im;
	struct rv_jit_context ctx;
	int ret;

	ctx.ninsns = 0;
	ctx.insns = NULL;
	ctx.ro_insns = NULL;
	ret = __arch_prepare_bpf_trampoline(&im, m, tlinks, func_addr, flags,
					    &ctx);

	return ret < 0 ? ret : ninsns_rvoff(ctx.ninsns);
}

/**
 * @brief Prepare a BPF trampoline image for a specific architecture
 *
 * @param im: The BPF trampoline image to prepare
 * @param image: The memory region to write the JITed trampoline instructions to
 * @param image_end: The end of the memory region for the JITed trampoline instructions
 * @param m: The BTF function model for the trampoline
 * @param flags: Flags to control the trampoline generation
 * @param tlinks: The trampoline links to be updated
 * @param func_addr: The address of the function to be called by the trampoline
 *
 * This function prepares a BPF trampoline image for a specific architecture. It
 * sets up the JIT context, calls the architecture-specific
 * __arch_prepare_bpf_trampoline() function to generate the trampoline
 * instructions, and flushes the instruction cache.
 *
 * @return The number of instructions in the trampoline, or a negative error code
 *         on failure.
 */
int arch_prepare_bpf_trampoline(struct bpf_tramp_image *im, void *image,
				void *image_end, const struct btf_func_model *m,
				u32 flags, struct bpf_tramp_links *tlinks,
				void *func_addr)
{
	int ret;
	struct rv_jit_context ctx;

	ctx.ninsns = 0;
	/*
	 * The bpf_int_jit_compile() uses a RW buffer (ctx.insns) to write the
	 * JITed instructions and later copies it to a RX region (ctx.ro_insns).
	 * It also uses ctx.ro_insns to calculate offsets for jumps etc. As the
	 * trampoline image uses the same memory area for writing and execution,
	 * both ctx.insns and ctx.ro_insns can be set to image.
	 */
	ctx.insns = image;
	ctx.ro_insns = image;
	ret = __arch_prepare_bpf_trampoline(im, m, tlinks, func_addr, flags,
					    &ctx);
	if (ret < 0)
		return ret;

	bpf_flush_icache(ctx.insns, ctx.insns + ctx.ninsns);

	return ninsns_rvoff(ret);
}


int bpf_jit_emit_insn(const struct bpf_insn *insn, struct rv_jit_context *ctx,
		      bool extra_pass)
{
	bool is64 = BPF_CLASS(insn->code) == BPF_ALU64 ||
		    BPF_CLASS(insn->code) == BPF_JMP;
	int s, e, rvoff, ret, i = insn - ctx->prog->insnsi;
	struct bpf_prog_aux *aux = ctx->prog->aux;
	u8 rd = -1, rs = -1, code = insn->code;
	s16 off = insn->off;
	s32 imm = insn->imm;

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

	/* function call */
	case BPF_JMP | BPF_CALL: {
		bool fixed_addr;
		u64 addr;

		mark_call(ctx);
		ret = bpf_jit_get_func_addr(
			ctx->prog, insn, extra_pass, &addr,
			&fixed_addr); // TODO: check for external funcs (helpers or kfuncs and decide what to do)
		if (ret < 0)
			return ret;

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

/**
 * @brief Builds the prologue for the RISC-V JIT compiler.
 *
 * This function is responsible for setting up the stack frame and saving
 * any necessary registers before the main body of the BPF program is
 * executed. It performs the following tasks:
 *
 * 1. Rounds up the BPF stack depth to a multiple of 16 bytes and marks the
 *    frame pointer register if the stack depth is non-zero.
 * 2. Calculates the total stack adjustment needed to accommodate the saved
 *    registers (return address, frame pointer, and callee-saved registers).
 * 3. Emits the necessary instructions to adjust the stack pointer and save
 *    the required registers.
 * 4. Sets the frame pointer to the adjusted stack pointer.
 * 5. Adjusts the stack pointer to accommodate the BPF program's stack usage.
 * 6. Saves the tail call counter register if the program contains both calls
 *    and tail calls.
 *
 * @param ctx The RISC-V JIT context containing the information about the
 *            BPF program being compiled.
 */
void bpf_jit_build_prologue(struct rv_jit_context *ctx)
{
	int i, stack_adjust = 0, store_offset, bpf_stack_adjust;

	bpf_stack_adjust = round_up(ctx->prog->aux->stack_depth, 16);
	if (bpf_stack_adjust)
		mark_fp(ctx);

	if (seen_reg(RV_REG_RA, ctx))
		stack_adjust += 8;
	stack_adjust += 8; /* RV_REG_FP */
	if (seen_reg(RV_REG_S1, ctx))
		stack_adjust += 8;
	if (seen_reg(RV_REG_S2, ctx))
		stack_adjust += 8;
	if (seen_reg(RV_REG_S3, ctx))
		stack_adjust += 8;
	if (seen_reg(RV_REG_S4, ctx))
		stack_adjust += 8;
	if (seen_reg(RV_REG_S5, ctx))
		stack_adjust += 8;
	if (seen_reg(RV_REG_S6, ctx))
		stack_adjust += 8;

	stack_adjust = round_up(stack_adjust, 16);
	stack_adjust += bpf_stack_adjust;

	store_offset = stack_adjust - 8;

	/* nops reserved for auipc+jalr pair */
	for (i = 0; i < RV_FENTRY_NINSNS; i++)
		emit(rv_nop(), ctx);

	/* First instruction is always setting the tail-call-counter
	 * (TCC) register. This instruction is skipped for tail calls.
	 * Force using a 4-byte (non-compressed) instruction.
	 */
	emit(rv_addi(RV_REG_TCC, RV_REG_ZERO, MAX_TAIL_CALL_CNT), ctx);

	emit_addi(RV_REG_SP, RV_REG_SP, -stack_adjust, ctx);

	if (seen_reg(RV_REG_RA, ctx)) {
		emit_sd(RV_REG_SP, store_offset, RV_REG_RA, ctx);
		store_offset -= 8;
	}
	emit_sd(RV_REG_SP, store_offset, RV_REG_FP, ctx);
	store_offset -= 8;
	if (seen_reg(RV_REG_S1, ctx)) {
		emit_sd(RV_REG_SP, store_offset, RV_REG_S1, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S2, ctx)) {
		emit_sd(RV_REG_SP, store_offset, RV_REG_S2, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S3, ctx)) {
		emit_sd(RV_REG_SP, store_offset, RV_REG_S3, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S4, ctx)) {
		emit_sd(RV_REG_SP, store_offset, RV_REG_S4, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S5, ctx)) {
		emit_sd(RV_REG_SP, store_offset, RV_REG_S5, ctx);
		store_offset -= 8;
	}
	if (seen_reg(RV_REG_S6, ctx)) {
		emit_sd(RV_REG_SP, store_offset, RV_REG_S6, ctx);
		store_offset -= 8;
	}

	emit_addi(RV_REG_FP, RV_REG_SP, stack_adjust, ctx);

	if (bpf_stack_adjust)
		emit_addi(RV_REG_S5, RV_REG_SP, bpf_stack_adjust, ctx);

	/* Program contains calls and tail calls, so RV_REG_TCC need
	 * to be saved across calls.
	 */
	if (seen_tail_call(ctx) && seen_call(ctx))
		emit_mv(RV_REG_TCC_SAVED, RV_REG_TCC, ctx);

	ctx->stack_size = stack_adjust;
}

/**
 * Builds the epilogue for the JIT-compiled BPF program.
 *
 * @param ctx The JIT compilation context.
 */
void bpf_jit_build_epilogue(struct rv_jit_context *ctx)
{
	__build_epilogue(false, ctx);
}

/**
 * Checks if the BPF JIT compiler supports calling kernel functions.
 *
 * @return true if the BPF JIT compiler supports calling kernel functions, false otherwise.
 */
bool bpf_jit_supports_kfunc_call(void)
{
	return true;
}
