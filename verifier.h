//
// Created by davide on 6/23/24.
//

#ifndef VERIFIER_H
#define VERIFIER_H

#include "base.h"
#include "bpf_code.h"
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/list.h>

typedef bool (*verifier_t)(const struct bpf_insn *, rvo_prog *);

/***********************************
 * funcs
 **********************************/

/**
 * This callback is invoked during BPF instruction verification.
 * It allows the offload device to inspect each BPF instruction during
 * verification.
 *
 * @param env The verifier environment
 * @param insn_idx The index of the current instruction
 * @param prev_insn_idx The index of the previous instruction
 * @return
 */
int rvo_isn_verify(struct bpf_verifier_env *env, int insn_idx,
		   int prev_insn_idx);

// JUMP instructions
bool verify_jump_instruction(const struct bpf_insn *insn, rvo_prog *ctx);
bool verify_pseudofunc_offset(const struct bpf_insn *insn, rvo_prog *ctx);

// LOAD instructions
bool verify_load_instruction(const struct bpf_insn *insn, rvo_prog *ctx);

// STORE instructions
bool verify_store_instruction(const struct bpf_insn *insn, rvo_prog *ctx);

// ALU instructions
bool verify_alu_instruction(const struct bpf_insn *insn, rvo_prog *ctx);

/***********************************
 * MAP insn class -> verifier fn
 **********************************/

static const verifier_t verifier_map[8] = {
	[BPF_JMP] = verify_jump_instruction,
	[BPF_JMP32] = verify_jump_instruction,
	[BPF_LD] = verify_load_instruction,
	[BPF_LDX] = verify_load_instruction,
	[BPF_ST] = verify_store_instruction,
	[BPF_STX] = verify_store_instruction,
	[BPF_ALU] = verify_alu_instruction,
	[BPF_ALU64] = verify_alu_instruction,
};

#endif //VERIFIER_H
