//
// Created by davide on 6/23/24.
//

#ifndef VERIFIER_H
#define VERIFIER_H

#include "base.h"
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

typedef int (*verifier_t)(const struct bpf_insn, struct bpf_verifier_env *);

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
int is_jump_instruction(const struct bpf_insn insn);
int verify_jump_instruction(const struct bpf_insn insn,
			    struct bpf_verifier_env *env);

/**
 * Checks if the function is NOT a BPF to BPF (pseudo) CALL
 * @param insn the instruction to check
 * @return 1 if the instruction is a call to ext functions
 */
int is_helper_call(const struct bpf_insn insn);

// LOAD instructions
int is_load_instruction(const struct bpf_insn insn);
int verify_load_instruction(const struct bpf_insn insn,
			    struct bpf_verifier_env *env);

// STORE instructions
int is_store_instruction(const struct bpf_insn insn);
int verify_store_instruction(const struct bpf_insn insn,
			     struct bpf_verifier_env *env);

int is_atomic_store(const struct bpf_insn insn);

// ALU instructions
int is_alu_instruction(const struct bpf_insn insn);
int verify_alu_instruction(const struct bpf_insn insn,
			   struct bpf_verifier_env *env);

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
