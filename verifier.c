//
// Created by davide on 6/23/24.
//

#include <linux/list.h>

#include "verifier.h"

#define get_meta_first_instruction(rvo_prog) \
	list_first_entry(&(rvo_prog)->insn_meta, struct rvo_insn_meta, l)
#define get_meta_last_instruction(rvo_prog) \
	list_last_entry(&(rvo_prog)->insn_meta, struct rvo_insn_meta, l)
#define get_meta_next_instruction(meta) list_next_entry(meta, l)
#define get_meta_prev_instruction(meta) list_prev_entry(meta, l)

rvo_insn_meta *rvo_get_insn_meta(const rvo_prog *prog, rvo_insn_meta *meta,
				 const unsigned int insn_idx)
{
	unsigned int i;

	// calculate the distance (in terms of instructions) between the current instruction and the target instruction
	// both in the forward and backward directions.
	unsigned int backward = meta->n - insn_idx;
	unsigned int forward = insn_idx - meta->n;

	// number of instructions remaining in the program from the current position
	const unsigned int remaining = prog->ninsns - insn_idx - 1;

	if (min(forward, backward) > remaining) {
		// the target instruction is beyond the end of the program
		backward = prog->ninsns - insn_idx - 1;
		meta = get_meta_last_instruction(prog);
	}
	if (min(forward, backward) > insn_idx && backward > insn_idx) {
		// the target instruction is before the start of the program
		forward = insn_idx;
		meta = get_meta_first_instruction(prog);
	}

	if (forward < backward) {
		// Iterate forward times using get_meta_next_instruction(meta) to move to the target instruction metadata.
		for (i = 0; i < forward; i++) {
			meta = get_meta_next_instruction(meta);
		}
	} else {
		// Iterate backward times using get_meta_prev_instruction(meta) to move to the target instruction metadata.
		for (i = 0; i < backward; i++) {
			meta = get_meta_prev_instruction(meta);
		}
	}

	return meta;
}

// JUMP instruction

int is_jump_instruction(const struct bpf_insn insn)

		return BPF_CLASS(insn.code) == BPF_JMP;
}
int verify_jump_instruction(const struct bpf_insn insn,
			    struct bpf_verifier_env *env)
{
	if (BPF_OP(insn.code) == BPF_CALL) {
		return !is_helper_call(insn);
	}

	return 1;
}

int is_helper_call(const struct bpf_insn insn)
{
	/*
	 * opcode:
	 *   1000 0 101   src_reg = 0000 (0) -> call helper function by static ID
	 *   1000 0 101   src_reg = 0010 (2) -> call helper function by BTF ID
	 *   ---- - ---
	 *   CALL K JMP
	 */

	if (is_jump_instruction(insn) && BPF_OP(insn.code) == BPF_CALL &&
	    insn.src_reg != BPF_PSEUDO_CALL) {
		pr_err("Unsupported helper func jump instruction found");
		return 1;
	}

	return 0;
}
int is_kfunc_call(const struct bpf_insn insn)
{
	if (is_jump_instruction(insn) && BPF_OP(insn.code) == BPF_CALL &&
	    insn.src_reg != BPF_PSEUDO_KFUNC_CALL) {
		pr_err("Unsupported kfunc instruction found");
		return 1;
	}

	return 0;
}

// LOAD instruction

int is_load_instruction(const struct bpf_insn insn)
{
	return (BPF_CLASS(insn.code) == BPF_LD ||
		BPF_CLASS(insn.code) == BPF_LDX);
}
int verify_load_instruction(const struct bpf_insn insn,
			    struct bpf_verifier_env *env)
{
	// all ok
	return 1;
}

// STORE instruction

int is_store_instruction(const struct bpf_insn insn)
{
	return (BPF_CLASS(insn.code) == BPF_ST ||
		BPF_CLASS(insn.code) == BPF_STX);
}
int verify_store_instruction(const struct bpf_insn insn,
			     struct bpf_verifier_env *env)
{
	// all ok
	return 1;
}

int is_atomic_store(const struct bpf_insn insn)
{
	//  OP  S CLS
	// ---- - ---
	// 1100 0 000   BPF_ATOMIC
	// 0000 0 011   BPF_STX

	return (BPF_CLASS(insn.code) == BPF_STX &&
		BPF_OP(insn.code) == BPF_ATOMIC);
}

// ALU instruction

int is_alu_instruction(const struct bpf_insn insn)
{
	return (BPF_CLASS(insn.code) == BPF_ALU ||
		BPF_CLASS(insn.code) == BPF_ALU64);
}
int verify_alu_instruction(const struct bpf_insn insn,
			   struct bpf_verifier_env *env)
{
	// all ok
	return 1;
}

// Main function

int rvo_isn_verify(struct bpf_verifier_env *env, int insn_idx,
		   int prev_insn_idx)
{
	rvo_prog *prog = env->prog->aux->offload->dev_priv;

	/** META STUFF **/
	rvo_insn_meta *meta = prog->verifier_meta;
	meta = rvo_get_insn_meta(prog, meta, insn_idx);

	const struct bpf_insn insn = meta->insn;

	// if insn uses extended BPF regs -> error
	if (insn.src_reg >= MAX_BPF_REG || insn.dst_reg >= MAX_BPF_REG) {
		pr_err("program uses extended registers, unsupported\n");
		return -EINVAL;
	}

	if (!verifier_map[BPF_CLASS(insn.code)](insn, env)) {
		pr_err("Unsupported instruction found");
		return -EINVAL;
	}

	return 0;
}
