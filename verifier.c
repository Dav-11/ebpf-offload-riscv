//
// Created by davide on 6/23/24.
//

#include <linux/list.h>

#include "verifier.h"

// JUMP instruction

int is_jump_instruction(const struct bpf_insn insn)
{
	__u8 const code = BPF_CLASS(insn.code);
	return (code == BPF_JMP);
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
	rvo_insn_meta *meta = prog->curr_meta;
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
