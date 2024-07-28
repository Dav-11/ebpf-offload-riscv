//
// Created by davide on 6/23/24.
//

#include "verifier.h"

// JUMP instruction

bool verify_jump_instruction(const struct bpf_insn *insn, rvo_prog *ctx)
{
	if (BPF_OP(insn->code) == BPF_CALL) {
		return !is_helper_call(insn);
	}

	return 1;
}

bool verify_pseudofunc_offset(const struct bpf_insn *insn, rvo_prog *ctx)
{
    //TODO: implement
    return false;
}

// LOAD instruction

bool verify_load_instruction(const struct bpf_insn *insn, rvo_prog *ctx)
{
	// all ok
	return 1;
}

// STORE instruction

bool verify_store_instruction(const struct bpf_insn *insn, rvo_prog *ctx)
{
	// all ok
	return 1;
}

// ALU instruction

bool verify_alu_instruction(const struct bpf_insn *insn, rvo_prog *ctx)
{
	// all ok
	return 1;
}

// Main function

int rvo_isn_verify(struct bpf_verifier_env *env, int insn_idx,
		   int prev_insn_idx)
{
	rvo_prog *prog = env->prog->aux->offload->dev_priv;
	struct bpf_insn *insn;

	/** META STUFF **/
	rvo_insn_meta *meta = prog->curr_meta;
	meta = rvo_get_insn_meta(prog, meta, insn_idx);

	insn = meta->insn;

	// if insn uses extended BPF regs -> error
	if (insn->src_reg >= MAX_BPF_REG || insn->dst_reg >= MAX_BPF_REG) {
		pr_err("program uses extended registers, unsupported\n");
		return -EINVAL;
	}

	if (!verifier_map[BPF_CLASS(insn->code)](insn, prog)) {
		pr_err("Unsupported instruction found");
		return -EINVAL;
	}

	return 0;
}
