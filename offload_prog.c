//
// Created by davide on 6/22/24.
//

#include "offload_prog.h"

int rvo_isn_verify(struct bpf_verifier_env *env, int insn_idx,
                   int prev_insn_idx)
{

	rvo_prog *prog = env->prog->aux->offload->dev_priv;
	rvo_insn_meta *meta = prog->verifier_meta;

	meta = rvo_get_insn_meta(prog, meta, insn_idx);

	// check if insn opcode exists in mapping
	if (!rvo_insn_opcode_supported(meta->insn.code)) {
		pr_err("instruction %#02x not supported\n",
			meta->insn.code);

		return -EINVAL;
	}

	// if insn uses extended BPF regs -> error
	if (meta->insn.src_reg >= MAX_BPF_REG || meta->insn.dst_reg >= MAX_BPF_REG) {
		pr_err("program uses extended registers, unsupported\n");
		return -EINVAL;
	}

	if (!verifier_map[BPF_CLASS(meta->insn.code)](prog, env)) {

		pr_err("Unsupported instruction found");
		return -EINVAL;
	}

	return 0;
}

int rvo_finalize(struct bpf_verifier_env *env)
{
	// TODO: implement
	return 0;
}

int rvo_replace_insn(struct bpf_verifier_env *env, u32 off,
		     struct bpf_insn *insn)
{
	// TODO: implement
	return 0;
}

int rvo_remove_insns(struct bpf_verifier_env *env, u32 off, u32 cnt)
{
	// TODO: implement
	return 0;
}

int rvo_prepare(struct bpf_prog *prog)
{
	// TODO: implement
	return 0;
}

int rvo_translate(struct bpf_prog *prog)
{
	/*
    struct bpf_prog *translated = NULL;

    translated = rvo_bpf_int_jit_compile(prog);

    prog = translated;
     */

	return 0;
}

void rvo_destroy(struct bpf_prog *prog)
{
	// TODO: implement
	return;
}