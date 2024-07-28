//
// Created by davide on 6/22/24.
//

#include "offload_prog.h"

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

int rvo_translate(struct bpf_prog *prog)
{
	/*
	rvo_prog *p = prog->aux->offload->dev_priv;

	unsigned int max_instr;
	int err;

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