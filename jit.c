//
// Created by Davide Collovigh on 01/07/24.
//

#include "jit.h"

static int build_body(rvo_jit_context *ctx, bool extra_pass, int *offset)
{
	const struct bpf_prog *prog = ctx->prog;

	for (int i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		int ret;

		ret = bpf_jit_emit_insn(insn, ctx, extra_pass);
	}
}

void build_prologue(rvo_jit_context *ctx, bool is_subprog)
{
}

void build_epilogue(rvo_jit_context *ctx)
{
}

int jit_compile(struct bpf_prog *prog)
{
	// init
	unsigned int prog_size = 0;
	unsigned int extable_size = 0;

	bool tmp_blinded = false;
	bool extra_pass = false;

	struct bpf_prog *tmp;
	struct bpf_prog *orig_prog = prog;

	int i;
	int pass = 0;
	int prev_ninsns = 0;

	if (!prog->jit_requested) {
		return orig_prog;
	}

	rvo_jit_context *ctx;
	rvo_jit_data *jit_data = prog->aux->jit_data;
	if (!jit_data) {
		jit_data = kzalloc(sizeof(*jit_data), GFP_KERNEL);
		if (!jit_data) {
			prog = orig_prog;
			goto out;
		}
		prog->aux->jit_data = jit_data;
	}

	ctx = &jit_data->ctx;

	if (ctx->offset) {
		extra_pass = true;
		prog_size = sizeof(*ctx->insns) * ctx->ninsns;
		goto skip_init_ctx;
	}

	ctx->prog = prog;
	ctx->offset = kcalloc(prog->len, sizeof(int), GFP_KERNEL);
	if (!ctx->offset) {
		prog = orig_prog;
		goto out_offset;
	}

	return 0;
}