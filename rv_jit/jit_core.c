//
// Created by Davide Collovigh on 24/05/24.
//

#include <stdbool.h>

#include "jit.h"

static int rvo_bpf_jit_compile(struct bpf_prog *prog)
{
	if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)) {
		return -EOPNOTSUPP;
	}

	unsigned int prog_size = 0, extable_size = 0;
	bool tmp_blinded = false, extra_pass = false;
	struct bpf_prog *tmp, *orig_prog = prog;
	int pass = 0, prev_ninsns = 0, i;
	struct rv_jit_data *jit_data;
	struct rv_jit_context *ctx;

	// if JIT not requested => returns original prog
	if (!prog->jit_requested)
		return orig_prog;

	// creates a copy of the original program and replaces the constant values with randomized or obfuscated values to prevent the compiler from optimizing the code based on const.
	// Maybe we do not need it?
	tmp = bpf_jit_blind_constants(prog);
	if (IS_ERR(tmp))
		return orig_prog;
	if (tmp != prog) {
		tmp_blinded = true;
		prog = tmp;
	}

	// get or create jit_data
	jit_data = prog->aux->jit_data;
	if (!jit_data) {
		jit_data = kzalloc(sizeof(*jit_data), GFP_KERNEL);
		if (!jit_data) {
			prog = orig_prog;
			goto out;
		}
		prog->aux->jit_data = jit_data;
	}

	ctx = &jit_data->ctx;

	/* this part is for when the function is called but the optimization was already done, can it happen ?
	// if offset already exists => this is not the first pass
	if (ctx->offset) {
		extra_pass = true;
		prog_size = sizeof(*ctx->insns) * ctx->ninsns;
		goto skip_init_ctx;
	}
*/
	ctx->prog = prog;
	ctx->offset = kcalloc(prog->len, sizeof(int), GFP_KERNEL);
	if (!ctx->offset) {
		prog = orig_prog;
		goto out_offset;
	}

	// replace BPF instructions with their corresponding RISC-V instructions
	// needed by folowing block to count instructions
	if (build_body(ctx, extra_pass, NULL)) {
		prog = orig_prog;
		goto out_offset;
	}

	// sets offset for each instruction to the number of instructions that have been emitted so far * 32
	for (i = 0; i < prog->len; i++) {
		prev_ninsns += 32;
		ctx->offset[i] = prev_ninsns;
	}

	// optimization loop
	for (i = 0; i < NR_JIT_ITERATIONS; i++) {
		pass++;
		ctx->ninsns = 0;

		bpf_jit_build_prologue(ctx);
		ctx->prologue_len = ctx->ninsns;

		if (build_body(ctx, extra_pass, ctx->offset)) {
			prog = orig_prog;
			goto out_offset;
		}

		ctx->epilogue_offset = ctx->ninsns;
		bpf_jit_build_epilogue(ctx);

		if (ctx->ninsns == prev_ninsns) {
			if (jit_data->header)
				break;

			/* obtain the actual image size */
			extable_size = prog->aux->num_exentries *
				       sizeof(struct exception_table_entry);

			prog_size = sizeof(*ctx->insns) * ctx->ninsns;

			// ALLOCATES SPACE FOR PROGRAM
			jit_data->ro_header = rv_jit_binary_alloc(
				prog_size + extable_size, &jit_data->ro_image,
				sizeof(u32), &jit_data->header,
				&jit_data->image);

			if (!jit_data->ro_header) {
				prog = orig_prog;
				goto out_offset;
			}

			/*
             * Use the image(RW) for writing the JITed instructions. But also save
             * the ro_image(RX) for calculating the offsets in the image. The RW
             * image will be later copied to the RX image from where the program
             * will run. The bpf_jit_binary_pack_finalize() will do this copy in the
             * final step.
             */
			ctx->ro_insns = (u16 *)jit_data->ro_image;
			ctx->insns = (u16 *)jit_data->image;
			/*
             * Now, when the image is allocated, the image can
             * potentially shrink more (auipc/jalr -> jal).
             */
		}
		prev_ninsns = ctx->ninsns;
	}

	if (i == NR_JIT_ITERATIONS) {
		pr_err("bpf-jit: image did not converge in <%d passes!\n", i);
		prog = orig_prog;
		goto out_free_hdr;
	}

	if (extable_size)
		prog->aux->extable = (void *)ctx->ro_insns + prog_size;

skip_init_ctx:
	pass++;
	ctx->ninsns = 0;
	ctx->nexentries = 0;

	bpf_jit_build_prologue(ctx);
	if (build_body(ctx, extra_pass, NULL)) {
		prog = orig_prog;
		goto out_free_hdr;
	}
	bpf_jit_build_epilogue(ctx);

	// if (bpf_jit_enable > 1) TODO: introduce var to enable/disable dumping
	rv_bpf_jit_dump(prog->len, prog_size, pass, ctx->insns);

	prog->bpf_func = (void *)ctx->ro_insns;
	prog->jited = 1;
	prog->jited_len = prog_size;

	if (!prog->is_func || extra_pass) {
		if (WARN_ON(rv_jit_binary_pack_finalize(
			    prog, jit_data->ro_header, jit_data->header))) {
			/* ro_header has been freed */
			jit_data->ro_header = NULL;
			prog = orig_prog;
			goto out_offset;
		}

		// /*
		//  * The instructions have now been copied to the ROX region from
		//  * where they will execute.
		//  * Write any modified data cache blocks out to memory and
		//  * invalidate the corresponding blocks in the instruction cache.
		//  */
		// bpf_flush_icache(jit_data->ro_header,
		// 		 ctx->ro_insns + ctx->ninsns);

		for (i = 0; i < prog->len; i++)
			ctx->offset[i] = ninsns_rvoff(ctx->offset[i]);

		bpf_prog_fill_jited_linfo(prog, ctx->offset);
out_offset:
		kfree(ctx->offset);
		kfree(jit_data);
		prog->aux->jit_data = NULL;
	}
out:

	if (tmp_blinded)
		bpf_jit_prog_release_other(prog,
					   prog == orig_prog ? tmp : orig_prog);
	return prog;

out_free_hdr:
	if (jit_data->header) {
		bpf_arch_text_copy(&jit_data->ro_header->size,
				   &jit_data->header->size,
				   sizeof(jit_data->header->size));
		bpf_jit_binary_pack_free(jit_data->ro_header, jit_data->header);
	}
	goto out_offset;
}

int build_body(struct rv_jit_context *ctx, bool extra_pass, int *offset)
{
	const struct bpf_prog *prog = ctx->prog;
	int i;

	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		int ret;

		ret = bpf_jit_emit_insn(insn, ctx, extra_pass);
		/* BPF_LD | BPF_IMM | BPF_DW: skip the next instruction. */
		if (ret > 0)
			i++;

		//  If offset is not NULL, it stores the current value of ctx->ninsns (the number of emitted instructions so far) in offset[i]
		if (offset)
			offset[i] = ctx->ninsns;
		if (ret < 0)
			return ret;
	}
	return 0;
}

inline int invert_bpf_cond(u8 cond)
{
	switch (cond) {
	case BPF_JEQ:
		return BPF_JNE;
	case BPF_JGT:
		return BPF_JLE;
	case BPF_JLT:
		return BPF_JGE;
	case BPF_JGE:
		return BPF_JLT;
	case BPF_JLE:
		return BPF_JGT;
	case BPF_JNE:
		return BPF_JEQ;
	case BPF_JSGT:
		return BPF_JSLE;
	case BPF_JSLT:
		return BPF_JSGE;
	case BPF_JSGE:
		return BPF_JSLT;
	case BPF_JSLE:
		return BPF_JSGT;
	}
	return -1;
}