//
// Created by Davide Collovigh on 01/07/24.
//

#include "jit.h"
#include "verifier.h"
#include <linux/random.h>
#include <linux/printk.h>
#include <linux/pid.h>

static void jit_dump(unsigned int len, unsigned int prog_len, u32 pass,
		     void *image)
{
	pr_err("bpf_len=%u riscv_len=%u pass=%u image=%pK from=%s pid=%d\n",
	       len, prog_len, pass, image, current->comm, task_pid_nr(current));

	if (image)
		print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_OFFSET, 16,
			       1, image, prog_len, false);
}

static int build_body(rvo_prog *ctx, bool extra_pass, int *offset)
{
	const struct bpf_prog *prog = ctx->prog;
	int i;

	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		int ret;

		ret = bpf_jit_emit_insn(insn, ctx, extra_pass);
	}

	return 0;
}

// TODO: understand what this is
static inline int rv_cfi_get_offset(void)
{
	return 4;
}

static inline void bpf_fill_ill_insns(void *area, unsigned int size)
{
	memset(area, 0, size);
}

void build_prologue(rvo_prog *ctx, bool is_subprog)
{
	//TODO: implement
}

void build_epilogue(rvo_prog *ctx)
{
	// TODO: implement
}

bool is_subprog(struct bpf_prog *prog)
{
	// TODO: implement
	return false;
}

static unsigned int get_extable_size(rvo_prog *prog)
{
	// TODO: implement
	// prog->aux->num_exentries * sizeof(struct exception_table_entry);
	return 0;
}

static struct bpf_binary_header *
jit_binary_alloc(unsigned int prog_len, u8 **img_ptr, unsigned int alignment,
		 bpf_jit_fill_hole_t bpf_fill_ill_insns)
{
	struct bpf_binary_header *header;
	u32 size, hole, start;

	WARN_ON_ONCE(!is_power_of_2(alignment) ||
		     alignment > BPF_IMAGE_ALIGNMENT);

	/* add 16 bytes for a random section of illegal instructions */
	size = round_up(prog_len + sizeof(*header) + 16, BPF_PROG_CHUNK_SIZE);

	// alloc struct for compiled insn
	// TODO: move to DMA (see dma_alloc_coherent() )
	header = kvmalloc(size, GFP_KERNEL);
	if (!header) {
		return NULL;
	}

	/* Fill space with illegal/arch-dep instructions. */
	bpf_fill_ill_insns(header, size);
	//header->size = size;  // req ker >= 6.8

	// return min between
	hole = min_t(unsigned int, // data type
		     size - (prog_len + sizeof(*header)), // first val
		     BPF_PROG_CHUNK_SIZE - sizeof(*header) // second val
	);

	//start = get_random_u32_below(hole) & ~(alignment - 1); // req ker >= 6.8

	*img_ptr = &header->image[start];

	return header;
}

//struct bpf_prog * jit_compile(struct bpf_prog *prog)
//{
//	// init
//	unsigned int prog_size = 0;
//	unsigned int extable_size = 0;
//
//	bool tmp_blinded = false;
//	bool extra_pass = false;
//
//	struct bpf_prog *tmp;
//	struct bpf_prog *orig_prog = prog;
//	rvo_prog *ctx;
//
//	rv_jit_data *jit_data;
//
//	int i, err;
//	int pass = 0;
//	int prev_ninsns = 0;
//
//	if (!prog->jit_requested) {
//		return orig_prog;
//	}
//
//	ctx = prog->aux->offload->dev_priv;
//
//	jit_data = ctx->jit_data;
//	if (!jit_data) {
//		jit_data = kzalloc(sizeof(*jit_data), GFP_KERNEL);
//		if (!jit_data) {
//			prog = orig_prog;
//			goto out;
//		}
//		ctx->jit_data = jit_data;
//	}
//
//	if (ctx->insns) {
//		extra_pass = true;
//		prog_size = sizeof(*ctx->insns) * ctx->ninsns;
//		goto skip_init_ctx;
//	}
//
//	// alloc offset array to hold offset for each insn start
//	ctx->offset = kcalloc(prog->len, sizeof(int), GFP_KERNEL);
//	if (!ctx->offset) {
//		prog = orig_prog;
//		goto out_offset;
//	}
//
//	// first iteration to generate regs and prog_size info
//	if (build_body(ctx, extra_pass, NULL)) {
//		prog = orig_prog;
//		goto out_offset;
//	}
//
//	// init insn to 32bit size each
//	for (i = 0; i < prog->len; i++) {
//		prev_ninsns += 32;
//		ctx->offset[i] = prev_ninsns;
//	}
//
//	for (i = 0; i < NR_JIT_ITERATIONS; i++) {
//		pass++;
//		ctx->ninsns = 0;
//
//		// emit insns for prologue
//		build_prologue(ctx, is_subprog(prog));
//
//		ctx->prologue_len = ctx->ninsns;
//
//		if (build_body(ctx, extra_pass, ctx->offset)) {
//			prog = orig_prog;
//			goto out_offset;
//		}
//
//		ctx->epilogue_offset = ctx->ninsns;
//		build_epilogue(ctx);
//
//		// if the number of insn is stable -> max optimization -> start finalization
//		if (ctx->ninsns == prev_ninsns) {
//			if (jit_data->header)
//				break;
//
//			extable_size = get_extable_size(ctx);
//			prog_size = sizeof(*ctx->insns) * ctx->ninsns;
//
//			jit_data->header = jit_binary_alloc(
//				prog_size + extable_size,
//				&jit_data->image,
//				sizeof(u32),
//				bpf_fill_ill_insns);
//			if (!jit_data->header) {
//				prog = orig_prog;
//				goto out_offset;
//			}
//
//			ctx->insns = (u16 *)jit_data->image;
//		}
//
//		prev_ninsns = ctx->ninsns;
//	}
//
//	if (i == NR_JIT_ITERATIONS) {
//		pr_err("bpf-jit: image did not converge in <%d passes!\n", i);
//		prog = orig_prog;
//		goto out_free_hdr;
//	}
//
//	// TODO: fix
//	if (extable_size) {
//		prog->aux->extable = (void *)ctx->insns + prog_size;
//	}
//
//	jit_dump(prog->len, prog_size, pass, ctx->insns);
//
//	/**
//	 * TODO: from here downwards, it needs to be reviewed
//	 */
//
//	prog->bpf_func = (void *)ctx->insns - rv_cfi_get_offset();
//	prog->jited = 1;
//	prog->jited_len = prog_size - rv_cfi_get_offset();
//
//	if (!prog->is_func || extra_pass) {
//		//  --- THIS PART IS USED TO MOVE RO-DATA TO RX-DATA ---
//		//
//		//
//		//		if (WARN_ON(bpf_jit_binary_pack_finalize(
//		//			    prog, jit_data->ro_header, jit_data->header))) {
//		//			/* ro_header has been freed */
//		//			jit_data->ro_header = NULL;
//		//			prog = orig_prog;
//		//			goto out_offset;
//		//		}
//		//		/*
//		//		 * The instructions have now been copied to the ROX region from
//		//		 * where they will execute.
//		//		 * Write any modified data cache blocks out to memory and
//		//		 * invalidate the corresponding blocks in the instruction cache.
//		//		 */
//		//		bpf_flush_icache(jit_data->ro_header,
//		//				 ctx->ro_insns + ctx->ninsns);
//		//
//		//
//		// --- END ---
//
//		// replace offset (16 bit) with byte offset (*2)
//		for (i = 0; i < prog->len; i++) {
//			ctx->offset[i] = ninsns_rvoff(ctx->offset[i]);
//		}
//
//		bpf_prog_fill_jited_linfo(prog, ctx->offset);
//out_offset:
//		kfree(ctx->offset);
//		kfree(jit_data);
//		prog->aux->jit_data = NULL;
//	}
//out:
//
//	if (tmp_blinded)
//		bpf_jit_prog_release_other(prog,
//					   prog == orig_prog ? tmp : orig_prog);
//	return prog;
//
//out_free_hdr:
//	if (jit_data->header) {
//		bpf_arch_text_copy(&jit_data->ro_header->size,
//				   &jit_data->header->size,
//				   sizeof(jit_data->header->size));
//		bpf_jit_binary_pack_free(jit_data->ro_header, jit_data->header);
//	}
//	goto out_offset;
//
//skip_init_ctx:
//	pass++;
//	ctx->ninsns = 0;
//	ctx->nexentries = 0; // TODO: understand what it is
//
//	build_prologue(ctx, is_subprog(prog));
//
//	if (build_body(ctx, extra_pass, ctx->offset)) {
//		prog = orig_prog;
//		goto out_free_hdr;
//	}
//
//	build_epilogue(ctx);
//
//out_offset:
//
//	return 0;
//out_err:
//	return err;
//}

bool is_signed_bpf_cond(u8 cond)
{
	return cond == BPF_JSGT || cond == BPF_JSLT || cond == BPF_JSGE ||
	       cond == BPF_JSLE;
}

/**
 * @brief Return -1 or inverted cond.
 */
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

int rvo_bpf_jit_get_func_addr(const struct bpf_prog *prog,
			      const struct bpf_insn *insn, bool extra_pass,
			      u64 *func_addr, bool *func_addr_fixed)
{
	s16 off = insn->off;
	s32 imm = insn->imm;
	u8 *addr;
	int err;
	rvo_prog *p;

	if (is_jump_instruction(insn)) {
		if (BPF_OP(insn->code) == BPF_EXIT) {
			return 0;
		}

		if (is_helper_call(insn)) {
			return -EINVAL;
		}

		/*
         * BPF-to-BPF call (a.k.a pseudo call).
         */
		if (is_pseudo_call(insn)) {
			/* Place-holder address till the last pass has collected
             * all addresses for JITed subprograms in which case we
             * can pick them up from prog->aux.
             */
			if (!extra_pass)
				addr = NULL;

			p = prog->aux->offload->dev_priv;
            if (verify_pseudofunc_offset(insn, p))
			{
				addr = (u8 *)prog->aux->func[off]->bpf_func;
			}
		}
	}

	//	*func_addr_fixed = insn->src_reg != BPF_PSEUDO_CALL;
	//	if (!*func_addr_fixed) {
	//		else if (prog->aux->func && off >= 0 &&
	//			 off < prog->aux->real_func_cnt)
	//			addr = (u8 *)prog->aux->func[off]->bpf_func;
	//		else return -EINVAL;
	//		//    } else if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL &&
	//		//               bpf_jit_supports_far_kfunc_call()) { // THIS IS ALWAYS FALSE
	//		//        err = bpf_get_kfunc_addr(prog, insn->imm, insn->off, &addr);
	//		//        if (err)
	//		//            return err;
	//	} else {
	//		/* Address of a BPF helper call. Since part of the core
	//         * kernel, it's always at a fixed location. __bpf_call_base
	//         * and the helper with imm relative to it are both in core
	//         * kernel.
	//         *
	//         * WE DO NOT SUPPORT IT
	//         */
	//		//addr = (u8 *)__bpf_call_base + imm;
	//		addr = NULL;
	//		return -EINVAL;
	//	}

	*func_addr = (unsigned long)addr;
	return 0;
}