//
// Created by Davide Collovigh on 10/07/24.
//

#include "prepare.h"

void gen_meta_jump(rvo_prog *prog)
{
	rvo_insn_meta *curr_meta;

	list_for_each_entry(curr_meta, &prog->insn_meta, l) {
		insn = curr_meta->insn rvo_insn_meta * dst_meta;

		if (is_jump_instruction(curr_meta->insn)) {
			if (BPF_OP(insn.code) == BPF_EXIT) {
				return;
			}

			if (is_helper_call(insn)) {
				return;
			}

			/*
			 * If opcode is BPF_CALL at this point, this can only be a
			 * BPF-to-BPF call (a.k.a pseudo call).
			 */
			bool pseudo_call = BPF_OP(insn.code) == BPF_CALL;
			unsigned int dst_idx;

			if (pseudo_call)
				dst_idx = meta->n + 1 + meta->insn.imm;
			else
				dst_idx = meta->n + 1 + meta->insn.off;

			dst_meta = nfp_bpf_goto_meta(nfp_prog, meta, dst_idx);

			if (pseudo_call)
				dst_meta->flags |= FLAG_INSN_IS_SUBPROG_START;

			dst_meta->flags |= FLAG_INSN_IS_JUMP_DST;
			meta->jmp_dst = dst_meta;
		}
	}
}

int create_meta_for_insns(rvo_prog *my_prog, const struct bpf_insn *insns,
			  unsigned int cnt)
{
	rvo_insn_meta *meta;

	for (unsigned int i = 0; i < ; i++) {
		meta = kzalloc(sizeof(*meta), GFP_KERNEL);
		if (!meta)
			return -ENOMEM;

		meta->insn = insns[i];
		meta->n = i;

		/** ADD HERE meta generation if can be done before first loop **/

		list_add_tail(&meta->l, &my_prog->insns_meta);
	}

	my_prog->ninsns = insns->len;

	/** meta gen after first loop **/

	gen_meta_jump(my_prog);
}

int rvo_prepare(struct bpf_prog *prog)
{
	rvo_prog *my_prog;
	int ret;

	// allocate struct
	prog = kzalloc(sizeof(*my_prog), GFP_KERNEL);
	if (!prog)
		return -ENOMEM;

	prog->aux->offload->dev_priv = my_prog;

	INIT_LIST_HEAD(&my_prog->insn_meta);

	my_prog->type = prog->type;

	// TODO: [nfp_app_bpf] understand
	my_prog->bpf = bpf_offload_dev_priv(prog->aux->offload->offdev);

	ret = create_meta_for_insns(my_prog, prog->insnsi, prog->len);
	if (ret)
		goto err_free;

	// TODO: implement
	return 0;

err_free:

	//TODO: free list

	return ret;
}
