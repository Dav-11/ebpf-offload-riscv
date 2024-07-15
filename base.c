//
// Created by Davide Collovigh on 09/07/24.
//
#include "base.h"

rvo_insn_meta *get_meta_first_instruction(rvo_prog *prog)
{
	return list_first_entry(&(prog)->insn_meta, rvo_insn_meta, l);
}
rvo_insn_meta *get_meta_last_instruction(rvo_prog *prog)
{
	return list_last_entry(&(prog)->insn_meta, rvo_insn_meta, l);
}
rvo_insn_meta *get_meta_next_instruction(rvo_insn_meta *meta)
{
	return list_next_entry(meta, l);
}
rvo_insn_meta *get_meta_prev_instruction(rvo_insn_meta *meta)
{
	return list_prev_entry(meta, l);
}
rvo_insn_meta *rvo_get_insn_meta(const rvo_prog *prog, rvo_insn_meta *curr_meta,
				 const unsigned int insn_idx)
{
	unsigned int i;
	unsigned int n_bpf_insns = prog->bpf_ninsns;

	// calculate the distance (in terms of instructions) between the current instruction and the target instruction
	// both in the forward and backward directions.
	unsigned int backward = curr_meta->n - insn_idx;
	unsigned int forward = insn_idx - curr_meta->n;

	// number of instructions remaining in the program from the current position
	const unsigned int remaining = n_bpf_insns - insn_idx - 1;

	if (min(forward, backward) > remaining) {
		// the target instruction is beyond the end of the program
		backward = n_bpf_insns - insn_idx - 1;
		curr_meta = get_meta_last_instruction(prog);
	}

	if (min(forward, backward) > insn_idx && backward > insn_idx) {
		// the target instruction is before the start of the program
		forward = insn_idx;
		curr_meta = get_meta_first_instruction(prog);
	}

	if (forward < backward) {
		// Iterate forward times using get_meta_next_instruction(meta) to move to the target instruction metadata.
		for (i = 0; i < forward; i++) {
			curr_meta = get_meta_next_instruction(curr_meta);
		}
	} else {
		// Iterate backward times using get_meta_prev_instruction(meta) to move to the target instruction metadata.
		for (i = 0; i < backward; i++) {
			curr_meta = get_meta_prev_instruction(curr_meta);
		}
	}

	return curr_meta;
}
