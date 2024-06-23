//
// Created by davide on 6/22/24.
//

#ifndef MAIN_H
#define MAIN_H

#include "rv_jit/verifier.h"

/***********************************
 * funcs
 **********************************/

/**
 * This callback is invoked during BPF instruction verification.
 * It allows the offload device to inspect each BPF instruction during
 * verification.
 *
 * @param env The verifier environment
 * @param insn_idx The index of the current instruction
 * @param prev_insn_idx The index of the previous instruction
 * @return
 */
int rvo_isn_verify(struct bpf_verifier_env *env, int insn_idx,
		   int prev_insn_idx);

/**
 * This callback is invoked at the end of BPF program verification to allow
 * finalization of the offload verification.
 *
 * @param env The verifier environment
 * @return
 */
int rvo_finalize(struct bpf_verifier_env *env);

/**
 * This callback replaces an instruction during BPF optimization.
 * @param env The verifier environment
 * @param off The offset of the instruction to replace
 * @param insn The new instruction
 * @return
 */
int rvo_replace_insn(struct bpf_verifier_env *env, u32 off,
		     struct bpf_insn *insn);

/**
 * This callback removes instructions during BPF optimization.
 * @param env The verifier environment
 * @param off The offset of the first instruction to remove
 * @param cnt The number of instructions to remove
 * @return
 */
int rvo_remove_insns(struct bpf_verifier_env *env, u32 off, u32 cnt);

/**
 * This callback is invoked to prepare the BPF program for offloading.
 * @param prog
 * @return
 */
int rvo_prepare(struct bpf_prog *prog);

/**
 * This callback translates the BPF program into the offload device's native
 * format.
 * @param prog
 * @return
 */
int rvo_translate(struct bpf_prog *prog);

/**
 * This callback is invoked to cleanup any resources allocated for offloading
 * the BPF program.
 * @param prog
 */
void rvo_destroy(struct bpf_prog *prog);

/***********************************
 * struct
 **********************************/

static const struct bpf_prog_offload_ops rvo_offload_ops = {
	.insn_hook = rvo_isn_verify,
	.finalize = rvo_finalize,
	.replace_insn = rvo_replace_insn,
	.remove_insns = rvo_remove_insns,
	.prepare = rvo_prepare,
	.translate = rvo_translate,
	.destroy = rvo_destroy,
};

#endif //MAIN_H
