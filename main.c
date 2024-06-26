// SPDX-License-Identifier: MIT

#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <bpf/bpf_helpers.h>

static const struct bpf_prog_offload_ops my_offload_ops = {
    .insn_hook = my_insn_hook,
    .finalize = my_finalize,
    .replace_insn = my_replace_insn,
    .remove_insns = my_remove_insns,
    .prepare = my_prepare,
    .translate = my_translate,
    .destroy = my_destroy,
};

static const struct bpf_offload_dev *dev;

/**
 * This callback is invoked during BPF instruction verification.
 * It allows the offload device to inspect each BPF instruction during verification.
 *
 * @param env The verifier environment
 * @param insn_idx The index of the current instruction
 * @param prev_insn_idx The index of the previous instruction
 * @return
 */
int my_insn_hook(struct bpf_verifier_env *env, int insn_idx, int prev_insn_idx) {

    // TODO: implement
    return 0;
}

/**
 * This callback is invoked at the end of BPF program verification to allow finalization of the offload verification.
 *
 * @param env The verifier environment
 * @return
 */
int my_finalize(struct bpf_verifier_env *env) {

    // TODO: implement
    return 0;
}
/**
 * This callback replaces an instruction during BPF optimization.
 * @param env The verifier environment
 * @param off The offset of the instruction to replace
 * @param insn The new instruction
 * @return
 */
int my_replace_insn(struct bpf_verifier_env *env, u32 off, struct bpf_insn *insn) {

    //TODO: implement
    return 0;
}

/**
 * This callback removes instructions during BPF optimization.
 * @param env The verifier environment
 * @param off The offset of the first instruction to remove
 * @param cnt The number of instructions to remove
 * @return
 */
int my_remove_insns(struct bpf_verifier_env *env, u32 off, u32 cnt) {

    //TODO: implement
    return 0;
}

/**
 * This callback is invoked to prepare the BPF program for offloading.
 * @param prog
 * @return
 */
int my_prepare(struct bpf_prog *prog) {

    //TODO: implement
    return 0;
}

/**
 * This callback translates the BPF program into the offload device's native format.
 * @param prog
 * @return
 */
int my_translate(struct bpf_prog *prog) {

    //TODO: implement
    return 0;
}

/**
 * This callback is invoked to cleanup any resources allocated for offloading the BPF program.
 * @param prog
 */
void my_destroy(struct bpf_prog *prog) {

    //TODO: implement
    return 0;
}

static int __init ebpf_riscv_offload_init(void)
{
    pr_info("Loaded module\n");

    dev = NULL;
    int err;

    dev = bpf_offload_dev_create(&my_offload_ops, NULL);

    return 0;
}

static void __exit ebpf_riscv_offload_exit(void)
{
    bpf_offload_dev_destroy(dev);

    pr_info("Removed module\n");
}

module_init(ebpf_riscv_offload_init);
module_exit(ebpf_riscv_offload_exit);