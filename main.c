// SPDX-License-Identifier: MIT

#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>

static int __init ebpf_riscv_offload_init(void)
{
    pr_info("Loaded module\n");

    return 0;
}

static void __exit ebpf_riscv_offload_exit(void)
{
    pr_info("Removed module\n");
}

module_init(ebpf_riscv_offload_init);
module_exit(ebpf_riscv_offload_exit);