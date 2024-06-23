// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>

#include "offload_prog.h"

MODULE_AUTHOR("Davide Collovigh");
MODULE_DESCRIPTION("bpf_offload_dev");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

static struct bpf_offload_dev *dev;

static int __init ebpf_riscv_offload_init(void)
{
	pr_info("Loaded module\n");

	/*
	// init arena memory
	int err = init_arena();
	if (err) {
		pr_err("Could not init arena, exit");
		return err;
	}

 */
	// init device
	dev = NULL;
	dev = bpf_offload_dev_create(&rvo_offload_ops, NULL);



	pr_info("LOADED BPF OFFLOAD DEVICE");

	return 0;
}

static void __exit ebpf_riscv_offload_exit(void)
{
	bpf_offload_dev_destroy(dev);

	// destroy arena
	// destroy_arena();

	pr_info("Removed module\n");
}

module_init(ebpf_riscv_offload_init);
module_exit(ebpf_riscv_offload_exit);
