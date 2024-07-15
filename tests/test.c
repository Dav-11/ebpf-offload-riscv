// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/filter.h>

MODULE_AUTHOR("Davide Collovigh");
MODULE_DESCRIPTION("test");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

enum {
	RV_REG_ZERO = 0, /* The constant value 0 */
	RV_REG_RA = 1, /* Return address */
	RV_REG_SP = 2, /* Stack pointer */
	RV_REG_GP = 3, /* Global pointer */
	RV_REG_TP = 4, /* Thread pointer */
	RV_REG_T0 = 5, /* Temporaries */
	RV_REG_T1 = 6,
	RV_REG_T2 = 7,
	RV_REG_FP = 8, /* Saved register/frame pointer */
	RV_REG_S1 = 9, /* Saved register */
	RV_REG_A0 = 10, /* Function argument/return values */
	RV_REG_A1 = 11, /* Function arguments */
	RV_REG_A2 = 12,
	RV_REG_A3 = 13,
	RV_REG_A4 = 14,
	RV_REG_A5 = 15,
	RV_REG_A6 = 16,
	RV_REG_A7 = 17,
	RV_REG_S2 = 18, /* Saved registers */
	RV_REG_S3 = 19,
	RV_REG_S4 = 20,
	RV_REG_S5 = 21,
	RV_REG_S6 = 22,
	RV_REG_S7 = 23,
	RV_REG_S8 = 24,
	RV_REG_S9 = 25,
	RV_REG_S10 = 26,
	RV_REG_S11 = 27,
	RV_REG_T3 = 28, /* Temporaries */
	RV_REG_T4 = 29,
	RV_REG_T5 = 30,
	RV_REG_T6 = 31,
};

enum {
	RV_CTX_F_SEEN_TAIL_CALL =	0,
	RV_CTX_F_SEEN_CALL =		RV_REG_RA,
	RV_CTX_F_SEEN_S1 =		RV_REG_S1,
	RV_CTX_F_SEEN_S2 =		RV_REG_S2,
	RV_CTX_F_SEEN_S3 =		RV_REG_S3,
	RV_CTX_F_SEEN_S4 =		RV_REG_S4,
	RV_CTX_F_SEEN_S5 =		RV_REG_S5,
	RV_CTX_F_SEEN_S6 =		RV_REG_S6,
};

static const int regmap[] = {
	[BPF_REG_0] = RV_REG_A5,  [BPF_REG_1] = RV_REG_A0,
	[BPF_REG_2] = RV_REG_A1,  [BPF_REG_3] = RV_REG_A2,
	[BPF_REG_4] = RV_REG_A3,  [BPF_REG_5] = RV_REG_A4,
	[BPF_REG_6] = RV_REG_S1,  [BPF_REG_7] = RV_REG_S2,
	[BPF_REG_8] = RV_REG_S3,  [BPF_REG_9] = RV_REG_S4,
	[BPF_REG_FP] = RV_REG_S5, [BPF_REG_AX] = RV_REG_T0,
};

static u8 bpf_to_rv_reg(int bpf_reg, unsigned long *flags)
{
	u8 reg = regmap[bpf_reg];

	switch (reg) {
	case RV_CTX_F_SEEN_S1:
	case RV_CTX_F_SEEN_S2:
	case RV_CTX_F_SEEN_S3:
	case RV_CTX_F_SEEN_S4:
	case RV_CTX_F_SEEN_S5:
	case RV_CTX_F_SEEN_S6:
		__set_bit(reg, flags);
	}

	return reg;
}

static bool seen_reg(int reg, unsigned long *flags)
{
	switch (reg) {
	case RV_CTX_F_SEEN_CALL:
	case RV_CTX_F_SEEN_S1:
	case RV_CTX_F_SEEN_S2:
	case RV_CTX_F_SEEN_S3:
	case RV_CTX_F_SEEN_S4:
	case RV_CTX_F_SEEN_S5:
	case RV_CTX_F_SEEN_S6:
		return test_bit(reg, flags);
	}
	return false;
}

void print_long_as_binary(long num) {
	int i;
	for (i = sizeof(long) * 8 - 1; i >= 0; i--) {
		printk(KERN_CONT "%c", (num & (1L << i)) ? '1' : '0');
	}
	printk(KERN_CONT "\n");
}

static int __init test_init(void)
{
	pr_info("Loaded module\n");

	unsigned long flags = 0;
	u8 rv_reg = 0;
	bool res = false;

	rv_reg = bpf_to_rv_reg(BPF_REG_6, &flags);
	pr_info("[%3u] -> [%3u]; flags: ", BPF_REG_6, rv_reg);
	print_long_as_binary(flags);

	rv_reg = bpf_to_rv_reg(BPF_REG_7, &flags);
	pr_info("[%3u] -> [%3u]; flags: ", BPF_REG_7, rv_reg);
	print_long_as_binary(flags);

	rv_reg = bpf_to_rv_reg(BPF_REG_8, &flags);
	pr_info("[%3u] -> [%3u]; flags: ", BPF_REG_8, rv_reg);
	print_long_as_binary(flags);

	rv_reg = bpf_to_rv_reg(BPF_REG_9, &flags);
	pr_info("[%3u] -> [%3u]; flags: ", BPF_REG_9, rv_reg);
	print_long_as_binary(flags);

	rv_reg = bpf_to_rv_reg(BPF_REG_FP, &flags);
	pr_info("[%3u] -> [%3u]; flags: ", BPF_REG_FP, rv_reg);
	print_long_as_binary(flags);

	res = seen_reg(RV_CTX_F_SEEN_S1, &flags);
	pr_info("[RV_CTX_F_SEEN_S1] -> [%u]", res);

	res = seen_reg(RV_CTX_F_SEEN_S2, &flags);
	pr_info("[RV_CTX_F_SEEN_S2] -> [%u]", res);

	res = seen_reg(RV_CTX_F_SEEN_S3, &flags);
	pr_info("[RV_CTX_F_SEEN_S3] -> [%u]", res);

	res = seen_reg(RV_CTX_F_SEEN_S4, &flags);
	pr_info("[RV_CTX_F_SEEN_S4] -> [%u]", res);

	res = seen_reg(RV_CTX_F_SEEN_S5, &flags);
	pr_info("[RV_CTX_F_SEEN_S5] -> [%u]", res);

	res = seen_reg(RV_CTX_F_SEEN_S6, &flags);
	pr_info("[RV_CTX_F_SEEN_S6] -> [%u]", res);

	return 0;
}

static void __exit test_exit(void)
{
	pr_info("Removed module\n");
}

module_init(test_init);
module_exit(test_exit);