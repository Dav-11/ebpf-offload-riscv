
#ifndef EBPF_OFFLOAD_RISCV_UTILS_H
#define EBPF_OFFLOAD_RISCV_UTILS_H

#include <linux/kernel.h> // for print_hex_dump()

static int is_power_of_2(int x);
static inline void rv_bpf_jit_dump(unsigned int flen, unsigned int proglen,
				   u32 pass, void *image);

#endif