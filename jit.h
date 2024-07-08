//
// Created by Davide Collovigh on 01/07/24.
//

#ifndef EBPF_OFFLOAD_RISCV_JIT_H
#define EBPF_OFFLOAD_RISCV_JIT_H

#include "base.h"
#include "codegen.h"

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

typedef struct rvo_jit_data {
	struct bpf_binary_header *header;
	struct bpf_binary_header *ro_header;
	u8 *image;
	u8 *ro_image;
	struct rv_jit_context ctx;
} rvo_jit_data;

typedef struct rvo_jit_context {
	struct bpf_prog *prog;
	u16 *insns; /* RV insns */
	u16 *ro_insns;
	int ninsns;
	int prologue_len;
	int epilogue_offset;
	int *offset; /* BPF to RV */
	int nexentries;
	unsigned long flags;
	int stack_size;
	u64 arena_vm_start;
	u64 user_vm_start;
} rvo_jit_context;

static int rvo_bpf_replace_map_ptrs(struct rvo_prog *prog);

#endif //EBPF_OFFLOAD_RISCV_JIT_H
