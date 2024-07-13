//
// Created by Davide Collovigh on 01/07/24.
//

#ifndef EBPF_OFFLOAD_RISCV_JIT_H
#define EBPF_OFFLOAD_RISCV_JIT_H

#include "base.h"
#include "codegen.h"

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

#define RVO_PROG_MAX_LEN 255

//typedef struct rvo_jit_data {
//	struct bpf_binary_header *header;
//	struct bpf_binary_header *ro_header;
//	u8 *image;
//	u8 *ro_image;
//	struct rvo_jit_context ctx;
//} rvo_jit_data;

static int rvo_bpf_replace_map_ptrs(struct rvo_prog *prog);

#endif //EBPF_OFFLOAD_RISCV_JIT_H
