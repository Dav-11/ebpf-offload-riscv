//
// Created by Davide Collovigh on 01/07/24.
//

#ifndef EBPF_OFFLOAD_RISCV_JIT_H
#define EBPF_OFFLOAD_RISCV_JIT_H

#include "base.h"
#include "codegen.h"
#include "rv_insn.h"

#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/stddef.h> // NULL

#define RVO_PROG_MAX_LEN 255
#define NR_JIT_ITERATIONS 5

#define BPF_PROG_CHUNK_SHIFT	6
#define BPF_PROG_CHUNK_SIZE	(1 << BPF_PROG_CHUNK_SHIFT)

int rvo_bpf_replace_map_ptrs(struct rvo_prog *prog);

#endif //EBPF_OFFLOAD_RISCV_JIT_H
