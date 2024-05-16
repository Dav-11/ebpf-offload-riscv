//
// Created by Davide Collovigh on 16/05/24.
//

#ifndef EBPF_OFFLOAD_RISCV_BPF_JIT_CORE_H
#define EBPF_OFFLOAD_RISCV_BPF_JIT_CORE_H

static int build_body(struct rv_jit_context *ctx, bool extra_pass, int *offset);

bool bpf_jit_needs_zext(void);

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog);

u64 bpf_jit_alloc_exec_limit(void);

void *bpf_jit_alloc_exec(unsigned long size);

void bpf_jit_free_exec(void *addr);

void *bpf_arch_text_copy(void *dst, void *src, size_t len);

int bpf_arch_text_invalidate(void *dst, size_t len);

void bpf_jit_free(struct bpf_prog *prog);

#endif //EBPF_OFFLOAD_RISCV_BPF_JIT_CORE_H
