//
// Created by davide on 7/22/24.
//

#ifndef EBPF_OFFLOAD_RISCV_BPF_CODE_H
#define EBPF_OFFLOAD_RISCV_BPF_CODE_H

#include "base.h"
#include <linux/bpf.h>

inline bool is_jump_instruction(const struct bpf_insn *insn);
inline bool is_load_instruction(const struct bpf_insn *insn);
inline bool is_store_instruction(const struct bpf_insn *insn);
inline bool is_alu_instruction(const struct bpf_insn *insn);

/**
 * Checks if the function is NOT a BPF to BPF (pseudo) CALL
 * @param insn the instruction to check
 * @return 1 if the instruction is a call to ext functions
 */
inline bool is_helper_call(const struct bpf_insn *insn);
inline bool is_pseudo_call(const struct bpf_insn *insn);
inline bool is_kfunc_call(const struct bpf_insn *insn);
inline bool is_atomic_store(const struct bpf_insn *insn);

#endif //EBPF_OFFLOAD_RISCV_BPF_CODE_H

//