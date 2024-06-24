//
// Created by davide on 6/23/24.
//

#ifndef VERIFIER_H
#define VERIFIER_H

#include "rv_jit/jit.h"

typedef int (*verifier_t)(rvo_prog *, struct bpf_verifier_env *);


/***********************************
 * funcs
 **********************************/

rvo_insn_meta *rvo_get_insn_meta(const rvo_prog *prog, rvo_insn_meta *meta, const unsigned int insn_idx);

int rvo_insn_opcode_supported(u8 code);

// JUMP instructions
int is_jump_instruction(const rvo_insn_meta *meta);
int verify_jump_instruction(rvo_prog *prog, struct bpf_verifier_env *env);

// LOAD instructions
int is_load_instruction(const rvo_insn_meta *meta);
int verify_load_instruction(rvo_prog *prog, struct bpf_verifier_env *env);

// STORE instructions
int is_store_instruction(const rvo_insn_meta *meta);
int verify_store_instruction(rvo_prog *prog, struct bpf_verifier_env *env);

// ALU instructions
int is_alu_instruction(const rvo_insn_meta *meta);
int verify_alu_instruction(rvo_prog *prog, struct bpf_verifier_env *env);


/***********************************
 * MAP insn class -> verifier fn
 **********************************/

static const verifier_t verifier_map[8] = {
    [BPF_JMP] = verify_jump_instruction,
    [BPF_JMP32] = verify_jump_instruction,
    [BPF_LD] = verify_load_instruction,
    [BPF_LDX] = verify_load_instruction,
    [BPF_ST] = verify_store_instruction,
    [BPF_STX] = verify_store_instruction,
    [BPF_ALU] = verify_alu_instruction,
    [BPF_ALU64] = verify_alu_instruction,
};

#endif //VERIFIER_H
