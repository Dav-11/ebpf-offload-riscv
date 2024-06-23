//
// Created by davide on 6/23/24.
//

#include "verifier.h"

int is_last_instruction(rvo_insn_meta *meta, unsigned int insn_idx) {

    // TODO: implement
    return 0;
}

int is_first_instruction(rvo_insn_meta *meta, unsigned int insn_idx) {

    // TODO: implement
    return 0;
}

int does_verifier_scan_backward(rvo_insn_meta *meta, unsigned int insn_idx) {

    // TODO: implement
    return 0;
}

rvo_insn_meta *get_meta_first_instruction(rvo_prog *prog) {

    //TODO: implement
    return prog->verifier_meta;
}

rvo_insn_meta *get_meta_last_instruction(rvo_prog *prog) {

    //TODO: implement
    return prog->verifier_meta;
}

rvo_insn_meta *get_meta_next_instruction(rvo_insn_meta *meta) {

    //TODO: implement
    return meta;
}

rvo_insn_meta *get_meta_prev_instruction(rvo_insn_meta *meta) {

    //TODO: implement
    return meta;
}

rvo_insn_meta * rvo_get_insn_meta(rvo_prog *prog, rvo_insn_meta *meta, unsigned int insn_idx) {

    unsigned int i;
    unsigned int backward = meta->n - insn_idx;
    unsigned int forward = insn_idx - meta->n;

    if (is_last_instruction(meta, insn_idx)) {
        backward = prog->n_insns - insn_idx - 1;
        meta = get_meta_last_instruction(prog);
    }
    if (is_first_instruction(meta, insn_idx)) {
        forward = insn_idx;
        meta = get_meta_first_instruction(prog);
    }

    if (forward < backward)
        for (i = 0; i < forward; i++)
            meta = get_meta_next_instruction(meta);
    else
        for (i = 0; i < backward; i++)
            meta = get_meta_prev_instruction(meta);

    return meta;
}

int rvo_insn_opcode_supported(const u8 code) {

    return (int) !!instr_cb[code];
}

int is_jump_instruction(const rvo_insn_meta *meta) {

    const struct bpf_insn insn = meta->insn;

    return BPF_CLASS(insn.code) == BPF_JMP;
}

int __always_inline is_kfunc_call(const struct bpf_insn insn) {

    if (BPF_OP(insn.code) == BPF_CALL && insn.src_reg != BPF_PSEUDO_KFUNC_CALL) {

        pr_err("Unsupported kfunc instruction found");
        return 1;
    }

    return 0;
}

int __always_inline is_helper_call(const struct bpf_insn insn) {

    // TODO: implement

    return 0;
}

int check_exit_call(rvo_prog *prog,
           struct bpf_verifier_env *env) {

    // TODO: implement
    return 1;
}

int verify_jump_instruction(rvo_prog *prog, struct bpf_verifier_env *env) {

    const rvo_insn_meta *meta = prog->verifier_meta;
    const struct bpf_insn insn = meta->insn;

    if (BPF_OP(insn.code) == BPF_CALL) {

        return  (!is_kfunc_call(insn) && !is_helper_call(insn));
    } else if (BPF_OP(insn.code) == BPF_EXIT) {

        return check_exit_call(prog, env);
    }

    return  1;
}

int is_load_instruction(const rvo_insn_meta *meta) {

    return (BPF_CLASS(meta->insn.code) == BPF_LD || BPF_CLASS(meta->insn.code) == BPF_LDX);
}

int verify_load_instruction(rvo_prog *prog, struct bpf_verifier_env *env) {

    // TODO: implement
    return 1;
}

int is_atomic_store(const rvo_insn_meta *meta) {

    //  OP  S CLS
    // ---- - ---
    // 1100 0 000   BPF_ATOMIC
    // 0000 0 011   BPF_STX

    return (BPF_CLASS(meta->insn.code) == BPF_STX && BPF_OP(meta->insn.code) == BPF_ATOMIC);
}

int is_store_instruction(const rvo_insn_meta *meta) {

    return (BPF_CLASS(meta->insn.code) == BPF_ST || BPF_CLASS(meta->insn.code) == BPF_STX);
}

int verify_store_instruction(rvo_prog *prog, struct bpf_verifier_env *env) {

    // TODO: implement
    return 1;
}

int is_alu_instruction(const rvo_insn_meta *meta) {

    return (BPF_CLASS(meta->insn.code) == BPF_ALU || BPF_CLASS(meta->insn.code) == BPF_ALU64);
}

int verify_alu_instruction(rvo_prog *prog, struct bpf_verifier_env *env) {

    // TODO: implement
    return 1;
}
