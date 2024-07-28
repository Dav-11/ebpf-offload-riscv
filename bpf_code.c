//
// Created by davide on 7/22/24.
//

#include "bpf_code.h"

inline bool is_jump_instruction(const struct bpf_insn *insn)
{
	__u8 const code = BPF_CLASS(insn->code);
	return (code == BPF_JMP);
}

inline bool is_helper_call(const struct bpf_insn *insn)
{
	/*
     * opcode:
     *   1000 0 101   src_reg = 0000 (0) -> call helper function by static ID
     *   1000 0 101   src_reg = 0010 (2) -> call helper function by BTF ID
     *   ---- - ---
     *   CALL K JMP
     */

	if (is_jump_instruction(insn) && BPF_OP(insn->code) == BPF_CALL &&
	    insn->src_reg != BPF_PSEUDO_CALL) {
		pr_err("Unsupported helper func jump instruction found");
		return true;
	}

	return false;
}

inline bool is_load_instruction(const struct bpf_insn *insn)
{
	return (BPF_CLASS(insn->code) == BPF_LD ||
		BPF_CLASS(insn->code) == BPF_LDX);
}

inline bool is_store_instruction(const struct bpf_insn *insn)
{
	return (BPF_CLASS(insn->code) == BPF_ST ||
		BPF_CLASS(insn->code) == BPF_STX);
}

inline bool is_atomic_store(const struct bpf_insn *insn)
{
	//  OP  S CLS
	// ---- - ---
	// 1100 0 000   BPF_ATOMIC
	// 0000 0 011   BPF_STX

	return (BPF_CLASS(insn->code) == BPF_STX &&
		BPF_OP(insn->code) == BPF_ATOMIC);
}

inline bool is_alu_instruction(const struct bpf_insn *insn)
{
	return (BPF_CLASS(insn->code) == BPF_ALU ||
		BPF_CLASS(insn->code) == BPF_ALU64);
}

inline bool is_pseudo_call(const struct bpf_insn *insn)
{
	return (is_jump_instruction(insn) && BPF_OP(insn->code) == BPF_CALL &&
		insn->src_reg == BPF_PSEUDO_CALL);
}

inline bool is_kfunc_call(const struct bpf_insn *insn)
{
	return (is_jump_instruction(insn) && BPF_OP(insn->code) == BPF_CALL &&
		insn->src_reg == BPF_PSEUDO_KFUNC_CALL);
}
