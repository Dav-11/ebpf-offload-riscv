//
// Created by davide on 6/30/24.
//

#ifndef BASE_H
#define BASE_H

#include <linux/list.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

/***********************************
 * meta flags
 **********************************/

#define FLAG_INSN_IS_JUMP_DST BIT(0)
#define FLAG_INSN_IS_SUBPROG_START BIT(1)

/***********************************
 * structs
 **********************************/

typedef struct rv_jit_data {
	struct bpf_binary_header *header;
	//struct bpf_binary_header *ro_header;
	u8 *image;
	//u8 *ro_image;
} rv_jit_data;

/**
 * @struct rvo_insn_meta
 * @brief  Metadata structure for BPF instructions.
 *
 * @var insn
 * BPF instruction
 *
 * @var n
 * BPF instruction number
 *
 * @var l
 * link on rvo_prog->insn_meta list
 *
 * @var flags
 * bits for information about the instruction
 *
 * @var jmp_dst
 * pointer to jump destination instruction's meta (only for jump instructions)
 */
typedef struct rvo_insn_meta {
	struct bpf_insn insn;
	unsigned short n;
	struct list_head l;
	unsigned short flags;

	/** FOR JUMP insn **/
	struct rvo_insn_meta *jmp_dst;

} rvo_insn_meta;

/**
 * @struct rvo_prog
 * @brief struct to hold all the program offload variables
 *
 * @var prog:
 * Pointer to machine code array
 *
 * @var __prog_alloc_len:
 * Size of the space necessary to allocate the program in memory
 *
 * @var bpf_ninsns:
 * Number of instructions in the program in bpf asm code
 *
 * @var ninsns:
 * Number of instructions in the program in riscv asm code
 *
 * @var insn_meta:
 * list of struct rvo_insn_meta to hold meta info for the instructions
 *
 * @var curr_meta:
 * pointer to an entry from insn_meta
 *
 * @var stack_size:
 * Total amount of stack used
 *
 * @var type:
 * BPF program type
 *
 * @var ctx:
 * Pointer to struct rvo_jit_context
 *
 * @var bpf:
 * Pointer to device structure
 */
typedef struct rvo_prog {
	struct bpf_prog *prog;
	enum bpf_prog_type type;

	// meta
	unsigned int bpf_ninsns;
	struct list_head insn_meta;
	rvo_insn_meta *curr_meta;

	// jit
	unsigned int ninsns;
	unsigned int __prog_alloc_len;
	unsigned long used_regs;
	rv_jit_data *jit_data;

	u16 *insns; /* RV insns */
	int *offset;

	int nexentries;

	unsigned int stack_size;
	int prologue_len;
	int epilogue_offset;

	void *bpf; // TODO: [nfp_app_bpf] understand what it has to be used for

} rvo_prog;

rvo_insn_meta *get_meta_first_instruction(rvo_prog *prog);
rvo_insn_meta *get_meta_last_instruction(rvo_prog *prog);
rvo_insn_meta *get_meta_next_instruction(rvo_insn_meta *meta);
rvo_insn_meta *get_meta_prev_instruction(rvo_insn_meta *meta);
rvo_insn_meta *rvo_get_insn_meta(const rvo_prog *prog, rvo_insn_meta *meta,
				 const unsigned int insn_idx);

#endif //BASE_H
