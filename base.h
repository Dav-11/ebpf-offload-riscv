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

/**
 * @struct rvo_insn_meta
 * @brief  Metadata structure for BPF instructions.
 *
 * @var rvo_insn_meta::insn
 * BPF instruction
 *
 * @var rvo_insn_meta::n
 * BPF instruction number
 *
 * @var rvo_insn_meta::l
 * link on rvo_prog->insn_meta list
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
 * @var rvo_prog::prog
 * Pointer to machine code array
 *
 * @var rvo_prog::__prog_alloc_len
 * Size of the space necessary to allocate the program in memory
 *
 * @var rvo_prog::ninsns
 * Number of instructions in the program
 *
 * @var rvo_prog::insn_meta
 * list of struct rvo_insn_meta to hold meta info for the instructions
 *
 * @var rvo_prog::stack_size
 * Total amount of stack used
 *
 * @var rvo_prog::type
 * BPF program type
 *
 * @var rvo_prog::ctx
 * Pointer to struct rvo_jit_context
 *
 * @var rvo_prog::bpf
 * Pointer to device structure
 */
typedef struct rvo_prog {
	struct bpf_prog *prog;
	u16 *insns; /* RV insns */

	unsigned int ninsns;
	unsigned int __prog_alloc_len;

	int prologue_len;
	int epilogue_offset;

	struct list_head insn_meta;
	rvo_jit_context *ctx;

	//struct list_head insns;

	unsigned int stack_size;

	enum bpf_prog_type type;

	void *bpf; // TODO: [nfp_app_bpf] understand what it has to be used for

} rvo_prog;

/**
 * @struct rvo_jit_context
 * @brief holds data necessary to the jit process
 */
typedef struct rvo_jit_context {
	int *offset; /* BPF to RV */
	int nexentries;
	unsigned long flags;
	u64 arena_vm_start;
	u64 user_vm_start;
} rvo_jit_context;

#endif //BASE_H
