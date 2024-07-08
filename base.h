//
// Created by davide on 6/30/24.
//

#ifndef BASE_H
#define BASE_H

#include <linux/list.h>

/***********************************
 * structs
 **********************************/

/**
 * @param insn: BPF instruction
 * @param n: eBPF instruction number
 * @param l: link on rvo_prog->insns list
 */
typedef struct rvo_insn_meta {
    struct bpf_insn insn;
    unsigned short n;
    struct list_head l;
} rvo_insn_meta;

/**
 * @parm prog: pointer to machine code array
 * @param prog_len: number of valid instructions in @prog array
 * @param __prog_alloc_len: alloc size of @prog array
 * @param n_insns: number of instructions in the program
 */
typedef struct rvo_prog {
    u64 *prog;
    unsigned int prog_len;
    unsigned int __prog_alloc_len;

    rvo_insn_meta *verifier_meta;

    unsigned int n_insns;
    struct list_head insns;
} rvo_prog;


#endif //BASE_H
