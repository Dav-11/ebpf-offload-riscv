#ifndef EBPF_OFFLOAD_RISCV_ASM_H
#define EBPF_OFFLOAD_RISCV_ASM_H

// #include <linux/bitfield.h>
// #include <linux/memory.h>
#include <linux/bpf.h>
#include <linux/bitfield.h>

// # define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)

//
// __set_bit()
//

struct rv_pt_regs {
	unsigned long epc;
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	/* Supervisor/Machine CSRs */
	unsigned long status;
	unsigned long badaddr;
	unsigned long cause;
	/* a0 value before the syscall */
	unsigned long orig_a0;
};

/**
 * The purpose of this function is to modify the instructions at a given memory address (ip) with either a jump or a call instruction, depending on the poke_type argument.
 * TODO: update -> part of the JUMP logic
 * @param ip instruction pointer
 * @param poke_type enum('BPF_MOD_JUMP','BPF_MOD_CALL')
 * @param old_addr
 * @param new_addr
 * @return
 */
int rv_bpf_arch_text_poke(void *ip, enum bpf_text_poke_type poke_type, void *old_addr, void *new_addr);

#endif