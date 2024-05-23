
#ifndef _BPF_RV_MEM_H
#define _BPF_RV_MEM_H

#include <linux/slab.h>
#include <linux/spinlock.h>

/*
 * BPF program pack allocator.
 *
 * Most BPF programs are pretty small. Allocating a hole page for each
 * program is sometime a waste. Many small bpf program also adds pressure
 * to instruction TLB. To solve this issue, we introduce a BPF program pack
 * allocator. The prog_pack allocator uses HPAGE_PMD_SIZE page (2MB on x86)
 * to host BPF programs.
 */
#define BPF_PROG_CHUNK_SHIFT 6
#define BPF_PROG_CHUNK_SIZE (1 << BPF_PROG_CHUNK_SHIFT)
#define BPF_PROG_CHUNK_MASK (~(BPF_PROG_CHUNK_SIZE - 1))

/* TODO: implement thread-safe version of this allocator to enable multiple programs
 * to be compiled and loaded at the same time.
 * - add a page-like structure to allow the space to be allocated and freed out of order
 * - add defragment logic to recover space
*/

/* Some arches need doubleword alignment for their instructions and/or data */
#define BPF_IMAGE_ALIGNMENT 8

#define ARENA_SIZE \
	(1 * 1024 * 1024) // Define the size of the arena (2^20B=1MiB)

// Entry of the array to place inside the arena to keep track of used space for thread safe version
struct arena_entry {
	unsigned char *base;
	size_t size;
	spinlock_t lock;
}

/**
 * The memory arena is a simple memory allocator.
*/
struct memory_arena {
	unsigned char *base;
	size_t offset;
	spinlock_t lock;
}

static struct memory_arena rv_bpf_arena;

// Arena mgmt funcs
static int init_arena(void);
static void destroy_arena(void);
static void *alloc_arena(size_t size);
static void *free_arena(size_t size);

// BPF program pack funcs
struct bpf_binary_header *
rv_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		    unsigned int alignment,
		    struct bpf_binary_header **rw_header, u8 **rw_image);

int rv_jit_binary_pack_finalize(struct bpf_prog *prog,
				 struct bpf_binary_header *ro_header,
				 struct bpf_binary_header *rw_header);

#endif /* _BPF_RV_MEM_H */