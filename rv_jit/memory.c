

#include "memory.h"

static int init_arena(void)
{
	// initialize spinlock
	spin_lock_init(&rv_bpf_arena.lock);
	rv_bpf_arena.offset = 0;

	// allocate memory
	rv_bpf_arena.base = kmalloc(ARENA_SIZE, GFP_KERNEL);
	if (!rv_bpf_arena.base) {
		pr_err("Failed to allocate memory for rv_bpf_arena\n");
		return -ENOMEM;
	}

	printk(KERN_INFO "Arena initialized\n");
	return 0;
}

static void destroy_arena(void)
{
	kfree(rv_bpf_arena.base);
	pr_info("Arena deinitialized\n");
}

static void *alloc_arena(size_t size)
{
	void *ptr = NULL;
	unsigned long flags = 0;

	// acquire lock
	spin_lock_irqsave(&rv_bpf_arena.lock, flags);

	if (rv_bpf_arena.offset + size <= ARENA_SIZE) {
		ptr = rv_bpf_arena.base + rv_bpf_arena.offset;
		rv_bpf_arena.offset += size;
	} else {
		pr_err("Arena out of memory\n");
	}

	// release lock
	spin_unlock_irqrestore(&rv_bpf_arena.lock, flags);

	return ptr;
}

struct bpf_binary_header *
rv_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		    unsigned int alignment,
		    struct bpf_binary_header **rw_header, u8 **rw_image)
{
	struct bpf_binary_header *ro_header;
	u32 size, hole, start;

	// warn if the alignment is not a power of 2 or too large
	WARN_ON_ONCE(!is_power_of_2(alignment) ||
		     alignment > BPF_IMAGE_ALIGNMENT);

	// compute size of the binary to allocate
	size = proglen + sizeof(*ro_header);

	ro_header = alloc_arena(size);
	if (!ro_header) {
		return NULL;
	}

	// allocate a RW buffer to temporarilly store the code, it will be copied to the RO buffer by finalizer func
	*rw_header = kvmalloc(size, GFP_KERNEL);
	if (!*rw_header) {
		arena_free(size);
		return NULL;
	}

	// fill space with illegal/arch-dep instructions
	bpf_fill_ill_insns(*rw_header, size);
	(*rw_header)->size = size;

	*image_ptr = &ro_header->image[start];
	*rw_image = &(*rw_header)->image[start];

	return ro_header;
}

/* Copy JITed text from rw_header to its final location, the ro_header. */
int rv_jit_binary_pack_finalize(struct bpf_prog *prog,
				struct bpf_binary_header *ro_header,
				struct bpf_binary_header *rw_header)
{
	void *ptr;

	ptr = rv_patch_text_mem(ro_header, rw_header, rw_header->size);

	kvfree(rw_header);

	if (IS_ERR(ptr)) {
		arena_free(ro_header->size);
		return PTR_ERR(ptr);
	}

	return 0;
}

int rv_patch_text_mem(void *addr, const void *insns, size_t len)
{
	memcpy(addr, insns, len);

	return 0;
}

/**
  * Allocate jit binary from bpf_prog_pack allocator.
  * Since the allocated memory is RO+X, the JIT engine cannot write directly
  * to the memory. To solve this problem, a RW buffer is also allocated at
  * as the same time. The JIT engine should calculate offsets based on the
  * RO memory address, but write JITed program to the RW buffer. Once the
  * JIT engine finishes, it calls bpf_jit_binary_pack_finalize, which copies
  * the JITed program to the RO memory.
  *
  * @param proglen		length of the program
  * @param image_ptr		A pointer to store the address of the allocated read-only (RO) memory region.
  * @param alignment		alignment of the allocated memory
  * @param rw_header		A pointer to store the address of the allocated read-write (RW) header.
  * @param rw_image		A pointer to store the address of the allocated read-write (RW) memory region.
  * @param bpf_fill_ill_insns	A function pointer to fill the allocated memory with illegal instructions.
  */
// struct bpf_binary_header *my_bpf_jit_binary_pack_alloc(
// 	unsigned int proglen, u8 **image_ptr, unsigned int alignment,
// 	struct bpf_binary_header **rw_header, u8 **rw_image,
// 	bpf_jit_fill_hole_t bpf_fill_ill_insns)
// {
// 	struct bpf_binary_header *ro_header;
// 	u32 size, hole, start;
//
// 	WARN_ON_ONCE(!is_power_of_2(alignment) ||
// 		     alignment > BPF_IMAGE_ALIGNMENT);
//
// 	/* add 16 bytes for a random section of illegal instructions */
// 	size = round_up(proglen + sizeof(*ro_header) + 16, BPF_PROG_CHUNK_SIZE);
//
// 	if (bpf_jit_charge_modmem(size))
// 		return NULL;
// 	ro_header = bpf_prog_pack_alloc(size, bpf_fill_ill_insns);
// 	if (!ro_header) {
// 		bpf_jit_uncharge_modmem(size);
// 		return NULL;
// 	}
//
// 	*rw_header = kvmalloc(size, GFP_KERNEL);
// 	if (!*rw_header) {
// 		bpf_prog_pack_free(ro_header, size);
// 		bpf_jit_uncharge_modmem(size);
// 		return NULL;
// 	}
//
// 	/* Fill space with illegal/arch-dep instructions. */
// 	bpf_fill_ill_insns(*rw_header, size);
// 	(*rw_header)->size = size;
//
// 	hole = min_t(unsigned int, size - (proglen + sizeof(*ro_header)),
// 		     BPF_PROG_CHUNK_SIZE - sizeof(*ro_header));
// 	start = get_random_u32_below(hole) & ~(alignment - 1);
//
// 	*image_ptr = &ro_header->image[start];
// 	*rw_image = &(*rw_header)->image[start];
//
// 	return ro_header;
// }