

static int is_power_of_2(int x)
{
	return (x > 0) && ((x & (x - 1)) == 0);
}

static inline void rv_bpf_jit_dump(unsigned int flen, unsigned int proglen,
				   u32 pass, void *image)
{
	pr_err("flen=%u proglen=%u pass=%u image=%pK from=%s pid=%d\n", flen,
	       proglen, pass, image, current->comm, task_pid_nr(current));

	if (image)
		print_hex_dump(KERN_ERR, "JIT code: ", DUMP_PREFIX_OFFSET, 16,
			       1, image, proglen, false);
}
