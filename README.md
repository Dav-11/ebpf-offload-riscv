# ebpf-offload-riscv

This project aims at creating a Linux Kernel Module that is able to compile ebpf code for riscv from a machine that runs on any arch.

The idea is to use the ebpf offload capability to implement a variation of the already present riscv JIT compiler so that it can be run on arch that are not RISCV.


## TODO
Here are the key steps to write a Linux kernel module (LKM) to offload eBPF program compilation:
1. Implement the `bpf_prog_offload_ops` structure with callback functions for translating and compiling eBPF programs:
```C
struct bpf_prog_offload_ops {
	/* verifier basic callbacks */
	int (*insn_hook)(struct bpf_verifier_env *env, int insn_idx, int prev_insn_idx);
	int (*finalize)(struct bpf_verifier_env *env);
	/* verifier optimization callbacks (called after .finalize) */
	int (*replace_insn)(struct bpf_verifier_env *env, u32 off, struct bpf_insn *insn);
	int (*remove_insns)(struct bpf_verifier_env *env, u32 off, u32 cnt);
	/* program management callbacks */
	int (*prepare)(struct bpf_prog *prog);
	int (*translate)(struct bpf_prog *prog);
	void (*destroy)(struct bpf_prog *prog);
};
```
2. Create a `bpf_offload_dev` struct using `bpf_offload_dev_create()`. This advertises your offload device to the kernel.
```C
 struct bpf_offload_dev {
 	const struct bpf_prog_offload_ops *ops;
 	struct list_head netdevs;
 	void *priv;
 };

struct bpf_offload_dev *
bpf_offload_dev_create(const struct bpf_prog_offload_ops *ops, void *priv);
```
3. In the `translate()` callback, walk the eBPF instructions and convert them to the target architecture. For example, convert eBPF to RISC-V instructions.
4. The kernel will call your `destroy()` callback on module unload to free resources.
5. Use `bpf_prog_offload_compile()` on eBPF programs to trigger offload to your device.
```C
int bpf_prog_offload_compile(struct bpf_prog *prog);
```

### Summary
The key steps are:
- Implement `bpf_prog_offload_ops` callbacks
- Register offload device
- Translate and compile eBPF instructions
- Return compiled binary to the kernel
- Handle cleanup on unload
