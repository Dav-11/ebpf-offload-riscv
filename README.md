# ebpf-offload-riscv

## TODO
Here are the key steps to write a Linux kernel module (LKM) to offload eBPF program compilation:
1. Implement the `bpf_prog_offload_ops` structure with callback functions for translating and compiling eBPF programs. This includes:
   - `translate()`: Translate eBPF instructions to the target architecture
   - `compile()`: Compile translated instructions to binary
   - `destroy()`: Cleanup on module unload
2. Register a bpf_offload_dev struct using `bpf_offload_dev_register()`. This advertises your offload device to the kernel.
3. In the `translate()` callback, walk the eBPF instructions and convert them to the target architecture. For example, convert eBPF to RISC-V instructions.
4. In the `compile()` callback, take the translated instructions and compile them into a binary blob executable by your device.
5. Return the compiled binary blob length and pointer back to the kernel.
6. The kernel will call your `destroy()` callback on module unload to free resources.
7. Use `bpf_prog_offload_compile()` on eBPF programs to trigger offload to your device.

### Summary
The key steps are:
- Implement `bpf_prog_offload_ops` callbacks
- Register offload device
- Translate and compile eBPF instructions
- Return compiled binary to the kernel
- Handle cleanup on unload
