# Load offloaded BPF program
You first tell the kernel at load time that your program is supposed to be offloaded for a given device, so that the verifier can perform the additional checks accordingly. Concretely, this is done by setting:
- `bpf_attr.prog_flags` to `BPF_F_XDP_DEV_BOUND_ONLY`
- `bpf_attr.prog_ifindex` to the relevant interface index for the offload in the union  

passed to the syscall (and defined in the UAPI header include/uapi/linux/bpf.h). See also how bpftool handles it in tools/bpf/bpftool/prog.c (bpf_program__set_ifindex(pos, offload_ifindex);). The field prog->aux->offload_requested that you mention is set in kernel/bpf/offload.c based on whether the flag BPF_F_XDP_DEV_BOUND_ONLY was passed.

After the program has been loaded, you also need to request offload when you attach it to the interface. The exact procedure to attach the program depends of the hook (TC vs. XDP), but again, you can have a look at how bpftool does it, this time in tools/bpf/bpftool/net.c (if (attach_type == NET_ATTACH_TYPE_XDP_OFFLOAD) flags |= XDP_FLAGS_HW_MODE;).