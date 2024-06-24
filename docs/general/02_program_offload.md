# Program code offload

## Flow
```mermaid
flowchart
    sys([BPF SYSCALL])
    sys_c(kernel/bpf/syscall.c)
    verifier_c(kernel/bpf/verifier.c)
    core_c(kernel/bpf/core.c)
    
    
    subgraph kernel/bpf/offload.c
        bpf_prog_offload_init("`bpf_prog_offload_init()
        ---
        allocate data structures for tracking offload device association`")

        bpf_prog_offload_verifier_prep("bpf_prog_offload_verifier_prep()")

        bpf_prog_offload_translate("bpf_prog_offload_translate()")
        bpf_prog_offload_destroy("bpf_prog_offload_destroy()")
    end
    
    subgraph driver

        BPF_OFFLOAD_VERIFIER_PREP("`BPF_OFFLOAD_VERIFIER_PREP
        ---
        allocate and construct driver-specific program data structures`")

        BPF_OFFLOAD_TRANSLATE("`BPF_OFFLOAD_TRANSLATE
        ---
        run optimizations and machine code generation`")

        BPF_OFFLOAD_DESTROY("`BPF_OFFLOAD_DESTROY
        ---
        free all data structures and machine code`")

        verify_insn("`verify_insn()
        ---
        perform extra dev-specific checks;
        gather context information`")
    end
    
    sys --> sys_c
    sys_c --> verifier_c
    sys_c --> bpf_prog_offload_init
    verifier_c --> bpf_prog_offload_verifier_prep
    bpf_prog_offload_verifier_prep -- "netdevice ops :: ndo_bpf()" --> BPF_OFFLOAD_VERIFIER_PREP
    verifier_c --> core_c
    verifier_c -- per-instruction verification callback --> verify_insn
    core_c --> bpf_prog_offload_translate
    bpf_prog_offload_translate -- "netdevice ops :: ndo_bpf()" --> BPF_OFFLOAD_TRANSLATE
    core_c --> bpf_prog_offload_destroy
    bpf_prog_offload_destroy -- "netdevice ops :: ndo_bpf()" --> BPF_OFFLOAD_DESTROY
    
```

## Interfaces
The driver has to implement two interfaces:

### bpf_prog_offload_ops

```C
static const struct bpf_prog_offload_ops rvo_offload_ops = {
	.insn_hook = rvo_isn_verify,
	.finalize = rvo_finalize,
	.replace_insn = rvo_replace_insn,
	.remove_insns = rvo_remove_insns,
	.prepare = rvo_prepare,
	.translate = rvo_translate,
	.destroy = rvo_destroy,
};
```

This struct handles the operations related to verification and translation.

### ndo_bpf
- Seems like this is a function that has to be registered by a device once it is loaded by the OS
- Do I need to have a netdev in order to be able to offload ?
- All the meta structs initializations are done here

## Verification
The main problems to exclude are from jumps:
- [kfunc](https://docs.kernel.org/bpf/kfuncs.html) jump -> kfunc addresses are pointers to host memory (which is not inside the accellerator)
- [bpf helper](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) jump -> these need to be implemented inside the accellerator to be used
  - TODO: understand how to eventually remap jumps to code inside the accelerator
- Tail jump: can a bpf function in the accelerator call a bpf function from the host kernel ?


