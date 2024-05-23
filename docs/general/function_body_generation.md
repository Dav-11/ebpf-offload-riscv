# Code Generation (RV JIT)

The code generation is mainly handled by `bpf_int_jit_compile(struct bpf_prog *prog)` function and it is divided in four phases:
- **bpf_jit_blind_constants(struct bpf_prog *prog)**:
- **bpf_jit_build_prologue(struct rv_jit_context *ctx)**: allocates space on the stack and saves the content of the registers it will use.
- **bpf_jit_build_body(struct rv_jit_context *ctx)**: generates the code for the body of the function.
- **bpf_jit_build_epilogue(struct rv_jit_context *ctx)**: restores the content of the registers and returns.

## 