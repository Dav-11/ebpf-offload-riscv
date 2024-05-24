# Prologue generation

> This docs is relative to the 64 bit version.

## Stack layout

```
(Higher addresses)

+---------------+
| RV_REG_S6     | <-- If RV_REG_S6 is used
+---------------+
| RV_REG_S5     | <-- If RV_REG_S5 is used
+---------------+
| RV_REG_S4     | <-- If RV_REG_S4 is used
+---------------+
| RV_REG_S3     | <-- If RV_REG_S3 is used
+---------------+
| RV_REG_S2     | <-- If RV_REG_S2 is used
+---------------+
| RV_REG_S1     | <-- If RV_REG_S1 is used
+---------------+
| RV_REG_FP     | <-- Frame pointer
+---------------+
| RV_REG_RA     | <-- Return address (if used)
+---------------+
|               |
|     ...       | <-- Space for BPF stack
|               |
+---------------+
| RV_REG_SP     | <-- Stack pointer
+---------------+

(Lower addresses)
```

## Function breakdown

1. Compute the stack depth required for the BPF program, rounded up to the nearest multiple of 16.
    ```C
    int i, stack_adjust = 0, store_offset, bpf_stack_adjust;

    // compute the stack depth required for the BPF program, rounded up to the nearest multiple of 16
    bpf_stack_adjust = round_up(ctx->prog->aux->stack_depth, 16);
    if (bpf_stack_adjust)
        mark_fp(ctx); // sets bit RV_CTX_F_SEEN_S5 of ctx->flags to 1
   ```
2. Compute the stack depth required for the BPF program by adding 8 for each reg used, rounded up to the nearest
   multiple of 16.
    ```C
    // compute the stack depth required for the BPF program by adding 8 for each reg used, rounded up to the nearest multiple of 16
    if (seen_reg(RV_REG_RA, ctx))
        stack_adjust += 8;
   
    stack_adjust += 8; /* RV_REG_FP */
   
    if (seen_reg(RV_REG_S1, ctx))
        stack_adjust += 8;
   
    if (seen_reg(RV_REG_S2, ctx))
        stack_adjust += 8;
   
    if (seen_reg(RV_REG_S3, ctx))
        stack_adjust += 8;
   
    if (seen_reg(RV_REG_S4, ctx))
        stack_adjust += 8;
   
    if (seen_reg(RV_REG_S5, ctx))
        stack_adjust += 8;
   
    if (seen_reg(RV_REG_S6, ctx))
        stack_adjust += 8;

    stack_adjust = round_up(stack_adjust, 16); // round to 16
    stack_adjust += bpf_stack_adjust;

    store_offset = stack_adjust - 8;
    ```
3. Add NOPS instructions at the start of the frame.
    ```C
    /* nops reserved for auipc+jalr pair */
    for (i = 0; i < RV_FENTRY_NINSNS; i++)
        emit(rv_nop(), ctx);
    ```
4. If function is not a tail call, then emit instr to initialize the tail-call-counter (TCC) register.
    ```C
    emit(rv_addi(RV_REG_TCC, RV_REG_ZERO, MAX_TAIL_CALL_CNT), ctx); // addi REG_TCC, REG_0,  MAX_TAIL_CALL_CNT
    ```
5. Emit instruction to push the stack
    ```C
    emit_addi(RV_REG_SP, RV_REG_SP, -stack_adjust, ctx); // addi REG_SP, REG_SP, -(stack_adjust)
    ```
6. For each of the callee-saved registers, if used pushes the value on the stack.
    ```C
    if (seen_reg(RV_REG_RA, ctx)) {
        emit_sd(RV_REG_SP, store_offset, RV_REG_RA, ctx);
        store_offset -= 8;
    }
    
    emit_sd(RV_REG_SP, store_offset, RV_REG_FP, ctx); // *(REG_FP + store_offset) = *REG_SP, 
    store_offset -= 8;
    
    if (seen_reg(RV_REG_S1, ctx)) {
        emit_sd(RV_REG_SP, store_offset, RV_REG_S1, ctx);
        store_offset -= 8;
    }
    
    if (seen_reg(RV_REG_S2, ctx)) {
        emit_sd(RV_REG_SP, store_offset, RV_REG_S2, ctx);
        store_offset -= 8;
    }
    
    if (seen_reg(RV_REG_S3, ctx)) {
        emit_sd(RV_REG_SP, store_offset, RV_REG_S3, ctx);
        store_offset -= 8;
    }
    
    if (seen_reg(RV_REG_S4, ctx)) {
        emit_sd(RV_REG_SP, store_offset, RV_REG_S4, ctx);
        store_offset -= 8;
    }
    
    if (seen_reg(RV_REG_S5, ctx)) {
        emit_sd(RV_REG_SP, store_offset, RV_REG_S5, ctx);
        store_offset -= 8;
    }
    
    if (seen_reg(RV_REG_S6, ctx)) {
        emit_sd(RV_REG_SP, store_offset, RV_REG_S6, ctx);
        store_offset -= 8;
    }
    ```

7. Updates the frame pointer.
    ```C
    emit_addi(
        RV_REG_FP, RV_REG_SP, stack_adjust,
        ctx); // RV_REG_FP = RV_REG_SP + stack_adjust => points to highest address considering registries saves
    ```
8. `RV_REG_S5` = `RV_REG_SP` + `bpf_stack_adjust` => points to highest address of BPF vars. (???)
    ```C
    if (bpf_stack_adjust)
        emit_addi(
            RV_REG_S5, RV_REG_SP, bpf_stack_adjust,
            ctx); // RV_REG_S5 = RV_REG_SP + bpf_stack_adjust => points to highest address of BPF vars
    ```
9. If the program contains calls and tail calls, `RV_REG_TCC` need to be saved across calls.
    ```C
    /* Program contains calls and tail calls, so RV_REG_TCC need
     * to be saved across calls.
     */
    if (seen_tail_call(ctx) && seen_call(ctx))
        emit_mv(RV_REG_TCC_SAVED, RV_REG_TCC, ctx);
    ```
10. Save the computed stack size.
    ```C
    ctx->stack_size = stack_adjust;
    ```
