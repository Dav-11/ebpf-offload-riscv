# Memory

## Registers
- 11 64 bit registers (r0 - r10)
  - 32 bit subregisters
    - Can only be accessed through special ALU (arithmetic logic unit) operations.
    - The 32 bit lower subregisters zero-extend into 64 bit when they are being written to
  - The operating mode is 64 bit by default
  - `r10` is the only register which is read-only and contains the frame pointer address in order to access the BPF stack space.
- 1 program counter

## Stack
- 512 byte stack