# BPF RISCV Offloading

This project aims to create an offload device to cross-compile the BPF code to RISCV in order for it to be executed on HW accellerators.

## What the module should do
-Register a new offload device
    - Translate the program code into RISCV machine code
    - Offload maps to a RISCV CPU

## Target Programming Workflow
- Program is written in standard manner
- LLVM compiled as normal
- iproute/tc/libbpf loads the program requesting offload
- The offload module JIT converts the BPF bytecode to RISCV machine code
- Translation reuses as much as possible of the linux verifier and JIT infrastructure

