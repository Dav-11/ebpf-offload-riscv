# ebpf-offload-riscv

This project aims at creating a Linux Kernel Module that is able to compile ebpf code for riscv from a machine that runs on any arch.

The idea is to use the ebpf offload capability to implement a variation of the already present riscv JIT compiler so that it can be run on arch that are not RISCV.

> This module is based on kernel version 6.8.X
