//
// Created by Davide Collovigh on 10/07/24.
//

#ifndef EBPF_OFFLOAD_RISCV_PREPARE_H
#define EBPF_OFFLOAD_RISCV_PREPARE_H

#include "base.h"
#include "verifier.h"
#include <linux/bpf.h>
#include <linux/list.h>

/**
 * This callback is invoked to prepare the BPF program for offloading.
 * @brief this function is responsible for preparing the BPF program for verification on the NIC hardware
 * @param prog
 * @return
 */
int rvo_prepare(struct bpf_prog *prog);

#endif //EBPF_OFFLOAD_RISCV_PREPARE_H
