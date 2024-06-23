//
// Created by davide on 6/23/24.
//

#include "verifier.h"


int does_verifier_scan_backward(rvo_insn_meta *meta, unsigned int insn_idx) {

    // TODO: implement
    return 0;
}

rvo_insn_meta * rvo_get_insn_meta(rvo_prog *nfp_prog, rvo_insn_meta *meta, unsigned int insn_idx) {

    int backwards = does_verifier_scan_backward(meta, insn_idx);

    // TODO: return the metadata for instruction insn_idx
    return meta;
}

int rvo_insn_opcode_supported(u8 code) {

    return (int) !!instr_cb[code];
}
