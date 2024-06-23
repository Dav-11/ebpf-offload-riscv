//
// Created by davide on 6/23/24.
//

#ifndef VERIFIER_H
#define VERIFIER_H

#include "jit.h"


/***********************************
 funcs
***********************************/

rvo_insn_meta *rvo_get_insn_meta(rvo_prog *nfp_prog, rvo_insn_meta *meta,
          unsigned int insn_idx);

int rvo_insn_opcode_supported(u8 code);



#endif //VERIFIER_H
