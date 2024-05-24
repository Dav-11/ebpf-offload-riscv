//
// Created by Davide Collovigh on 24/05/24.
//

#include "jit.h"

inline bool is_creg(u8 reg)
{
	return (1 << reg) & (BIT(RV_REG_FP) | BIT(RV_REG_S1) | BIT(RV_REG_A0) |
			     BIT(RV_REG_A1) | BIT(RV_REG_A2) | BIT(RV_REG_A3) |
			     BIT(RV_REG_A4) | BIT(RV_REG_A5));
}