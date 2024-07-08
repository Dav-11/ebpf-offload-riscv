//
// Created by Davide Collovigh on 08/07/24.
//

#include "rv_insn.h"

#define PRINT_INSN(a, b, c) printk("%s %s %s", a, b, c)

static inline u32 rv_addi(u8 rd, u8 rs1, u16 imm11_0)
{
	printk("ADDI $R%u $R%u %u", rd, rs1, imm11_0);
	return 0;
}

static inline u32 rv_slli(u8 rd, u8 rs1, u16 imm11_0)
{
	printk("SLLI $R%u $R%u %u", rd, rs1, imm11_0);
	return 0;
}

static inline u32 rv_srli(u8 rd, u8 rs1, u16 imm11_0)
{
	printk("SRLI $R%u $R%u %u", rd, rs1, imm11_0);
	return 0;
}
