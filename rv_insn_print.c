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
static inline u32 rv_andi(u8 rd, u8 rs1, u16 imm11_0)
{
	printk("ANDI $R%u $R%u %u", rd, rs1, imm11_0);
	return 0;
}
static inline u32 rv_ori(u8 rd, u8 rs1, u16 imm11_0)
{
	printk("ORI $R%u $R%u %u", rd, rs1, imm11_0);
	return 0;
}
static inline u32 rv_xori(u8 rd, u8 rs1, u16 imm11_0)
{
	printk("XORI $R%u $R%u %u", rd, rs1, imm11_0);
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
static inline u32 rv_srai(u8 rd, u8 rs1, u16 imm11_0)
{
	printk("SRAI $R%u $R%u %u", rd, rs1, imm11_0);
	return 0;
}

static inline u32 rv_lui(u8 rd, u32 imm31_12)
{
	printk("LUI $R%u %u", rd, imm31_12);
	return 0;
}

static inline u32 rv_auipc(u8 rd, u32 imm31_12)
{
	printk("AUIPC $R%u %u", 0x17, rd, imm31_12);
	return 0;
}

static inline u32 rv_add(u8 rd, u8 rs1, u8 rs2)
{
	printk("ADD $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_sub(u8 rd, u8 rs1, u8 rs2)
{
	printk("SUB $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_sltu(u8 rd, u8 rs1, u8 rs2)
{
	printk("SLTU $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_and(u8 rd, u8 rs1, u8 rs2)
{
	printk("AND $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_or(u8 rd, u8 rs1, u8 rs2)
{
	printk("OR $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_xor(u8 rd, u8 rs1, u8 rs2)
{
	printk("XOR $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_sll(u8 rd, u8 rs1, u8 rs2)
{
	printk("SLL $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_srl(u8 rd, u8 rs1, u8 rs2)
{
	printk("SRL $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_sra(u8 rd, u8 rs1, u8 rs2)
{
	printk("SRA $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_mul(u8 rd, u8 rs1, u8 rs2)
{
	printk("MUL $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_mulhu(u8 rd, u8 rs1, u8 rs2)
{
	printk("MULHU $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_div(u8 rd, u8 rs1, u8 rs2)
{
	printk("DIV $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_divu(u8 rd, u8 rs1, u8 rs2)
{
	printk("DIVU $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_rem(u8 rd, u8 rs1, u8 rs2)
{
	printk("REM $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_remu(u8 rd, u8 rs1, u8 rs2)
{
	printk("REMU $R%u %R%u $R%u", rd, rs1, rs2);
	return 0;
}

static inline u32 rv_jal(u8 rd, u32 imm20_1)
{
	printk("JAL $R%u %u", rd, imm20_1);
	return 0;
}

static inline u32 rv_jalr(u8 rd, u8 rs1, u16 imm11_0)
{
	printk("JALR $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_beq(u8 rs1, u8 rs2, u16 imm12_1)
{
	printk("BEQ $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_bne(u8 rs1, u8 rs2, u16 imm12_1)
{
	printk("BNE $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_bltu(u8 rs1, u8 rs2, u16 imm12_1)
{
	printk("BLTU $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_bgtu(u8 rs1, u8 rs2, u16 imm12_1)
{
	printk("BGTU $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_bgeu(u8 rs1, u8 rs2, u16 imm12_1)
{
	printk("BGEU $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_bleu(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_bgeu(rs2, rs1, imm12_1);
}

static inline u32 rv_blt(u8 rs1, u8 rs2, u16 imm12_1)
{
	printk("BLT $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_bgt(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_blt(rs2, rs1, imm12_1);
}

static inline u32 rv_bge(u8 rs1, u8 rs2, u16 imm12_1)
{
	printk("BGE $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_ble(u8 rs1, u8 rs2, u16 imm12_1)
{
	return rv_bge(rs2, rs1, imm12_1);
}

static inline u32 rv_lb(u8 rd, u16 imm11_0, u8 rs1)
{
	printk("LB $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_lh(u8 rd, u16 imm11_0, u8 rs1)
{
	printk("LH $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_lw(u8 rd, u16 imm11_0, u8 rs1)
{
	printk("LW $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_lbu(u8 rd, u16 imm11_0, u8 rs1)
{
	printk("LBU $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_lhu(u8 rd, u16 imm11_0, u8 rs1)
{
	printk("LHU $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_sb(u8 rs1, u16 imm11_0, u8 rs2)
{
	printk("SB $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_sh(u8 rs1, u16 imm11_0, u8 rs2)
{
	printk("SH $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_sw(u8 rs1, u16 imm11_0, u8 rs2)
{
	printk("SW $R%u %u($R%u)", rd, imm11_0, rs1);
	return 0;
}

static inline u32 rv_amoadd_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	printk("AMO ADD_W $R%u RS2=%u RS1=%u AQ=%u RL=%u", rd, rs2, rs1, aq,
	       rl);
	return 0;
}

static inline u32 rv_amoand_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	printk("AMO AND_W $R%u RS2=%u RS1=%u AQ=%u RL=%u", rd, rs2, rs1, aq,
	       rl);
	return 0;
}

static inline u32 rv_amoor_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	printk("AMO OR_W $R%u RS2=%u RS1=%u AQ=%u RL=%u", rd, rs2, rs1, aq, rl);
	return 0;
}

static inline u32 rv_amoxor_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	printk("AMO XOR_W $R%u RS2=%u RS1=%u AQ=%u RL=%u", rd, rs2, rs1, aq,
	       rl);
	return 0;
}

static inline u32 rv_amoswap_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	printk("AMO SWAP_W $R%u RS2=%u RS1=%u AQ=%u RL=%u", rd, rs2, rs1, aq,
	       rl);
	return 0;
}

static inline u32 rv_lr_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	printk("AMO LR_W $R%u RS2=%u RS1=%u AQ=%u RL=%u", rd, rs2, rs1, aq, rl);
	return 0;
}

static inline u32 rv_sc_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl)
{
	printk("AMO SC_W $R%u RS2=%u RS1=%u AQ=%u RL=%u", rd, rs2, rs1, aq, rl);
	return 0;
}

static inline u32 rv_fence(u8 pred, u8 succ)
{
	u16 imm11_0 = pred << 4 | succ;

	return 0;
}

static inline u32 rv_nop(void)
{
	printk("NOP");
	return 0;
}
