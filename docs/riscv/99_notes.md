# Notes in no particular order

- `AUIPC` (Add Upper Immediate to PC): $ rd \leftarrow PC + (imm \ll 12)  $
- `bcc` (Branch if Carry Clear):
  - does not exist in RISCV (used in ARM)
  - branch to a different part of the code if the carry flag in the condition code register (CPSR) is clear
