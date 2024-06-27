# Instructions

## general encoding
bpf instructions have fixed size length, and comes in two versions:
### basic instructions (64 bit length)

<table>
    <tr>
        <td>
          0
        </td>
        <td>
          1
        </td>
        <td>
          2
        </td>
        <td>
          3
        </td>
        <td>
          4
        </td>
        <td>
          5
        </td>
        <td>
          6
        </td>
        <td>
          7
        </td>
        <td>
          8
        </td>
        <td>
          9
        </td>
        <td>
          10
        </td>
        <td>
          11
        </td>
        <td>
          12
        </td>
        <td>
          13
        </td>
        <td>
          14
        </td>
        <td>
          15
        </td>
        <td>
          16
        </td>
        <td>
          17
        </td>
        <td>
          18
        </td>
        <td>
          19
        </td>
        <td>
          20
        </td>
        <td>
          21
        </td>
        <td>
          22
        </td>
        <td>
          23
        </td>
        <td>
          24
        </td>
        <td>
          25
        </td>
        <td>
          26
        </td>
        <td>
          27
        </td>
        <td>
          28
        </td>
        <td>
          29
        </td>
        <td>
          30
        </td>
        <td>
          31
        </td>
    </tr>
    <tr>
        <td colspan="8">
          opcode
        </td>
        <td colspan="8">
          regs
        </td>
        <td colspan="16">
          offset
        </td>
    </tr>
    <tr>
        <td colspan="32">
          immediate
        </td>
    </tr>
</table>

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    opcode     |     regs      |            offset             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              imm                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Extended Instructions (128 bit length)

<table>
    <tr>
        <td>
          0
        </td>
        <td>
          1
        </td>
        <td>
          2
        </td>
        <td>
          3
        </td>
        <td>
          4
        </td>
        <td>
          5
        </td>
        <td>
          6
        </td>
        <td>
          7
        </td>
        <td>
          8
        </td>
        <td>
          9
        </td>
        <td>
          10
        </td>
        <td>
          11
        </td>
        <td>
          12
        </td>
        <td>
          13
        </td>
        <td>
          14
        </td>
        <td>
          15
        </td>
        <td>
          16
        </td>
        <td>
          17
        </td>
        <td>
          18
        </td>
        <td>
          19
        </td>
        <td>
          20
        </td>
        <td>
          21
        </td>
        <td>
          22
        </td>
        <td>
          23
        </td>
        <td>
          24
        </td>
        <td>
          25
        </td>
        <td>
          26
        </td>
        <td>
          27
        </td>
        <td>
          28
        </td>
        <td>
          29
        </td>
        <td>
          30
        </td>
        <td>
          31
        </td>
    </tr>
    <tr>
        <td colspan="8">
          opcode
        </td>
        <td colspan="8">
          regs
        </td>
        <td colspan="16">
          offset
        </td>
    </tr>
    <tr>
        <td colspan="32">
          immediate
        </td>
    </tr>
    <tr>
        <td colspan="32">
          reserved
        </td>
    </tr>
    <tr>
        <td colspan="32">
          next_imm
        </td>
    </tr>
</table>

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    opcode     |     regs      |            offset             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              imm                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           reserved                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           next_imm                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### reserved
unused, set to zero

#### next_imm
second signed integer immediate value

### opcode
<table>
    <tr>
        <td>
          0
        </td>
        <td>
          1
        </td>
        <td>
          2
        </td>
        <td>
          3
        </td>
        <td>
          4
        </td>
        <td>
          5
        </td>
        <td>
          6
        </td>
        <td>
          7
        </td>
    </tr>
    <tr>
        <td colspan="5">
          class-specific
        </td>
        <td colspan="3">
          class
        </td>
    </tr>
</table>

#### classes
| class | value | description                     |
|-------|-------|---------------------------------|
| LD    | 000   | non-standard load operations    |
| LDX   | 001   | load into register operations   |
| ST    | 010   | store from immediate operations |
| STX   | 011   | store from register operations  |
| ALU   | 100   | 32-bit arithmetic operations    |
| JMP   | 101   | 64-bit jump operations          |
| JMP32 | 110   | 32-bit jump operations          |
| ALU64 | 111   | 64-bit arithmetic operations    |

### regs
The source and destination register numbers.

On a little-endian host:
<table>
    <tr>
        <td>
          0
        </td>
        <td>
          1
        </td>
        <td>
          2
        </td>
        <td>
          3
        </td>
        <td>
          4
        </td>
        <td>
          5
        </td>
        <td>
          6
        </td>
        <td>
          7
        </td>
    </tr>
    <tr>
        <td colspan="4">
          src_reg
        </td>
        <td colspan="4">
          dst_reg
        </td>
    </tr>
</table>

On a big-endian host:
<table>
    <tr>
        <td>
          0
        </td>
        <td>
          1
        </td>
        <td>
          2
        </td>
        <td>
          3
        </td>
        <td>
          4
        </td>
        <td>
          5
        </td>
        <td>
          6
        </td>
        <td>
          7
        </td>
    </tr>
    <tr>
        <td colspan="4">
          dst_reg
        </td>
        <td colspan="4">
          src_reg
        </td>
    </tr>
</table>

### offset
Signed integer offset used with pointer arithmetic, except where otherwise specified (some arithmetic instructions reuse this field for other purposes)

### imm
signed integer immediate value

## Arithmetic instructions (classes `ALU`, `ALU64`)
| name  | code | offset  | description                                                |
|-------|------|---------|------------------------------------------------------------|
| ADD   | 0x0  | 0       | dst += src                                                 |
| SUB   | 0x1  | 0       | dst -= src                                                 |
| MUL   | 0x2  | 0       | dst *= src                                                 |
| DIV   | 0x3  | 0       | dst = (src != 0) ? (dst / src) : 0                         |
| SDIV  | 0x3  | 1       | dst = (src != 0) ? (dst s/ src) : 0                        |
| OR    | 0x4  | 0       | dst \|= src                                                |
| AND   | 0x5  | 0       | dst &= src                                                 |
| LSH   | 0x6  | 0       | dst <<= (src & mask)                                       |
| RSH   | 0x7  | 0       | dst >>= (src & mask)                                       |
| NEG   | 0x8  | 0       | dst = -dst                                                 |
| MOD   | 0x9  | 0       | dst = (src != 0) ? (dst % src) : dst                       |
| SMOD  | 0x9  | 1       | dst = (src != 0) ? (dst s% src) : dst                      |
| XOR   | 0xa  | 0       | dst ^= src                                                 |
| MOV   | 0xb  | 0       | dst = src                                                  |
| MOVSX | 0xb  | 8/16/32 | dst = (s8,s16,s32)src (move operation with sign extension) |
| ARSH  | 0xc  | 0       | sign extending dst >>= (src & mask)                        |
| END   | 0xd  | 0       | byte swap operations (see Byte swap instructions below)    |

### opcode
```
+-+-+-+-+-+-+-+-+
|  code |s|class|
+-+-+-+-+-+-+-+-+
```

### s (source)
the source operand location, which unless otherwise specified is one of:

| source | value | description                                    |
|--------|-------|------------------------------------------------|
| K      | 0     | use 32-bit ‘imm’ value as source operand       |
| X      | 1     | use ‘src_reg’ register value as source operand |

### Edge case handling
- Underflow and overflow are allowed during arithmetic operations, meaning the 64-bit or 32-bit value will wrap.
- If BPF program execution would result in division by zero, the destination register is instead set to zero.
- If execution would result in modulo by zero, for ALU64 the value of the destination register is unchanged whereas for ALU the upper 32 bits of the destination register are zeroed.

### Modulo and division
- For unsigned operations (`DIV` and `MOD`)
  - For ALU, ‘imm’ is interpreted as a 32-bit **unsigned** value.
  - For ALU64, ‘imm’ is first sign extended from 32 to 64 bits, and then interpreted as a 64-bit **unsigned** value.
- For signed operations (`SDIV` and `SMOD`)
  - For ALU, ‘imm’ is interpreted as a 32-bit **signed** value.
  - For ALU64, ‘imm’ is first sign extended from 32 to 64 bits, and then interpreted as a 64-bit **signed** value.

### Byte swap operations
The byte swap instructions operate on the destination register only and do not use a separate source register or immediate value.

These instructions use the s (source) bit to choose which kind of swap to perform (for ALU64 there is only one option):

| class | s bit | meaning  | description                                       |
|-------|-------|----------|---------------------------------------------------|
| ALU   | 0     | TO_LE    | convert between host byte order and little endian |
| ALU   | 1     | TO_BE    | convert between host byte order and big endian    |
| ALU64 | 0     | reserved | do byte swap unconditionally                      |

The ‘imm’ field encodes the width of the swap operations.
The following widths are supported: 16, 32 and 64.
Width 64 operations belong to the base64 conformance group and other swap operations belong to the base32 conformance group.

## JUMP instructions (classes `JMP`, `JMP32`)
| code | value | src_reg | description                       | notes                                            |
|------|-------|---------|-----------------------------------|--------------------------------------------------|
| JA   | 0x0   | 0x0     | PC += offset                      | {JA, K, JMP} only                                |
| JA   | 0x0   | 0x0     | PC += imm                         | {JA, K, JMP32} only                              |
| JEQ  | 0x1   | any     | PC += offset if dst == src        |                                                  |
| JGT  | 0x2   | any     | PC += offset if dst > src         | unsigned                                         |
| JGE  | 0x3   | any     | PC += offset if dst >= src        | unsigned                                         |
| JSET | 0x4   | any     | PC += offset if dst & src         |                                                  |
| JNE  | 0x5   | any     | PC += offset if dst != src        |                                                  |
| JSGT | 0x6   | any     | PC += offset if dst > src         | signed                                           |
| JSGE | 0x7   | any     | PC += offset if dst >= src        | signed                                           |
| CALL | 0x8   | 0x0     | call helper function by static ID | {CALL, K, JMP} only, see Helper functions        |
| CALL | 0x8   | 0x1     | call PC += imm                    | {CALL, K, JMP} only, see Program-local functions |
| CALL | 0x8   | 0x2     | call helper function by BTF ID    | {CALL, K, JMP} only, see Helper functions        |
| EXIT | 0x9   | 0x0     | return                            | {CALL, K, JMP} only                              |
| JLT  | 0xa   | any     | PC += offset if dst < src         | unsigned                                         |
| JLE  | 0xb   | any     | PC += offset if dst <= src        | unsigned                                         |
| JSLT | 0xc   | any     | PC += offset if dst < src         | signed                                           |
| JSLE | 0xd   | any     | PC += offset if dst <= src        | signed                                           |

The offset to increment by is in units of 64-bit instructions relative to the instruction following the jump instruction.
Thus, ‘PC += 1’ skips execution of the next instruction if it’s a basic instruction or results in undefined behavior if the next instruction is a 128-bit wide instruction.

> The BPF program needs to store the return value into register R0 before doing an EXIT.

The `JMP` class permits a 16-bit jump offset specified by the ‘offset’ field, whereas the `JMP32` class permits a 32-bit jump offset specified by the ‘imm’ field.
A > 16-bit conditional jump may be converted to a < 16-bit conditional jump plus a 32-bit unconditional jump.

### Helper funcs
- Helper functions are a concept whereby BPF programs can call into a set of function calls exposed by the underlying platform.
- Historically, each helper function was identified by a **static ID encoded in the ‘imm’ field**. The available helper functions may differ for each program type, but static IDs are unique across all program types.
- Platforms that support the BPF Type Format (BTF) support identifying a helper function by a BTF ID encoded in the ‘imm’ field, where the BTF ID identifies the helper name and type.

### Program-local functions
Program-local functions are functions exposed by the same BPF program as the caller, and are referenced by offset from the call instruction, similar to JA.
The offset is encoded in the ‘imm’ field of the call instruction. An EXIT within the program-local function will return to the caller.

### Kfuncs


