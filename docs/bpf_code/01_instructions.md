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

### Wide Instructions (128 bit length)

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

### opcode

```
+-+-+-+-+-+-+-+-+
|  code |s|class|
+-+-+-+-+-+-+-+-+
```

### Helper funcs
- Helper functions are a concept whereby BPF programs can call into a set of function calls exposed by the underlying platform.
- Historically, each helper function was identified by a **static ID encoded in the ‘imm’ field**. The available helper functions may differ for each program type, but static IDs are unique across all program types.
- Platforms that support the BPF Type Format (BTF) support identifying a helper function by a BTF ID encoded in the ‘imm’ field, where the BTF ID identifies the helper name and type.

### Program-local functions
Program-local functions are functions exposed by the same BPF program as the caller, and are referenced by offset from the call instruction, similar to JA.
The offset is encoded in the ‘imm’ field of the call instruction. An EXIT within the program-local function will return to the caller.

### Kfuncs

## Load & store instructions (classes `LD`, `LDX`, `ST`, `STX`)

### opcode

```
+-+-+-+-+-+-+-+-+
|mode |sz |class|
+-+-+-+-+-+-+-+-+
```

#### mode

| mode modifier | value | description                         | reference                                 |
|---------------|-------|-------------------------------------|-------------------------------------------|
| IMM           | 0     | 64-bit immediate instructions       | [64-bit immediate instructions]()         |
| ABS           | 1     | legacy BPF packet access (absolute) | [Legacy BPF Packet access instructions]() |
| IND           | 2     | legacy BPF packet access (indirect) | [Legacy BPF Packet access instructions]() |
| MEM           | 3     | regular load and store operations   | [Regular load and store operations]()     |
| MEMSX         | 4     | sign-extension load operations      | [Sign-extension load operations]()        |
| ATOMIC        | 6     | atomic operations                   | [Atomic operations]()                     |

#### sz (size)

| size | value | description           |
|------|-------|-----------------------|
| W    | 0     | word (4 bytes)        |
| H    | 1     | half word (2 bytes)   |
| B    | 2     | byte                  |
| DW   | 3     | double word (8 bytes) |

### Regular load and store operations

The `MEM` mode modifier is used to encode regular load and store instructions that transfer data between a register and
memory.

`{MEM, <size>, STX}`:

```
*(size *) (dst + offset) = src
```

`{MEM, <size>, ST}`:

```
*(size *) (dst + offset) = imm
```

### Sign-extension load operations

The `MEMSX` mode modifier is used to encode sign-extension load instructions that transfer data between a register and
memory.

`{MEMSX, <size>, LDX}`:

```
dst = *(signed size *) (src + offset)
```

Where ‘<size>’ is one of: `B`, `H`, or `W`, and ‘signed size’ is one of: s8, s16, or s32.

### Atomic operations

All atomic operations supported by BPF are encoded as store operations that use the ATOMIC mode modifier as follows:

- `{ATOMIC, W, STX}` for 32-bit operations, which are part of the “atomic32” conformance group.
- `{ATOMIC, DW, STX}` for 64-bit operations, which are part of the “atomic64” conformance group.
- 8-bit and 16-bit wide atomic operations are not supported.

The ‘imm’ field is used to encode the actual atomic operation.
Simple atomic operation use a subset of the values defined to encode arithmetic operations in the ‘imm’ field to encode
the atomic operation:

| imm | value | description |
|-----|-------|-------------|
| ADD | 0x00  | atomic add  |
| OR  | 0x40  | atomic or   |
| AND | 0x50  | atomic and  |
| XOR | 0xa0  | atomic xor  |

In addition to the simple atomic operations, there also is a modifier and two complex atomic operations:

| imm     | value         | description                 |
|---------|---------------|-----------------------------|
| FETCH   | 0x01          | modifier: return old value  |
| XCHG    | 0xe0 \| FETCH | atomic exchange             |
| CMPXCHG | 0xf0 \| FETCH | atomic compare and exchange |

If the `FETCH` flag is set, then the operation also overwrites src with the value that was in memory before it was
modified.

The `XCHG` operation atomically exchanges src with the value addressed by dst + offset.

The `CMPXCHG` operation atomically compares the value addressed by dst + offset with `R0`.
If they match, the value addressed by dst + offset is replaced with src.
In either case, the value that was at dst + offset before the operation is zero-extended and loaded back to `R0`.

### Immediate instructions

Instructions with the `IMM` ‘mode’ modifier use the wide instruction encoding defined in Instruction encoding, and use
the ‘src_reg’ field of the basic instruction to hold an opcode subtype.

The following table defines a set of {IMM, DW, LD} instructions with opcode subtypes in the ‘src_reg’ field, using new
terms such as “map” defined further below:

| src_reg | pseudocode                                | imm type    | dst type     |
|---------|-------------------------------------------|-------------|--------------|
| 0x0     | dst = (next_imm << 32) \| imm             | integer     | integer      |
| 0x1     | dst = map_by_fd(imm)                      | map fd      | map          |
| 0x2     | dst = map_val(map_by_fd(imm)) + next_imm  | map fd      | data address |
| 0x3     | dst = var_addr(imm)                       | variable id | data address |
| 0x4     | dst = code_addr(imm)                      | integer     | code address |
| 0x5     | dst = map_by_idx(imm)                     | map index   | map          |
| 0x6     | dst = map_val(map_by_idx(imm)) + next_imm | map index   | data address |

where:

- map_by_fd(imm) means to convert a 32-bit file descriptor into an address of a map (see Maps)
- map_by_idx(imm) means to convert a 32-bit index into an address of a map
- map_val(map) gets the address of the first value in a given map
- var_addr(imm) gets the address of a platform variable (see Platform Variables) with a given id
- code_addr(imm) gets the address of the instruction at a specified relative offset in number of (64-bit) instructions
- the ‘imm type’ can be used by disassemblers for display
- the ‘dst type’ can be used for verification and JIT compilation purposes