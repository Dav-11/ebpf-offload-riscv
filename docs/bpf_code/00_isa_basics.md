# ISA basics

## Types

This document refers to integer types with the notation `SN` to specify a type’s signedness (`S`) and bit width (`N`),
respectively.

Meaning of signedness notation:

| S | Meaning  |
|---|----------|
| u | unsigned |
| s | signed   |

Meaning of bit-width notation:

| N   | Bit width |
|-----|-----------|
| 8   | 8 bits    |
| 16  | 16 bits   |
| 32  | 32 bits   |
| 64  | 64 bits   |
| 128 | 128 bits  |

For example, u32 is a type whose valid values are all the 32-bit unsigned numbers and s16 is a type whose valid values
are all the 16-bit signed numbers.

## Sign Extend

To sign extend an `X` -bit number, A, to a `Y` -bit number, B , means to:

1. Copy all X bits from A to the lower X bits of B.
2. Set the value of the remaining Y - X bits of B to the value of the most-significant bit of A.

```
Sign extend an 8-bit number A to a 16-bit number B on a big-endian platform:

A:          10000110
B: 11111111 10000110
```

## Conformance group

- **base32**: includes all instructions defined in this specification unless otherwise noted.
- **base64**: includes base32, plus instructions explicitly noted as being in the base64 conformance group.
- **atomic32**: includes 32-bit atomic operation instructions (see Atomic operations).
- **atomic64**: includes atomic32, plus 64-bit atomic operation instructions.
- **divmul32**: includes 32-bit division, multiplication, and modulo instructions.
- **divmul64**: includes divmul32, plus 64-bit division, multiplication, and modulo instructions.
- **packet**: deprecated packet access instructions.

> An implementation must support the `base32` conformance group and may support additional conformance groups, where
> supporting a conformance group means it must support all instructions in that conformance group.

