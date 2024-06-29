# Variables

## Maps

Maps are shared memory regions accessible by BPF programs on some platforms.

A map can have various semantics as defined in a separate document, and may or may not have a single contiguous memory
region, but the ‘`map_val(map)`’ is currently only defined for maps that do have a single contiguous memory region.

Each map can have a file descriptor (fd) if supported by the platform, where ‘map_by_fd(imm)’ means to get the map with
the specified file descriptor.

Each BPF program can also be defined to use a set of maps associated with the program at load time, and ‘map_by_idx(
imm)’ means to get the map with the given index in the set associated with the BPF program containing the instruction.

## Platform Variables

Platform variables are memory regions, identified by integer ids, exposed by the runtime and accessible by BPF programs
on some platforms.

The ‘var_addr(imm)’ operation means to get the address of the memory region identified by the given id.