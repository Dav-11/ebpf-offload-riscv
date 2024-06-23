# Maps Offload

## Flow
![maps](../img/bpf_map_wf.svg)

## Characteristics
- Maps reside entirely in device memory
- Programs running on the host do not have access to offloaded maps and vice versa (because host cannot efficiently access device memory)
- User space API remains unchanged
- Each map in the kernel has set of ops associated
    ```C
    // from linux/include/linux/bpf.h
    
    /* map is generic key/value storage optionally accessible by eBPF programs */
    struct bpf_map_ops {
        
        /* funcs callable from userspace (via syscall) */
        int (*map_alloc_check)(union bpf_attr *attr);
        struct bpf_map *(*map_alloc)(union bpf_attr *attr);
        void (*map_release)(struct bpf_map *map, struct file *map_file);
        void (*map_free)(struct bpf_map *map);
        int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
        
        /* funcs callable from userspace and from eBPF programs */
        void *(*map_lookup_elem)(struct bpf_map *map, void *key);
        int (*map_update_elem)(struct bpf_map *map, void *key, void *value, u64 flags);
        int (*map_delete_elem)(struct bpf_map *map, void *key);
    };
    ```
- If `map_ifindex` is set the ops are pointed to an empty set of “offload ops” regardless of the type (`bpf_offload_prog_ops`)
    ```C
    // from linux/tools/lib/bpf/bpf.h
    struct bpf_map_create_opts {
        size_t sz; /* size of this struct for forward/backward compatibility */
    
        __u32 btf_fd;
        __u32 btf_key_type_id;
        __u32 btf_value_type_id;
        __u32 btf_vmlinux_value_type_id;
    
        __u32 inner_map_fd;
        __u32 map_flags;
        __u64 map_extra;
    
        __u32 numa_node;
        __u32 map_ifindex;
    }; 
    ```
