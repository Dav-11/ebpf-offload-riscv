# bpf_offload_dev

## File
`kernel/bpf/offload.c`

## Definition
```C
struct bpf_offload_dev {
	const struct bpf_prog_offload_ops *ops;
	struct list_head netdevs;
	void *priv;
};
```