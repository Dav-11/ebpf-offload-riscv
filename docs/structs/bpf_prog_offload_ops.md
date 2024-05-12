# bpf_prog_offload_ops

## File
`include/linux/bpf.h`

## Declaration
```C
struct bpf_prog_offload_ops {
	/* verifier basic callbacks */
	int (*insn_hook)(struct bpf_verifier_env *env, int insn_idx, int prev_insn_idx);
	int (*finalize)(struct bpf_verifier_env *env);
	/* verifier optimization callbacks (called after .finalize) */
	int (*replace_insn)(struct bpf_verifier_env *env, u32 off, struct bpf_insn *insn);
	int (*remove_insns)(struct bpf_verifier_env *env, u32 off, u32 cnt);
	/* program management callbacks */
	int (*prepare)(struct bpf_prog *prog);
	int (*translate)(struct bpf_prog *prog);
	void (*destroy)(struct bpf_prog *prog);
};
```

## Examples
### drivers/net/netdevsim/bpf.c
```C
static int
nsim_bpf_verify_insn(struct bpf_verifier_env *env, int insn_idx, int prev_insn)
{
	struct nsim_bpf_bound_prog *state;
	int ret = 0;

	state = env->prog->aux->offload->dev_priv;
	if (state->nsim_dev->bpf_bind_verifier_delay && !insn_idx)
		msleep(state->nsim_dev->bpf_bind_verifier_delay);

	if (insn_idx == env->prog->len - 1) {
		pr_vlog(env, "Hello from netdevsim!\n");

		if (!state->nsim_dev->bpf_bind_verifier_accept)
			ret = -EOPNOTSUPP;
	}

	return ret;
}

static int nsim_bpf_finalize(struct bpf_verifier_env *env)
{
	return 0;
}

static int nsim_bpf_verifier_prep(struct bpf_prog *prog)
{
	struct nsim_dev *nsim_dev =
			bpf_offload_dev_priv(prog->aux->offload->offdev);

	if (!nsim_dev->bpf_bind_accept)
		return -EOPNOTSUPP;

	return nsim_bpf_create_prog(nsim_dev, prog);
}

static int nsim_bpf_translate(struct bpf_prog *prog)
{
	struct nsim_bpf_bound_prog *state = prog->aux->offload->dev_priv;

	state->state = "xlated";
	return 0;
}

static void nsim_bpf_destroy_prog(struct bpf_prog *prog)
{
	struct nsim_bpf_bound_prog *state;

	state = prog->aux->offload->dev_priv;
	WARN(state->is_loaded,
	     "offload state destroyed while program still bound");
	debugfs_remove_recursive(state->ddir);
	list_del(&state->l);
	kfree(state);
}

static const struct bpf_prog_offload_ops nsim_bpf_dev_ops = {
	.insn_hook	= nsim_bpf_verify_insn,
	.finalize	= nsim_bpf_finalize,
	.prepare	= nsim_bpf_verifier_prep,
	.translate	= nsim_bpf_translate,
	.destroy	= nsim_bpf_destroy_prog,
};


```
