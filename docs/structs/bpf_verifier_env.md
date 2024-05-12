# bpf_verifier_env

## File
`include/linux/bpf_verifier.h`

## Declaration
```C
/* single container for all structs
 * one verifier_env per bpf_check() call
 */
struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;		/* eBPF program being verified */
	const struct bpf_verifier_ops *ops;
	struct module *attach_btf_mod;	/* The owner module of prog->aux->attach_btf */
	struct bpf_verifier_stack_elem *head; /* stack of verifier states to be processed */
	int stack_size;			/* number of states to be processed */
	bool strict_alignment;		/* perform strict pointer alignment checks */
	bool test_state_freq;		/* test verifier with different pruning frequency */
	bool test_reg_invariants;	/* fail verification on register invariants violations */
	struct bpf_verifier_state *cur_state; /* current verifier state */
	struct bpf_verifier_state_list **explored_states; /* search pruning optimization */
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[MAX_USED_MAPS]; /* array of map's used by eBPF program */
	struct btf_mod_pair used_btfs[MAX_USED_BTFS]; /* array of BTF's used by BPF program */
	u32 used_map_cnt;		/* number of used maps */
	u32 used_btf_cnt;		/* number of used BTF objects */
	u32 id_gen;			/* used to generate unique reg IDs */
	u32 hidden_subprog_cnt;		/* number of hidden subprogs */
	int exception_callback_subprog;
	bool explore_alu_limits;
	bool allow_ptr_leaks;
	/* Allow access to uninitialized stack memory. Writes with fixed offset are
	 * always allowed, so this refers to reads (with fixed or variable offset),
	 * to writes with variable offset and to indirect (helper) accesses.
	 */
	bool allow_uninit_stack;
	bool bpf_capable;
	bool bypass_spec_v1;
	bool bypass_spec_v4;
	bool seen_direct_write;
	bool seen_exception;
	struct bpf_insn_aux_data *insn_aux_data; /* array of per-insn state */
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[BPF_MAX_SUBPROGS + 2]; /* max + 2 for the fake and exception subprogs */
	union {
		struct bpf_idmap idmap_scratch;
		struct bpf_idset idset_scratch;
	};
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	struct backtrack_state bt;
	struct bpf_jmp_history_entry *cur_hist_ent;
	u32 pass_cnt; /* number of times do_check() was called */
	u32 subprog_cnt;
	/* number of instructions analyzed by the verifier */
	u32 prev_insn_processed, insn_processed;
	/* number of jmps, calls, exits analyzed so far */
	u32 prev_jmps_processed, jmps_processed;
	/* total verification time */
	u64 verification_time;
	/* maximum number of verifier states kept in 'branching' instructions */
	u32 max_states_per_insn;
	/* total number of allocated verifier states */
	u32 total_states;
	/* some states are freed during program analysis.
	 * this is peak number of states. this number dominates kernel
	 * memory consumption during verification
	 */
	u32 peak_states;
	/* longest register parentage chain walked for liveness marking */
	u32 longest_mark_read_walk;
	bpfptr_t fd_array;

	/* bit mask to keep track of whether a register has been accessed
	 * since the last time the function state was printed
	 */
	u32 scratched_regs;
	/* Same as scratched_regs but for stack slots */
	u64 scratched_stack_slots;
	u64 prev_log_pos, prev_insn_print_pos;
	/* buffer used to generate temporary string representations,
	 * e.g., in reg_type_str() to generate reg_type string
	 */
	char tmp_str_buf[TMP_STR_BUF_LEN];
};
```

## Examples

