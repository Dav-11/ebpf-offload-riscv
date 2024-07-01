//
// Created by davide on 6/23/24.
//

#include "offload_maps.h"

static int rvo_bpf_map_alloc(struct netdevsim *ns,
			     struct bpf_offloaded_map *offmap)
{
	int err;

	if (offmap->map.map_type != BPF_MAP_TYPE_ARRAY &&
	    offmap->map.map_type != BPF_MAP_TYPE_HASH)
		return -EINVAL;
	if (offmap->map.max_entries > RVO_BPF_MAX_KEYS)
		return -ENOMEM;
	if (offmap->map.map_flags)
		return -EINVAL;

	// TODO implement

	return 0;
}

int rvo_bpf_map_get_next_key(struct bpf_offloaded_map *offmap, void *key,
			     void *next_key)
{
	// TODO: implement
	return 0;
}
int rvo_bpf_map_lookup_entry(struct bpf_offloaded_map *offmap, void *key,
			     void *value)
{
	// TODO: implement
	return 0;
}
int rvo_bpf_map_update_entry(struct bpf_offloaded_map *offmap, void *key,
			     void *value, u64 flags)
{
	// TODO: implement
	return 0;
}
int rvo_bpf_map_delete_elem(struct bpf_offloaded_map *offmap, void *key)
{
	// TODO: implement
	return 0;
}