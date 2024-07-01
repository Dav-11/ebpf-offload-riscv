//
// Created by davide on 6/23/24.
//

#ifndef MAPS_H
#define MAPS_H

#include "rv_jit/jit.h"

#define RVO_BPF_MAX_KEYS 256

/***********************************
 * funcs
 **********************************/

int rvo_bpf_map_get_next_key(struct bpf_offloaded_map *offmap, void *key,
			     void *next_key);
int rvo_bpf_map_lookup_entry(struct bpf_offloaded_map *offmap, void *key,
			     void *value);
int rvo_bpf_map_update_entry(struct bpf_offloaded_map *offmap, void *key,
			     void *value, u64 flags);
int rvo_bpf_map_delete_elem(struct bpf_offloaded_map *offmap, void *key);

/***********************************
 * struct
 **********************************/

static const struct bpf_map_dev_ops rvo_bpf_map_ops = {
	.map_get_next_key = rvo_bpf_map_get_next_key,
	.map_lookup_elem = rvo_bpf_map_lookup_entry,
	.map_update_elem = rvo_bpf_map_update_entry,
	.map_delete_elem = rvo_bpf_map_delete_elem,
};

#endif //MAPS_H
