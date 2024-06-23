//
// Created by davide on 6/23/24.
//

#include "netdev.h"

static const struct net_device_ops rvo_netdev_ops = {
    .ndo_start_xmit		= nsim_start_xmit,
    .ndo_set_rx_mode	= nsim_set_rx_mode,
    .ndo_set_mac_address	= eth_mac_addr,
    .ndo_validate_addr	= eth_validate_addr,
    .ndo_change_mtu		= nsim_change_mtu,
    .ndo_get_stats64	= nsim_get_stats64,
    .ndo_set_vf_mac		= nsim_set_vf_mac,
    .ndo_set_vf_vlan	= nsim_set_vf_vlan,
    .ndo_set_vf_rate	= nsim_set_vf_rate,
    .ndo_set_vf_spoofchk	= nsim_set_vf_spoofchk,
    .ndo_set_vf_trust	= nsim_set_vf_trust,
    .ndo_get_vf_config	= nsim_get_vf_config,
    .ndo_set_vf_link_state	= nsim_set_vf_link_state,
    .ndo_set_vf_rss_query_en = nsim_set_vf_rss_query_en,
    .ndo_setup_tc		= nsim_setup_tc,
    .ndo_set_features	= nsim_set_features,
    .ndo_bpf		= nsim_bpf, /// <------- TODO: HERE
};

static const struct net_device_ops rvo_vf_netdev_ops = {
    .ndo_start_xmit		= nsim_start_xmit,
    .ndo_set_rx_mode	= nsim_set_rx_mode,
    .ndo_set_mac_address	= eth_mac_addr,
    .ndo_validate_addr	= eth_validate_addr,
    .ndo_change_mtu		= nsim_change_mtu,
    .ndo_get_stats64	= nsim_get_stats64,
    .ndo_setup_tc		= nsim_setup_tc,
    .ndo_set_features	= nsim_set_features,
};
