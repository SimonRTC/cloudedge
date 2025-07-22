#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/if_vlan.h>

#include "types.h"

static __always_inline __u16 parse_hardware_addresses(void **cursor, void *data_end, struct event *evt)
{
    struct ethhdr *eth = *cursor;
    if ((void *)(eth + 1) > data_end)
        return 0; // out-of-bounds

    __u8 *src_mac = eth->h_source;
    __u8 *dst_mac = eth->h_dest;

    // Copy MACs into event
    __builtin_memcpy(evt->src_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(evt->dst_mac, eth->h_dest, ETH_ALEN);

    // Advance cursor after Ethernet header
    *cursor = eth + 1;

    // Return outer EtherType
    return bpf_ntohs(eth->h_proto);
}
