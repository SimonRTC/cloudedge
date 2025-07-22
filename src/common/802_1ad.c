#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/if_vlan.h>

#include "types.h"

static __always_inline u16 parse_vlans(void **cursor, void *data_end, u16 outer_proto, u16 *s_vlan, u16 *c_vlan)
{
    *s_vlan = 0;
    *c_vlan = 0;

    // Only parse if VLAN tag present
    if (outer_proto != ETH_P_8021Q && outer_proto != ETH_P_8021AD)
        return outer_proto;

    // ---- Outer VLAN header ----
    struct vlan_hdr *vh = *cursor;
    if ((void *)(vh + 1) > data_end)
        return 0;

    u16 vlan_id = bpf_ntohs(vh->h_vlan_TCI) & 0x0FFF;
    u16 inner_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);

    if (outer_proto == ETH_P_8021AD)
    {
        *s_vlan = vlan_id; // Service VLAN
    }
    else
    {
        *c_vlan = vlan_id; // Single customer VLAN
    }

    // Advance cursor after first VLAN
    *cursor = vh + 1;

    // ---- Second VLAN (QinQ) if present ----
    if (inner_proto == ETH_P_8021Q)
    {
        struct vlan_hdr *vh2 = *cursor;
        if ((void *)(vh2 + 1) > data_end)
            return 0;

        *c_vlan = bpf_ntohs(vh2->h_vlan_TCI) & 0x0FFF;
        inner_proto = bpf_ntohs(vh2->h_vlan_encapsulated_proto);

        *cursor = vh2 + 1;
    }

    return inner_proto;
}

/*
 * push_vlans
 *
 * Pushes one or two VLAN headers (802.1Q or QinQ 802.1ad) on the packet.
 *
 * - If svlan == 0 and cvlan == 0 -> no rewrite performed.
 * - If only svlan is set -> pushes one outer S-VLAN tag (802.1ad).
 * - If only cvlan is set -> pushes one inner C-VLAN tag (802.1q).
 * - If both svlan and cvlan are set -> pushes QinQ (outer 802.1ad, inner 802.1q).
 *
 * Returns:
 *   0 on success, -1 if headroom adjustment fails or bounds check fails.
 */
static __always_inline int push_vlans(struct xdp_md *ctx, u16 svlan, u16 cvlan)
{
    /* No VLANs requested -> nothing to do */
    if (svlan == 0 && cvlan == 0)
        return 0;

    /* Calculate required space (4 bytes per VLAN tag) */
    int needed_len = 0;
    if (svlan)
        needed_len += sizeof(struct vlan_hdr);
    if (cvlan)
        needed_len += sizeof(struct vlan_hdr);

    /* Adjust head backwards to create space for VLAN tags */
    if (bpf_xdp_adjust_head(ctx, -needed_len) < 0)
        return -1;

    /* Refresh pointers after headroom adjustment */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    /* Save original EtherType (payload after MACs) */
    __be16 orig_proto = eth->h_proto;
    struct vlan_hdr *vh = (void *)(eth + 1);

    /* Push S-VLAN first (outermost tag) if set */
    if (svlan)
    {
        if ((void *)(vh + 1) > data_end)
            return -1;

        vh->h_vlan_TCI = bpf_htons(svlan & 0x0FFF);
        vh->h_vlan_encapsulated_proto = orig_proto;

        /* Outer VLAN always QinQ 802.1ad */
        eth->h_proto = bpf_htons(ETH_P_8021AD);

        /* Next inner VLAN type becomes 802.1Q */
        orig_proto = bpf_htons(ETH_P_8021Q);
        vh++;
    }

    /* Push C-VLAN next (inner tag) if set */
    if (cvlan)
    {
        if ((void *)(vh + 1) > data_end)
            return -1;

        vh->h_vlan_TCI = bpf_htons(cvlan & 0x0FFF);
        vh->h_vlan_encapsulated_proto = orig_proto;

        /* If only single tag -> mark it as 802.1Q */
        if (!svlan)
            eth->h_proto = bpf_htons(ETH_P_8021Q);
    }

    return 0;
}

static __always_inline u32 offset_from_event(event_t *evt)
{
    u32 offset = sizeof(struct ethhdr); // Always start after Ethernet header (14 bytes)

    // Add 4 bytes for each VLAN tag present
    if (evt->s_vlan)
        offset += sizeof(struct vlan_hdr);

    if (evt->c_vlan)
        offset += sizeof(struct vlan_hdr);

    return offset;
}