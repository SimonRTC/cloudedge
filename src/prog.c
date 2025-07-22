
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/socket.h>

#include "common/types.h"
#include "common/mac.c"
#include "common/802_1ad.c"
#include "common/ip.c"

/*
 * events_rb
 *
 * A global ring buffer used to send event_t structures from the XDP program
 * to user space. Each recorded event contains metadata about the packet,
 * such as VLAN tags, MAC addresses, IP addresses, ports, and the resulting action.
 *
 * - Type: BPF_MAP_TYPE_RINGBUF
 * - Size: 16 MB (1 << 24 bytes)
 * - Usage: High-throughput, lock-free communication between kernel eBPF
 *          and user space consumers without per-CPU allocation overhead.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16MB ring buffer */
} events_rb SEC(".maps");

/*
 * drop_errors
 *
 * Per-CPU counter array for tracking packet drop errors caused by
 * ring buffer allocation failures or parsing issues.
 *
 * - Type: BPF_MAP_TYPE_PERCPU_ARRAY
 * - max_entries: 1 (single counter per CPU)
 * - Key: always 0 (only one logical entry)
 * - Value: 64-bit counter incremented whenever an error occurs
 *
 * Usage: Allows monitoring of drop events without global contention.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_errors SEC(".maps");

/*
 * routing_tablev4
 *
 * Dynamic software routing table for IPv4 lookups.
 *
 * - Type: BPF_MAP_TYPE_HASH
 * - max_entries: 1024 routes
 * - Key: struct DSRKv4_t (customer-facing IPv4 routing key)
 * - Value: struct DSRPv4_t (provider-facing IPv4 forwarding path)
 *
 * Usage:
 *   - Matches an incoming IPv4 flow (DSRKv4_t) including VLANs, protocol, and port
 *   - Returns the corresponding forwarding path (DSRPv4_t) for IP translation or forwarding
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, DSRKv4_t);
    __type(value, DSRPv4_t);
} routing_tablev4 SEC(".maps");

/*
 * routing_tablev6
 *
 * Dynamic software routing table for IPv6 lookups.
 *
 * - Type: BPF_MAP_TYPE_HASH
 * - max_entries: 1024 routes
 * - Key: struct DSRKv6_t (customer-facing IPv6 routing key)
 * - Value: struct DSRPv6_t (provider-facing IPv6 forwarding path)
 *
 * Usage:
 *   - Matches an incoming IPv6 flow (DSRKv6_t) including VLANs, protocol, and port
 *   - Returns the corresponding forwarding path (DSRPv6_t) for IP translation or forwarding
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, DSRKv6_t);
    __type(value, DSRPv6_t);
} routing_tablev6 SEC(".maps");

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Cursor pointer to the reading location of the packet
    void *cursor = data;

    // Latest EtherType on cursor
    u16 eth_proto = 0;

    // Source svlan and cvlan
    u16 s_vlan = 0, c_vlan = 0;

    struct event *evt = bpf_ringbuf_reserve(&events_rb, sizeof(*evt), 0);
    if (!evt)
    {
        // Failed to allocate space, increment error counter
        u32 key = 0;
        u64 *err_cnt = bpf_map_lookup_elem(&drop_errors, &key);
        if (err_cnt)
            __sync_fetch_and_add(err_cnt, 1);

        // Drop the packet since we can't log it
        return XDP_DROP;
    }

    // Set default router action
    evt->action = ROUTER_ACTION_FAILURE;

    // 1) Parse MAC addresses → get outer EtherType
    eth_proto = parse_hardware_addresses(&cursor, data_end, evt);
    if (!eth_proto)
        goto submit;

    // 2) Parse VLANs if present → get final encapsulated EtherType
    eth_proto = parse_vlans(&cursor, data_end, eth_proto, &s_vlan, &c_vlan);
    if (!eth_proto)
        goto submit;

    // Fill L3 inner protocol into event
    evt->l3_proto = eth_proto;

    /* Fill vlans info */
    evt->s_vlan = s_vlan;
    evt->c_vlan = c_vlan;

    /*
     * Special case: ARP packets
     * ARP is always allowed (no further parsing)
     */
    if (eth_proto == ETH_P_ARP)
    {
        evt->action = ROUTER_ACTION_PASS;
        goto submit;
    }

    // 3) Parse L4 if present -> get final encapsulated EtherType
    parse_ip_protocol(&cursor, data_end, eth_proto, evt);

    // Only IPv4/IPv6 proceed to routing
    if (evt->l3_proto != ETH_P_IP && evt->l3_proto != ETH_P_IPV6)
    {
        evt->action = ROUTER_ACTION_DROP;
        goto submit;
    }

    /* Initializing the fib lookup parameters */
    struct bpf_fib_lookup fib_params = {};

    fib_params.l4_protocol = evt->l4_proto;
    fib_params.sport = evt->src_port;
    fib_params.dport = evt->dst_port;
    // fib_params.tot_len = 0; mandatory?
    fib_params.ifindex = ctx->ingress_ifindex;

    if (evt->l3_proto == ETH_P_IP)
    {

        /* Build the IPv4 key for lookup */
        DSRKv4_t key4 = {};

        be32 dst_ip4 = *(__be32 *)evt->dst_ip;
        key4.advertised = bpf_ntohl(dst_ip4); /* match on customer-facing router IP */
        key4.protocol = evt->l4_proto;        /* L4 protocol (TCP/UDP/etc.) */
        key4.port = evt->dst_port;            /* normalized port */
        key4.svlan = evt->s_vlan;             /* outer VLAN */
        key4.cvlan = evt->c_vlan;             /* inner VLAN */

        /* Try to find a matching provider-facing path */
        DSRPv4_t *path4 = bpf_map_lookup_elem(&routing_tablev4, &key4);
        if (!path4)
        {
            evt->action = ROUTER_ACTION_NO_ROUTE;
            goto submit;
        }

        // Filter FIB request by vlan (untested)
        // fib_params.h_vlan_proto = ETH_P_8021AD;
        // fib_params.h_vlan_TCI = path4->svlan;

        fib_params.family = AF_INET;
        fib_params.ipv4_src = path4->advertised;
        fib_params.ipv4_dst = path4->target;

        //
        // note(smalpel): [DEV] ip src+dst must be rewritten & csum recalculated BEFORE the next operation!
        //
    }
    else if (evt->l3_proto == ETH_P_IPV6)
    {
        /* Not supported yet! */
        goto submit;
    }

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == BPF_FIB_LKUP_RET_SUCCESS)
    {

        // Rewrite mac addresses
        if (rewrite_mac(ctx, evt->dst_mac, fib_params.dmac) < 0)
            goto submit;

        evt->action = ROUTER_ACTION_REDIRECT;
        bpf_ringbuf_submit(evt, 0);
        return bpf_redirect(fib_params.ifindex, 0);
    }

    /* Failed to lookup -> drop */
    evt->action = ROUTER_ACTION_FIB_FAILURE;

submit:
    bpf_ringbuf_submit(evt, 0);

    if (evt->action == ROUTER_ACTION_PASS)
        return XDP_PASS;

    return XDP_PASS;
}

// Required license for eBPF programs
char _license[] SEC("license") = "GPL";