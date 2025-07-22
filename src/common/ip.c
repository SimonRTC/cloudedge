#pragma once

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

#include "types.h"

static __always_inline void parse_ip_protocol(void **cursor, void *data_end, __u16 proto, struct event *evt)
{
    // Reset fields
    __builtin_memset(evt->src_ip, 0, sizeof(evt->src_ip));
    __builtin_memset(evt->dst_ip, 0, sizeof(evt->dst_ip));
    evt->src_port = 0;
    evt->dst_port = 0;
    evt->l4_proto = 0;

    // --- IPv4 ---
    if (proto == ETH_P_IP)
    {
        struct iphdr *ip = *cursor;
        if ((void *)(ip + 1) > data_end)
            return;

        // Copy IPv4 addresses
        __builtin_memcpy(evt->src_ip, &ip->saddr, 4);
        __builtin_memcpy(evt->dst_ip, &ip->daddr, 4);
        evt->l4_proto = ip->protocol; // TCP/UDP/ICMP

        // Compute total IPv4 header length (ihl * 4)
        __u8 ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(*ip))
            return;

        if ((void *)ip + ip_hdr_len > data_end)
            return;

        // Advance cursor past IPv4 header
        *cursor = (void *)ip + ip_hdr_len;

        // --- L4: TCP ---
        if (ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = *cursor;
            if ((void *)(tcp + 1) > data_end)
                return;

            evt->src_port = bpf_ntohs(tcp->source);
            evt->dst_port = bpf_ntohs(tcp->dest);

            // --- L4: UDP ---
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp = *cursor;
            if ((void *)(udp + 1) > data_end)
                return;

            evt->src_port = bpf_ntohs(udp->source);
            evt->dst_port = bpf_ntohs(udp->dest);
        }
    }

    // --- IPv6 ---
    else if (proto == ETH_P_IPV6)
    {
        struct ipv6hdr *ip6 = *cursor;
        if ((void *)(ip6 + 1) > data_end)
            return;

        __builtin_memcpy(evt->src_ip, &ip6->saddr, sizeof(ip6->saddr));
        __builtin_memcpy(evt->dst_ip, &ip6->daddr, sizeof(ip6->daddr));
        evt->l4_proto = ip6->nexthdr;

        // Advance cursor past IPv6 header
        *cursor = (void *)ip6 + sizeof(*ip6);

        if (ip6->nexthdr == IPPROTO_TCP)
        {
            struct tcphdr *tcp = *cursor;
            if ((void *)(tcp + 1) > data_end)
                return;

            evt->src_port = bpf_ntohs(tcp->source);
            evt->dst_port = bpf_ntohs(tcp->dest);
        }
        else if (ip6->nexthdr == IPPROTO_UDP)
        {
            struct udphdr *udp = *cursor;
            if ((void *)(udp + 1) > data_end)
                return;

            evt->src_port = bpf_ntohs(udp->source);
            evt->dst_port = bpf_ntohs(udp->dest);
        }
    }
}

static __always_inline int rewrite_ipv4(struct xdp_md *ctx, u32 offset, u32 new_src_ip, u32 new_dst_ip)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *iph = data + offset;

    if ((void *)(iph + 1) > data_end)
        return -1;

    if (new_src_ip)
        iph->saddr = new_src_ip;
    if (new_dst_ip)
        iph->daddr = new_dst_ip;

    // Reset checksum before recomputing
    iph->check = 0;

    // Compute IPv4 header checksum (20 bytes, no options)
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)iph;

#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*iph) >> 1); i++)
    {
        sum += (__u32)ptr[i];
    }

    // Fold to 16 bits
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    iph->check = ~sum;

    return 0;
}

static __always_inline void ipv4_l4_checksum(struct xdp_md *ctx, u32 ip_offset, u8 l4_proto, be32 old_saddr, be32 new_saddr, be32 old_daddr, be32 new_daddr)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct iphdr *iph = data + ip_offset;
    if ((void *)(iph + 1) > data_end)
        return;

    __u32 ihl_len = iph->ihl * 4;
    void *l4h = (void *)iph + ihl_len;
    if (l4h + sizeof(struct tcphdr) > data_end) // minimal L4 header
        return;

    __u16 *check_field = NULL;
    if (l4_proto == IPPROTO_TCP)
    {
        struct tcphdr *tcph = l4h;
        check_field = &tcph->check;
    }
    else if (l4_proto == IPPROTO_UDP)
    {
        struct udphdr *udph = l4h;
        check_field = &udph->check;
        if (*check_field == 0) // UDP checksum optional → skip
            return;
    }
    else
    {
        return; // other protocols no fix needed
    }

    // Load old checksum
    __u16 old_csum = *check_field;

    // Calculate incremental delta from pseudo-header diff
    __u32 sum = 0;
    sum += (~(__u16)(old_saddr >> 16)) & 0xFFFF;
    sum += (~(__u16)(old_saddr & 0xFFFF)) & 0xFFFF;
    sum += (new_saddr >> 16) & 0xFFFF;
    sum += new_saddr & 0xFFFF;

    sum += (~(__u16)(old_daddr >> 16)) & 0xFFFF;
    sum += (~(__u16)(old_daddr & 0xFFFF)) & 0xFFFF;
    sum += (new_daddr >> 16) & 0xFFFF;
    sum += new_daddr & 0xFFFF;

    // Fold delta into checksum
    __u32 new_csum = ~old_csum & 0xFFFF;
    new_csum += sum;
    new_csum = (new_csum & 0xFFFF) + (new_csum >> 16);
    new_csum = (new_csum & 0xFFFF) + (new_csum >> 16);
    new_csum = ~new_csum;

    *check_field = (__u16)new_csum;
}
