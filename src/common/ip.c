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
