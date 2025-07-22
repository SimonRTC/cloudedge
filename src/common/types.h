#pragma once

#include <linux/types.h>

/* Unsigned fixed-width integer aliases */
typedef __uint128_t u128; /* 128-bit unsigned integer */
typedef __u64 u64;        /* 64-bit unsigned integer */
typedef __u32 u32;        /* 32-bit unsigned integer */
typedef __u16 u16;        /* 16-bit unsigned integer */
typedef __u8 u8;          /* 8-bit unsigned integer */

/* Signed fixed-width integer aliases */
typedef __s64 s64; /* 64-bit signed integer */
typedef __s32 s32; /* 32-bit signed integer */
typedef __s16 s16; /* 16-bit signed integer */

/* Big-endian integer aliases (network byte order) */
typedef __be64 be64; /* 64-bit big-endian */
typedef __be32 be32; /* 32-bit big-endian */
typedef __be16 be16; /* 16-bit big-endian */

typedef u8 bool_t; /* 0 = false, non-zero = true */
#define TRUE 1
#define FALSE 0

#ifndef AF_INET
#define AF_INET 2 /* IPv4 socket family */
#endif

#ifndef AF_INET6
#define AF_INET6 10 /* IPv6 socket family */
#endif

struct pkt_cursor
{
    void *pos; // current parsing position
    void *end; // packet end
};

/* VLAN header format used for parsing stacked VLANs */
struct vlan_hdr
{
    be16 h_vlan_TCI;                /* VLAN Tag Control Identifier (Priority + VLAN ID) */
    be16 h_vlan_encapsulated_proto; /* Next encapsulated ethertype */
};

/*
 * Dynamic Software Routing Key for IPv4 (DSRKv4)
 *
 * **Customer-facing lookup key.**
 *
 * This key uniquely identifies an incoming IPv4 flow received from the
 * customer network. It is used as the lookup key in a BPF map to retrieve
 * the corresponding provider-facing forwarding path.
 *
 * A unique key is defined by the combination of:
 *   - advertised IPv4 router address (interface facing the customer network)
 *   - Layer 4 protocol number (as per RFC 790)
 *   - Layer 4 port number (TCP/UDP source or destination)
 *   - outer VLAN ID (S-VLAN, service-provider tag)
 *   - inner VLAN ID (C-VLAN, customer tag)
 *
 * Fields:
 *   advertised : IPv4 address of the router interface facing the **customer network**
 *   protocol   : Layer 4 protocol identifier (TCP, UDP, ICMP, etc.)
 *   port       : Layer 4 port (source or destination, depending on flow match)
 *   svlan      : Outer VLAN ID (S-VLAN) used in provider encapsulation
 *   cvlan      : Inner VLAN ID (C-VLAN) used in customer encapsulation
 *
 * Together, these values fully describe a single IPv4 flow for routing lookup.
 */
struct DSRKv4
{
    u32 advertised; /* Router IPv4 facing the customer network */
    s16 protocol;   /* L4 protocol number (RFC 790) */
    u16 port;       /* L4 port number (TCP/UDP/other) */
    u16 svlan;      /* Outer VLAN (Service VLAN) */
    u16 cvlan;      /* Inner VLAN (Customer VLAN) */
} __attribute__((packed)) typedef DSRKv4_t;

/*
 * Dynamic Software Route Path for IPv4 (DSRPv4)
 *
 * **Provider-facing forwarding path.**
 *
 * This entry describes how traffic that matched a DSRKv4 key should be
 * rewritten and forwarded inside the provider network. It can optionally
 * rewrite VLAN tags before forwarding.
 *
 * Fields:
 *   advertised : IPv4 address of the router interface facing the **provider core network**
 *                (i.e., the egress interface within the SP domain)
 *   target     : Final translated IPv4 destination inside the provider network
 *                (e.g., NAT destination or next-hop IP)
 *   svlan      : Outer VLAN ID to apply on egress (Service VLAN in provider domain)
 *   cvlan      : Inner VLAN ID to apply on egress (Customer VLAN inside provider domain)
 *
 * In summary:
 *   - Matched by a **customer-facing DSRKv4 key** (including VLANs and port)
 *   - Produces a **provider-facing DSRPv4 path**
 *   - Defines how to rewrite IP and VLANs within the provider core
 */
struct DSRPv4
{
    u32 advertised; /* Router IPv4 facing the provider network */
    u32 target;     /* Translated IPv4 destination in the provider network */
    u16 svlan;      /* Outer VLAN (Service VLAN) for forwarding */
    u16 cvlan;      /* Inner VLAN (Customer VLAN) for forwarding */
} __attribute__((packed)) typedef DSRPv4_t;

/*
 * Dynamic Software Routing Key for IPv6 (DSRKv6)
 *
 * **Customer-facing lookup key for IPv6 flows.**
 *
 * Same concept as DSRKv4, but for IPv6 traffic. This key uniquely identifies
 * an incoming IPv6 flow received from the customer network.
 *
 * A unique key is defined by:
 *   - advertised IPv6 router address (interface facing the customer network)
 *   - Layer 4 protocol number (as per RFC 790)
 *   - Layer 4 port number (TCP/UDP source or destination)
 *   - outer VLAN ID (S-VLAN)
 *   - inner VLAN ID (C-VLAN)
 *
 * Fields:
 *   advertised : IPv6 address of the router interface facing the **customer network**
 *   protocol   : Layer 4 protocol identifier (TCP, UDP, ICMPv6, etc.)
 *   port       : Layer 4 port (source or destination, depending on flow match)
 *   svlan      : Outer VLAN ID (S-VLAN)
 *   cvlan      : Inner VLAN ID (C-VLAN)
 *
 * Combined, these fields uniquely identify a single IPv6 flow for routing lookup.
 */
struct DSRKv6
{
    u128 advertised; /* Router IPv6 facing the customer network */
    s16 protocol;    /* L4 protocol number (RFC 790) */
    u16 port;        /* L4 port number (TCP/UDP/other) */
    u16 svlan;       /* Outer VLAN (Service VLAN) */
    u16 cvlan;       /* Inner VLAN (Customer VLAN) */
} __attribute__((packed)) typedef DSRKv6_t;

/*
 * Dynamic Software Route Path for IPv6 (DSRPv6)
 *
 * **Provider-facing forwarding path for IPv6 flows.**
 *
 * This entry describes how traffic that matched a DSRKv6 key should be
 * rewritten and forwarded inside the provider network. It can also
 * rewrite VLAN tags before forwarding.
 *
 * Fields:
 *   advertised : IPv6 address of the router interface facing the **provider core network**
 *                (i.e., the egress interface within the SP domain)
 *   target     : Final translated IPv6 destination inside the provider network
 *                (e.g., NAT destination or next-hop IPv6)
 *   svlan      : Outer VLAN ID to apply on egress (Service VLAN in provider domain)
 *   cvlan      : Inner VLAN ID to apply on egress (Customer VLAN inside provider domain)
 *
 * In summary:
 *   - Matched by a **customer-facing DSRKv6 key** (including VLANs and port)
 *   - Produces a **provider-facing DSRPv6 path**
 *   - Defines how to rewrite IPv6 and VLANs within the provider core
 */
struct DSRPv6
{
    u128 advertised; /* Router IPv6 facing the provider network */
    u128 target;     /* Translated IPv6 destination in the provider network */
    u16 svlan;       /* Outer VLAN (Service VLAN) for forwarding */
    u16 cvlan;       /* Inner VLAN (Customer VLAN) for forwarding */
} __attribute__((packed)) typedef DSRPv6_t;

/*
 * Event actions
 *
 * These constants define the possible actions that can be applied to an event.
 *
 * ROUTER_ACTION_DROP           : Packet is dropped and not forwarded.
 * ROUTER_ACTION_REDIRECT       : Packet is redirected to another interface or path.
 * ROUTER_ACTION_PASS           : Packet is allowed without modification (bypass).
 * ROUTER_ACTION_NO_ROUTE       : No route and packet was dropped.
 * ROUTER_ACTION_FAILURE        : Packet processing failed and was dropped.
 * ROUTER_ACTION_FIB_FAILURE    : Resolving failed and packet was dropped.
 * ROUTER_ACTION_TTL_EXPIRED    : Packet expired and packet was dropped.
 */
#define ROUTER_ACTION_DROP 0        /* Drop the packet */
#define ROUTER_ACTION_REDIRECT 1    /* Redirect to another interface or next hop */
#define ROUTER_ACTION_PASS 2        /* Accept without changes */
#define ROUTER_ACTION_NO_ROUTE 3    /* No route available fro this packet */
#define ROUTER_ACTION_FAILURE 4     /* Drop due to a processing failure */
#define ROUTER_ACTION_FIB_FAILURE 5 /* Drop due to a next-hop resolving failure */
#define ROUTER_ACTION_TTL_EXPIRED 6 /* Drop due to a expired packet TTL  */

/*
 * event
 *
 * Represents a single network event observed or processed by the data plane.
 * It contains metadata describing the flow, including protocol, VLAN tags,
 * Layer 2 MAC addresses, Layer 3/4 addressing, and the resulting action.
 *
 * Fields:
 *
 *   protocol  : Layer 4 protocol number (RFC 790) such as TCP, UDP, ICMP
 *
 *   s_vlan    : Outer VLAN ID (Service VLAN)
 *   c_vlan    : Inner VLAN ID (Customer VLAN)
 *
 *   src_mac   : Source MAC address (Ethernet layer)
 *   dst_mac   : Destination MAC address (Ethernet layer)
 *
 *   src_ip    : Source IPv4 address (valid if protocol is IPv4)
 *   src_ip6   : Source IPv6 address (valid if protocol is IPv6)
 *   src_port  : Source Layer 4 port (TCP/UDP/other)
 *
 *   dst_ip    : Destination IPv4 address (valid if protocol is IPv4)
 *   dst_ip6   : Destination IPv6 address (valid if protocol is IPv6)
 *   dst_port  : Destination Layer 4 port (TCP/UDP/other)
 *
 *   action    : Resulting action for this event (one of ROUTER_ACTION_*)
 *
 * Notes:
 * - For IPv4 packets, only src_ip and dst_ip are used; src_ip6/dst_ip6 remain unused.
 * - For IPv6 packets, only src_ip6 and dst_ip6 are used; src_ip/dst_ip remain unused.
 * - VLAN fields allow correlation of events in double-tagged (QinQ) scenarios.
 * - MAC addresses provide Layer 2 context, useful for tracing and debugging.
 */
struct event
{
    __u16 l3_proto; // ETH_P_IP=0x0800, ETH_P_IPV6=0x86DD, ETH_P_ARP=0x0806...
    __u16 s_vlan;   // Outer VLAN (Service VLAN)
    __u16 c_vlan;   // Inner VLAN (Customer VLAN)

    __u8 src_mac[6]; // Source MAC address
    __u8 dst_mac[6]; // Destination MAC address

    __u8 l4_proto; // IPPROTO_TCP=6, IPPROTO_UDP=17

    __u8 src_ip[16]; // IPv4 = first 4 bytes used, IPv6 = full 16 bytes
    __u8 dst_ip[16]; // Same as above

    __u16 src_port; // TCP/UDP source port
    __u16 dst_port; // TCP/UDP destination port

    __u8 action; // 0=DROP, 1=REDIRECT, 2=ALLOW, etc.

    __u8 _pad; /* <-- extra pad to align to 58 like Go */
} __attribute__((packed)) typedef event_t;
