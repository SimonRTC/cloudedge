#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include "types.h"

/*
 * parse_arp_request - Validate and extract an ARP request payload.
 *
 * @arp_start: pointer to the beginning of the ARP header in the packet.
 * @data_end: pointer to the end of the packet buffer.
 * @arp_out: output pointer to the parsed ARP header.
 * @sha: output pointer to the sender hardware address (MAC).
 * @sip: output pointer to the sender protocol address (IPv4).
 * @tha: output pointer to the target hardware address (MAC).
 * @tip: output pointer to the target protocol address (IPv4).
 *
 * Return:
 *  TRUE if a valid Ethernet+IPv4 ARP request was parsed,
 *  FALSE if the packet is invalid or not a supported ARP.
 *
 * This function ensures the ARP header and payload are fully
 * contained within the packet bounds before accessing any fields.
 */
static __always_inline bool_t parse_arp_request(void *arp_start, void *data_end, struct arp_hdr **arp_out, u8 **sha, be32 **sip, u8 **tha, be32 **tip)
{
    /* Initial position at the ARP header */
    void *pos = arp_start;
    void *next = pos + sizeof(struct arp_hdr);

    /* Ensure the ARP header fits in the packet */
    if (next > data_end)
        return FALSE;

    /* Cast the ARP header and advance cursor */
    struct arp_hdr *arp = pos;
    pos = next;

    /*
     * Validate ARP header fields:
     *  - Hardware type must be Ethernet (1)
     *  - Protocol type must be IPv4 (0x0800)
     *  - Hardware length must be 6 bytes (MAC)
     *  - Protocol length must be 4 bytes (IPv4)
     */
    if (arp->ar_hrd != bpf_htons(1) ||        /* must be Ethernet */
        arp->ar_pro != bpf_htons(ETH_P_IP) || /* must be IPv4 */
        arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
        return FALSE;

    /*
     * Validate that the ARP payload fits in the packet.
     * ARP payload size = SHA(6) + SPA(4) + THA(6) + TPA(4) = 20 bytes.
     */
    next = pos + (ETH_ALEN + 4 + ETH_ALEN + 4);
    if (next > data_end)
        return FALSE;

    /* Extract ARP payload pointers */
    u8 *p = pos;
    *sha = p;                /* Sender hardware address (MAC) */
    *sip = (be32 *)(p + 6);  /* Sender protocol address (IPv4) */
    *tha = p + 10;           /* Target hardware address (MAC) */
    *tip = (be32 *)(p + 16); /* Target protocol address (IPv4) */

    /* Return the parsed ARP header */
    *arp_out = arp;
    return TRUE;
}

/*
 * arp_build_reply - Build an ARP reply in-place for a given ARP request.
 *
 * @ctx: XDP context containing packet data and bounds.
 * @vlan_offset: offset after VLAN tags (not used directly here).
 * @arp: pointer to ARP header within the packet.
 * @sha: pointer to sender hardware address field in ARP payload.
 * @sip: pointer to sender protocol address field in ARP payload.
 * @tha: pointer to target hardware address field in ARP payload.
 * @tip: pointer to target protocol address field in ARP payload.
 * @my_mac: pointer to the router MAC address (6 bytes).
 *
 * This function:
 *  - Swaps the Ethernet MACs so the reply goes back to the original sender.
 *  - Sets ARP opcode to reply (2).
 *  - Sets ARP sender fields (SHA + SPA) to the router MAC and IP.
 *  - Sets ARP target fields (THA + TPA) to the original sender MAC and IP.
 *
 * It performs bounds checking before modifying the Ethernet header.
 */
static __always_inline void arp_build_reply(struct xdp_md *ctx, __u32 vlan_offset, struct arp_hdr *arp, u8 *sha, be32 *sip, u8 *tha, be32 *tip, const u8 my_mac[6])
{
    /* Get packet data and bounds */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Ensure we can safely swap Ethernet MAC addresses (requires 12 bytes) */
    if (data + 12 > data_end)
        return;

    /* Save original sender MAC and IP */
    u8 orig_sha[6];
    __builtin_memcpy(orig_sha, sha, ETH_ALEN);
    be32 orig_sip = *sip;

    /*
     * Swap Ethernet header MAC addresses:
     *  - Destination MAC becomes original source MAC
     *  - Source MAC becomes our router MAC
     * VLAN tags remain untouched as they are after offset 12.
     */
    __builtin_memcpy(data, data + 6, ETH_ALEN);   /* dst = original src */
    __builtin_memcpy(data + 6, my_mac, ETH_ALEN); /* src = our router MAC */

    /*
     * Update ARP header:
     *  - Set opcode to ARP reply
     *  - Sender fields become router MAC and router IP
     *  - Target fields become original sender MAC and IP
     */
    arp->ar_op = bpf_htons(2); /* ARP opcode = reply */

    __builtin_memcpy(sha, my_mac, ETH_ALEN); /* Sender hardware = router MAC */
    *sip = *tip;                             /* Sender protocol = router IP */

    __builtin_memcpy(tha, orig_sha, ETH_ALEN); /* Target hardware = original sender MAC */
    *tip = orig_sip;                           /* Target protocol = original sender IP */
}
