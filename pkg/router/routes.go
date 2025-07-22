package router

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

/*
DSRKv4 represents the **Dynamic Software Routing Key for IPv4 (DSRKv4)**.

This struct uniquely identifies an incoming IPv4 flow received from the customer network.
It is used as the *lookup key* in a BPF map to retrieve the corresponding provider-facing forwarding path.

A unique key is determined by the combination of:
  - Advertised IPv4 router address (interface facing the customer network)
  - Layer 4 protocol number (as per RFC 790)
  - Layer 4 port number (TCP/UDP source or destination)
  - Outer VLAN ID (S-VLAN, service-provider tag)
  - Inner VLAN ID (C-VLAN, customer tag)

Fields:

	Advertised : IPv4 address of the router interface facing the **customer network** (matches C `u32`)
	Protocol   : Layer 4 protocol identifier (TCP, UDP, ICMP, etc.) (matches C `s16`)
	Port       : Layer 4 port (source or destination, depending on flow match) (matches C `u16`)
	Svlan      : Outer VLAN ID (S-VLAN) used in provider encapsulation (matches C `u16`)
	Cvlan      : Inner VLAN ID (C-VLAN) used in customer encapsulation (matches C `u16`)

Together, these values fully describe a single IPv4 flow for routing lookup.

Binary layout:

	Total size = 4 + 2 + 2 + 2 + 2 = 12 bytes
*/
type DSRKv4 struct {
	Advertised uint32 // Router IPv4 facing the customer network
	Protocol   int16  // L4 protocol number (RFC 790)
	Port       uint16 // L4 port number (TCP/UDP/other)
	Svlan      uint16 // Outer VLAN (Service VLAN)
	Cvlan      uint16 // Inner VLAN (Customer VLAN)
}

/*
DSRPv4 represents the **Dynamic Software Route Path for IPv4 (DSRPv4)**.

This struct describes how traffic that matched a DSRKv4 key should be rewritten
and forwarded inside the provider network. It is stored as the *value* in the BPF map.

Fields:

	Advertised : IPv4 address of the router interface facing the **provider core network**
	             (i.e., the egress interface within the SP domain)
	Target     : Final translated IPv4 destination inside the provider network
	             (e.g., NAT destination or next-hop IP)
	Svlan      : Outer VLAN ID to apply on egress (Service VLAN in provider domain)
	Cvlan      : Inner VLAN ID to apply on egress (Customer VLAN inside provider domain)

In summary:
  - Matched by a **customer-facing DSRKv4 key** (including VLANs and port)
  - Produces a **provider-facing DSRPv4 path**
  - Defines how to rewrite IP and VLANs within the provider core

Binary layout:

	Total size = 4 + 4 + 2 + 2 = 12 bytes
*/
type DSRPv4 struct {
	Advertised uint32 // Router IPv4 facing the provider network
	Target     uint32 // Translated IPv4 destination in the provider network
	Svlan      uint16 // Outer VLAN (Service VLAN) for forwarding
	Cvlan      uint16 // Inner VLAN (Customer VLAN) for forwarding
}

// AddRoute4 inserts or updates an IPv4 route in the kernel BPF routing table.
//
// key:   Customer-facing lookup key (DSRKv4)
// value: Provider-facing forwarding path (DSRPv4)
func (r *Router) AddRoute4(key DSRKv4, value DSRPv4) error {

	if r.RoutingTable4 == nil {
		return fmt.Errorf("routing_tablev4 map not initialized")
	}

	// Ensure packed layout (Go struct is already 12 bytes like C)
	// but we force a little-endian encoding to match kernel expectation
	keyBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(keyBytes[0:4], key.Advertised)
	binary.LittleEndian.PutUint16(keyBytes[4:6], uint16(key.Protocol))
	binary.LittleEndian.PutUint16(keyBytes[6:8], key.Port)
	binary.LittleEndian.PutUint16(keyBytes[8:10], key.Svlan)
	binary.LittleEndian.PutUint16(keyBytes[10:12], key.Cvlan)

	valBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(valBytes[0:4], value.Advertised)
	binary.LittleEndian.PutUint32(valBytes[4:8], value.Target)
	binary.LittleEndian.PutUint16(valBytes[8:10], value.Svlan)
	binary.LittleEndian.PutUint16(valBytes[10:12], value.Cvlan)

	// Update() replaces if already exists, inserts otherwise
	if err := r.RoutingTable4.Update(keyBytes, valBytes, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to add IPv4 route: %v", err)
	}

	return nil
}

// DeleteRoute4 removes an existing IPv4 route from the kernel BPF routing table.
//
// key: Customer-facing lookup key to delete
func (r *Router) DeleteRoute4(key DSRKv4) error {

	if r.RoutingTable4 == nil {
		return fmt.Errorf("routing_tablev4 map not initialized")
	}

	keyBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(keyBytes[0:4], key.Advertised)
	binary.LittleEndian.PutUint16(keyBytes[4:6], uint16(key.Protocol))
	binary.LittleEndian.PutUint16(keyBytes[6:8], key.Port)
	binary.LittleEndian.PutUint16(keyBytes[8:10], key.Svlan)
	binary.LittleEndian.PutUint16(keyBytes[10:12], key.Cvlan)

	if err := r.RoutingTable4.Delete(keyBytes); err != nil {
		return fmt.Errorf("failed to delete IPv4 route: %v", err)
	}

	return nil
}

/*
DSRKv6 represents the **Dynamic Software Routing Key for IPv6 (DSRKv6)**.

Same concept as DSRKv4, but for IPv6 traffic. This key uniquely identifies
an incoming IPv6 flow received from the customer network.

A unique key is determined by:
  - Advertised IPv6 router address (interface facing the customer network)
  - Layer 4 protocol number (as per RFC 790)
  - Layer 4 port number (TCP/UDP source or destination)
  - Outer VLAN ID (S-VLAN, service-provider tag)
  - Inner VLAN ID (C-VLAN, customer tag)

Fields:

	Advertised : IPv6 address of the router interface facing the **customer network** (matches C `u128`, fixed 16-byte array)
	Protocol   : Layer 4 protocol identifier (TCP, UDP, ICMPv6, etc.) (matches C `s16`)
	Port       : Layer 4 port (source or destination, depending on flow match) (matches C `u16`)
	Svlan      : Outer VLAN ID (S-VLAN) used in provider encapsulation (matches C `u16`)
	Cvlan      : Inner VLAN ID (C-VLAN) used in customer encapsulation (matches C `u16`)

Binary layout:

	Total size = 16 + 2 + 2 + 2 + 2 = 24 bytes
*/
type DSRKv6 struct {
	Advertised [16]byte // IPv6 address of router interface facing the customer network
	Protocol   int16    // L4 protocol number (RFC 790)
	Port       uint16   // L4 port number (TCP/UDP/other)
	Svlan      uint16   // Outer VLAN (Service VLAN)
	Cvlan      uint16   // Inner VLAN (Customer VLAN)
}

/*
DSRPv6 represents the **Dynamic Software Route Path for IPv6 (DSRPv6)**.

This entry describes how traffic that matched a DSRKv6 key should be rewritten
and forwarded inside the provider network. It is stored as the *value* in the BPF map.

Fields:

	Advertised : IPv6 address of the router interface facing the **provider core network**
	             (i.e., the egress interface within the SP domain)
	Target     : Final translated IPv6 destination inside the provider network
	             (e.g., NAT destination or next-hop IPv6)
	Svlan      : Outer VLAN ID to apply on egress (Service VLAN in provider domain)
	Cvlan      : Inner VLAN ID to apply on egress (Customer VLAN inside provider domain)

In summary:
  - Matched by a **customer-facing DSRKv6 key** (including VLANs and port)
  - Produces a **provider-facing DSRPv6 path**
  - Defines how to rewrite IPv6 and VLANs within the provider core

Binary layout:

	Total size = 16 + 16 + 2 + 2 = 36 bytes
*/
type DSRPv6 struct {
	Advertised [16]byte // IPv6 address of router interface facing the provider network
	Target     [16]byte // Translated IPv6 destination in the provider network
	Svlan      uint16   // Outer VLAN (Service VLAN) for forwarding
	Cvlan      uint16   // Inner VLAN (Customer VLAN) for forwarding
}
