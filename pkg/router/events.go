package router

import (
	"encoding/binary"
	"fmt"
	"net"
)

const EventPackedSize = 57 // matches C sizeof(struct event)

// Must match BPF structs
type Event struct {
	L3Proto uint16   // aligned 2
	SVLAN   uint16   // aligned 2
	CVLAN   uint16   // aligned 2
	SrcMAC  [6]byte  // aligned 1
	DstMAC  [6]byte  // aligned 1
	L4Proto uint8    // aligned 1
	SrcIP   [16]byte // aligned 1
	DstIP   [16]byte // aligned 1
	SrcPort uint16   // aligned 2
	DstPort uint16   // aligned 2
	Action  uint8    // aligned 1
}

func (e Event) prettyPrint() {
	srcMAC := net.HardwareAddr(e.SrcMAC[:])
	dstMAC := net.HardwareAddr(e.DstMAC[:])

	// Detect IP version from L3Proto
	var srcIP, dstIP net.IP
	switch e.L3Proto {
	case 0x0800: // ETH_P_IP (IPv4)
		srcIP = net.IP(e.SrcIP[:4])
		dstIP = net.IP(e.DstIP[:4])
	case 0x86DD: // ETH_P_IPV6
		srcIP = net.IP(e.SrcIP[:16])
		dstIP = net.IP(e.DstIP[:16])
	default:
		srcIP = net.IP(nil)
		dstIP = net.IP(nil)
	}

	// Human-friendly L4 protocol name
	var l4 string
	switch e.L4Proto {
	case 6:
		l4 = "TCP"
	case 17:
		l4 = "UDP"
	default:
		l4 = fmt.Sprintf("0x%x", e.L4Proto)
	}

	fmt.Println("==== Event ====")
	fmt.Printf("L3 Proto: 0x%04x  (%s)\n", e.L3Proto, l3ProtoName(e.L3Proto))
	fmt.Printf("SVLAN: %d, CVLAN: %d\n", e.SVLAN, e.CVLAN)
	fmt.Printf("Src MAC: %s -> Dst MAC: %s\n", srcMAC, dstMAC)

	if srcIP != nil {
		fmt.Printf("Src IP: %s:%d -> Dst IP: %s:%d\n", srcIP, e.SrcPort, dstIP, e.DstPort)
	} else {
		fmt.Printf("No IP parsed (non-IP traffic)\n")
	}

	fmt.Printf("L4 Proto: %s\n", l4)
	fmt.Printf("Action: %s (%d)\n", actionName(e.Action), e.Action)
	fmt.Println()
}

func l3ProtoName(proto uint16) string {
	switch proto {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x0806:
		return "ARP"
	default:
		return fmt.Sprintf("0x%04x", proto)
	}
}

func actionName(a uint8) string {
	switch a {
	case 0:
		return "DROP"
	case 1:
		return "REDIRECT"
	case 2:
		return "PASS"
	case 3:
		return "NO_ROUTE"
	case 4:
		return "FAILURE"
	case 5:
		return "FIB_FAILURE"
	case 6:
		return "TTL_EXPIRED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", a)
	}
}

func parseEvent(raw [EventPackedSize]byte) Event {
	var evt Event

	evt.L3Proto = binary.LittleEndian.Uint16(raw[0:2])
	evt.SVLAN = binary.LittleEndian.Uint16(raw[2:4])
	evt.CVLAN = binary.LittleEndian.Uint16(raw[4:6])

	copy(evt.SrcMAC[:], raw[6:12])
	copy(evt.DstMAC[:], raw[12:18])

	evt.L4Proto = raw[18]

	copy(evt.SrcIP[:], raw[19:35])
	copy(evt.DstIP[:], raw[35:51])

	evt.SrcPort = binary.LittleEndian.Uint16(raw[51:53])
	evt.DstPort = binary.LittleEndian.Uint16(raw[53:55])

	evt.Action = raw[55] // ✅ CORRECT offset for C packed struct

	return evt
}
