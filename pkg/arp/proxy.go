package arp

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ethernet"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// Proxy is responsible for sending periodic Gratuitous ARP Requests
// on a given network interface for a set of VLAN-tagged IP/MAC announcements.
type Proxy struct {
	raw           map[string]int           // Map of ifname -> fd
	announcements map[string]*Announcement // Map of IP -> Announcement
}

// NewProxy initializes a Proxy instance for the specified network interface name.
// It opens a raw AF_PACKET socket that can be used to send Ethernet frames.
func NewProxy() *Proxy {
	return &Proxy{
		raw:           map[string]int{},
		announcements: map[string]*Announcement{},
	}
}

// Listen starts an infinite loop that periodically sends VLAN-tagged Gratuitous ARP Requests
// for all configured announcements. It broadcasts ARP Requests so other hosts/switches
// on the same VLAN learn the IP->MAC mapping.
func (arp *Proxy) Listen(interval time.Duration) error {

	// Announce periodically
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {

		if err := arp.prepareSockets(); err != nil {
			return err
		}

		for _, ann := range arp.announcements {

			// Prepare sockaddr for sending frames out the interface
			sll := &unix.SockaddrLinklayer{
				Protocol: htons(unix.ETH_P_ALL),
				Ifindex:  ann.ifidx,
				Halen:    6,
			}

			// Build a Gratuitous ARP Request payload: who-has <IP>? Tell <IP>
			arpPayload := buildARPRequest(ann.MAC, ann.IP)

			// Build VLAN header (802.1Q tag + ARP ethertype)
			vlanHeader := []byte{
				byte(ann.VLAN >> 8), byte(ann.VLAN & 0xff), // VLAN ID
				byte(ethernet.EtherTypeARP >> 8), byte(ethernet.EtherTypeARP & 0xff),
			}

			// Wrap ARP payload in a VLAN-tagged Ethernet frame
			frame := &ethernet.Frame{
				Destination: ethernet.Broadcast,
				Source:      ann.MAC,
				EtherType:   ethernet.EtherTypeVLAN,
				Payload:     append(vlanHeader, arpPayload...),
			}

			// Marshal Ethernet frame into raw bytes
			rawFrame, err := frame.MarshalBinary()
			if err != nil {
				klog.Infof("Failed to marshal Ethernet frame for %s: %v", ann.IP, err)
				continue
			}

			// Send VLAN-tagged Gratuitous ARP Request
			if err := unix.Sendto(arp.raw[ann.ifname], rawFrame, 0, sll); err != nil {
				klog.Infof("Failed to send VLAN %d Gratuitous ARP for %s: %v", ann.VLAN, ann.IP, err)
				continue
			}

			klog.V(5).Infof("Announced VLAN %d Gratuitous ARP Request: who-has %s? tell %s (MAC %s)", ann.VLAN, ann.IP, ann.IP, ann.MAC)
		}

		// Wait for the next tick before re-announcing
		<-ticker.C
	}
}

// Prepare raw ethernet sockets for ARP
func (arp *Proxy) prepareSockets() error {

	used := map[string]bool{}

	for _, ann := range arp.announcements {

		used[ann.ifname] = true

		// Checks if the raw socket already exists
		if _, exists := arp.raw[ann.ifname]; exists {
			continue
		}

		// Open raw AF_PACKET socket for sending Ethernet frames.
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if err != nil {
			return fmt.Errorf("failed to open raw socket: %v", err)
		}

		arp.raw[ann.ifname] = fd
	}

	// Close unused sockets
	for ifname, fd := range arp.raw {
		if _, exists := used[ifname]; !exists {
			unix.Close(fd)
		}
	}

	return nil
}

// buildARPRequest creates a standard ARP Request payload.
// It sets sender MAC/IP, and uses the same IP as the target (Gratuitous ARP Request).
func buildARPRequest(mac net.HardwareAddr, ip netip.Addr) []byte {

	buf := make([]byte, 28)

	// Hardware type: Ethernet (1)
	buf[0], buf[1] = 0x00, 0x01

	// Protocol type: IPv4 (0x0800)
	buf[2], buf[3] = 0x08, 0x00

	// Hardware size: 6 bytes, Protocol size: 4 bytes
	buf[4], buf[5] = 6, 4

	// Opcode: 1 (request)
	buf[6], buf[7] = 0x00, 0x01

	// Sender MAC
	copy(buf[8:14], mac)

	// Sender IP
	copy(buf[14:18], ip.AsSlice())

	// Target MAC = 00:00:00:00:00:00
	// Target IP = same as sender IP (Gratuitous)
	copy(buf[24:28], ip.AsSlice())

	return buf
}

// htons converts a 16-bit value from host byte order to network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
