package arp

import (
	"fmt"
	"net"
	"net/netip"
)

type Announcement struct {
	ifname string
	ifidx  int
	IP     netip.Addr
	MAC    net.HardwareAddr
	VLAN   uint16
}

// Builds an Announcement from separate elements
func CreateNativeAnnouncement(ifname string, ip net.IP, vlan uint16) (*Announcement, error) {

	ip4, err := netip.ParseAddr(ip.To4().String())
	if err != nil {
		return nil, fmt.Errorf("invalid IPv4 address %s: %v", ip.To4().String(), err)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %v", ifname, err)
	}

	if vlan > 4095 {
		return nil, fmt.Errorf("vlan id %d is invalid, must be 0-4095", vlan)
	}

	return &Announcement{
		ifname: ifname,
		ifidx:  iface.Index,
		IP:     ip4,
		MAC:    iface.HardwareAddr,
		VLAN:   vlan,
	}, nil
}

// AddAnnouncement adds or updates an announcement in the proxy.
func (arp *Proxy) AddAnnouncement(ann *Announcement) {
	arp.announcements[keyForAnnouncement(ann)] = ann
}

// DelAnnouncement removes a specific announcement from the proxy.
func (arp *Proxy) DelAnnouncement(ann *Announcement) error {
	k := keyForAnnouncement(ann)
	if _, exists := arp.announcements[k]; exists {
		delete(arp.announcements, k)
		return nil
	} else {
		return fmt.Errorf("announcement not found")
	}
}

// keyForAnnouncement generates a unique string key for the given Announcement.
func keyForAnnouncement(ann *Announcement) string {
	return fmt.Sprintf("%s|%s|%s|%d", ann.ifname, ann.IP.String(), ann.MAC.String(), ann.VLAN)
}
