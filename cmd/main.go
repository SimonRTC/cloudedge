package main

import (
	"encoding/binary"
	"net"
	"os"
	"time"

	"github.com/SimonRTC/cloudedge/pkg/arp"
	"github.com/SimonRTC/cloudedge/pkg/router"
	"k8s.io/klog/v2"
)

func main() {

	if len(os.Args) < 2 {
		klog.Fatalf("Usage: %s <iface>", os.Args[0])
	}

	iface := os.Args[1]

	// Create the ARP proxy
	proxy := arp.NewProxy()

	// Create the eBPF XDP router instance
	r, err := router.NewRouter(iface)
	if err != nil {
		klog.Fatal(err)
	}

	// Sample network routes
	/*
		ann, err := arp.CreateNativeAnnouncement(iface, net.ParseIP("10.0.0.10"), 10)
		if err != nil {
			klog.Fatal(err)
		}

		proxy.AddAnnouncement(ann)
	*/

	// Convert IPv4 to uint32 in little-endian
	advIP := binary.LittleEndian.Uint32(net.ParseIP("10.0.0.10").To4())
	providerAdv := binary.LittleEndian.Uint32(net.ParseIP("192.168.100.10").To4())    // example provider-facing
	providerTarget := binary.LittleEndian.Uint32(net.ParseIP("192.168.200.50").To4()) // example NAT target

	if err := r.AddRoute4(router.DSRKv4{
		Advertised: advIP,                                       // 10.0.0.10
		Protocol:   6,                                           // TCP = 6
		Port:       binary.BigEndian.Uint16([]byte{0x00, 0x50}), // HTTP port
		Svlan:      0,                                           // No outer VLAN
		Cvlan:      10,                                          // Customer VLAN 10
	}, router.DSRPv4{
		Advertised: providerAdv,    // router IP facing provider core
		Target:     providerTarget, // NAT or next-hop
		Svlan:      0,              // no extra VLAN on provider side
		Cvlan:      666,            // no inner VLAN
	}); err != nil {
		klog.Fatal(err)
	}

	if err := r.AddRoute4(router.DSRKv4{
		Advertised: advIP, // 10.0.0.10
		Protocol:   0,     // ARP = 0
		Port:       0,     // ARP = 0
		Svlan:      0,     // No outer VLAN
		Cvlan:      10,    // Customer VLAN 10
	}, router.DSRPv4{}); err != nil {
		klog.Fatal(err)
	}

	// Start the ARP announcer loop
	go func() {
		klog.Info("Starting ARP proxy on each announced interfaces.")
		if err := proxy.Listen(5 * time.Second); err != nil {
			klog.Fatalf("ARP proxy exited with error: %v", err)
		}
	}()

	klog.Info("Starting eBPF XDP router.")
	if err := r.Listen(); err != nil {
		klog.Fatal(err)
	}
}
