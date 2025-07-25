package router

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"k8s.io/klog/v2"
)

// Router represents a running eBPF-based software router.
// It manages:
//   - The source network interface where XDP is attached
//   - The destination interface for forwarding
//   - Loaded eBPF programs and maps (routing tables, events, drops events)
type Router struct {

	// Running interface name and index
	ifname string
	ifidx  int
	ifmac  net.HardwareAddr

	// eBPF program and hashmaps
	XdpProg        *ebpf.Program `ebpf:"xdp_prog_main"`           // Main XDP NAT/forwarding program
	HadwareAddress *ebpf.Map     `ebpf:"router_hardware_address"` // Router Hadware Address (MAC)
	RoutingTable4  *ebpf.Map     `ebpf:"routing_tablev4"`         // Dynamic software routing table for IPv4 lookups
	RoutingTable6  *ebpf.Map     `ebpf:"routing_tablev6"`         // Dynamic software routing table for IPv6 lookups
	Events         *ebpf.Map     `ebpf:"events_rb"`               // Logging events buffer
	Drops          *ebpf.Map     `ebpf:"drop_errors"`             // Emergency drops
}

func NewRouter(ifname string) (*Router, error) {

	// Resolve the source interface index
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %v", ifname, err)
	}

	r := &Router{
		ifname: iface.Name,
		ifidx:  iface.Index,
		ifmac:  iface.HardwareAddr,
	}

	// Load the embedded eBPF program and maps
	spec, err := loadBPFSpecFromEmbed()
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded eBPF spec: %v", err)
	}

	// Assign program and maps to Router fields
	if err := spec.LoadAndAssign(r, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %v", err)
	}

	return r, nil

}

func (r *Router) Listen() error {

	defer r.XdpProg.Close()

	defer r.HadwareAddress.Close()
	defer r.Events.Close()
	defer r.Drops.Close()

	defer r.RoutingTable4.Close()
	defer r.RoutingTable6.Close()

	// Attach XDP program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   r.XdpProg,
		Interface: r.ifidx,
	})

	if err != nil {
		return fmt.Errorf("failed to attach XDP on %s: %v", r.ifname, err)
	}

	defer l.Close()

	// Open ring buffer for events
	events, err := ringbuf.NewReader(r.Events)
	if err != nil {
		return fmt.Errorf("ringbuf.NewReader failed: %v", err)
	}

	defer events.Close()

	// Inject the hadware address (mac) of the router interface
	var mkey uint32 = 0
	if err := r.HadwareAddress.Put(mkey, r.ifmac); err != nil {
		return fmt.Errorf("failed to set router MAC: %w", err)
	}

	// Setup signal handling to allow graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	done := make(chan struct{})

	// Goroutine reading ringbuf
	go func() {

		defer close(done) // notify main when goroutine exits

		for {
			record, err := events.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					// Reader closed, stop gracefully
					return
				}
				klog.Warningf("Events perf reader error: %v", err)
				continue
			}

			if len(record.RawSample) < EventPackedSize {
				klog.Warningf("Invalid sample size: got %d, expected %d", len(record.RawSample), EventPackedSize)
				continue
			}

			var raw [EventPackedSize]byte
			copy(raw[:], record.RawSample[:EventPackedSize])

			evt := parseEvent(raw)
			evt.prettyPrint()
		}
	}()

	// Wait until Ctrl+C is pressed
	<-stop
	klog.Warning("Stopping listener...")

	// Close perf reader, which will unblock goroutine
	events.Close()

	// Wait for perf reader goroutine to finish
	<-done
	klog.Warning("Perf reader stopped.")

	return nil
}
