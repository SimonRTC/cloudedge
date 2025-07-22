package router

import (
	"bytes"
	"embed"
	"fmt"

	"github.com/cilium/ebpf"
)

// bpfFS is an embedded filesystem that contains the compiled eBPF object.
//
// The directive below embeds the prebuilt BPF program `xdp_nat.bpf.o`
// directly into the Go binary at compile time.
//
// This removes the need to ship external files and ensures
// the correct version of the BPF program is always available.
//
//go:embed bpf/router.bpf.o
var bpfFS embed.FS

// loadBPFSpecFromEmbed loads the embedded eBPF object and returns its parsed spec.
//
// What this function does:
//
//  1. Reads the `xdp_nat.bpf.o` bytes from the embedded filesystem.
//  2. Parses the ELF format using cilium/ebpf.
//  3. Produces a *ebpf.CollectionSpec, which describes the maps and programs.
//
// Returns:
//   - *ebpf.CollectionSpec: parsed representation of maps and programs
//   - error: if reading or parsing fails
//
// Example usage:
//
//	spec, err := loadBPFSpecFromEmbed()
//	if err != nil {
//	    log.Fatalf("Failed to load BPF spec: %v", err)
//	}
func loadBPFSpecFromEmbed() (*ebpf.CollectionSpec, error) {

	// Step 1: Read the embedded BPF object into memory
	bpfBytes, err := bpfFS.ReadFile("bpf/router.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded BPF object: %w", err)
	}

	// Step 2: Parse the object bytes into an eBPF collection spec
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse embedded BPF spec: %w", err)
	}

	return spec, nil
}
