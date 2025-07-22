Build eBPF program:
clang -target bpf -O2 -g \
  -I$(pwd)/.libraries/include \
  -c ./pkg/router/bpf/xdp_nat.c \
  -o ./pkg/router/bpf/xdp_nat.bpf.o

Disable scrappy vlan stripping on interface:
> ethtool -K ens5 rx-vlan-offload off tx-vlan-offload off rx-vlan-filter off

Create basic netns setup:
sudo ip link add veth0 type veth peer name veth1
sudo ip netns add target_ns
sudo ip link set veth1 netns target_ns
sudo ip link set veth0 up
sudo ip netns exec target_ns ip link set lo up
sudo ip netns exec target_ns ip link set veth1 up
# sudo ip netns exec target_ns ip route add default dev veth1
# sudo ip netns exec target_ns sysctl -w net.ipv4.ip_forward=1
# sudo iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE