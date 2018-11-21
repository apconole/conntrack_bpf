#!/bin/bash

#ensure we are up to date
make

# load all the modules...
sudo modprobe nf_conntrack
sudo modprobe nft_ct
sudo modprobe nft_conn
sudo modprobe nf_flow_table
sudo modprobe nf_flow_table_inet
sudo modprobe nf_flow_table_hw
sudo modprobe nf_flow_table_bpf_flowmap
sudo modprobe nft_flow_offload
sudo modprobe nft_fwd_netdev
sudo modprobe nft_queue
sudo modprobe nft_chain_nat_ipv4
sudo modprobe nft_chain_route_ipv4
sudo modprobe nft_chain_fib_ipv4
sudo modprobe nft_masq
sudo modprobe nft_masq_ipv4
sudo modprobe nft_redir
sudo modprobe nft_redir_ipv4

if [ "X$tablename" == "X" ]; then
    tablename="t"
fi

if [ "X$flowname" == "X" ]; then
    flowname="f"
fi

if [ "X$chainname" == "X" ]; then
    chainname="c"
fi

if [ "X$device" == "X" ]; then
    device="enp0s31f6"
fi

sudo ip link set "$device" xdp off
sudo ip link set "$device" xdp object conntrack_offload.o
sudo ~/git/nftables/src/nft flush ruleset
sudo ~/git/nftables/src/nft add table "$tablename"
sudo ~/git/nftables/src/nft add flowtable "$tablename" "$flowname" { hook ingress priority 10\; devices = { "$device" }\; }

sudo ~/git/nftables/src/nft add chain "$tablename" "$chainname" { type filter hook forward priority 0\; policy accept\; }

sudo ~/git/nftables/src/nft add chain "$tablename" "natin_${chainname}" { type nat hook prerouting priority 0 \; }
sudo ~/git/nftables/src/nft add chain "$tablename" "natout_${chainname}" { type nat hook postrouting priority 100 \; }
sudo ~/git/nftables/src/nft add rule "$tablename" "natout_${chainname}" ip saddr 192.168.122.0/24 oifname "$internet" masquerade
sudo ~/git/nftables/src/nft add rule "$tablename" "natout_${chainname}" counter


sudo ~/git/nftables/src/nft add chain "$tablename" "off_${chainname}"
sudo ~/git/nftables/src/nft add rule "$tablename" "off_$chainname" flow offload "@$flowname"

sudo ~/git/nftables/src/nft add rule "$tablename" "$chainname" ip protocol tcp jump "off_$chainname"
sudo ~/git/nftables/src/nft add rule "$tablename" "$chainname" ip protocol icmp jump "off_$chainname"
sudo ~/git/nftables/src/nft add rule "$tablename" "$chainname" counter

sudo ~/git/nftables/src/nft list ruleset
