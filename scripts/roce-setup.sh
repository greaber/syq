#!/usr/bin/env bash
# roce-setup.sh — bring up and configure the ConnectX RoCE ports on a GPU host.
#
# Run as root. Subcommands:
#
#   probe                Bring every RoCE port admin-up and report link state,
#                        speed and whether a transceiver is present. Changes
#                        nothing persistent; safe to run on all hosts first.
#   configure [--apply]  Write /etc/netplan/60-roce.yaml giving each RoCE port
#                        an address 192.168.<100+N>.<H>/24 (N = port index in
#                        PCI order, H = last octet of this host's bond0 IP), MTU
#                        9000, and add ufw rules allowing traffic on those
#                        interfaces. Without --apply it only prints the plan.
#   test-server          Start ib_write_bw listening (run on one host).
#   test-client <ip>     Run ib_write_bw against a host running test-server.
#   status               Show the current state of all RoCE ports.
#
# Assumptions: mlx5 NICs whose netdev names end in "np0"/"np1" (ConnectX-7 /
# BlueField-3 / ConnectX-6 Dx), Ubuntu with netplan and ufw, rdma-core and
# perftest installed (they are on j2..j5). Nothing here touches bond0.

set -euo pipefail

SUBNET_BASE=100          # 192.168.(100+N).H
NETPLAN=/etc/netplan/60-roce.yaml

die() { echo "error: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "run as root (sudo $0 $*)"; }

# RoCE-capable netdevs, sorted by PCI address so N is stable across identical hosts.
roce_ports() {
  for d in /sys/class/net/*/device; do
    n=$(basename "$(dirname "$d")")
    [ -e "$d/infiniband" ] || continue
    [ "$(basename "$(readlink "$d/driver")")" = mlx5_core ] || continue
    pci=$(basename "$(readlink "$d")")
    echo "$pci $n"
  done | sort | awk '{print $2}'
}

ibdev_of() { ls "/sys/class/net/$1/device/infiniband" 2>/dev/null | head -1; }
port_state() { cat "/sys/class/infiniband/$(ibdev_of "$1")/ports/1/state" 2>/dev/null | awk '{print $2}'; }
phys_state() { cat "/sys/class/infiniband/$(ibdev_of "$1")/ports/1/phys_state" 2>/dev/null | awk '{print $2}'; }

host_octet() {
  ip -4 -o addr show bond0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | awk -F. '{print $4}' | head -1
}

cmd_status() {
  printf "%-16s %-8s %-10s %-9s %-10s %-9s %s\n" IFACE IBDEV OPER SPEED PORT PHYS ADDR
  for n in $(roce_ports); do
    printf "%-16s %-8s %-10s %-9s %-10s %-9s %s\n" "$n" "$(ibdev_of "$n")" \
      "$(cat /sys/class/net/$n/operstate)" "$(cat /sys/class/net/$n/speed 2>/dev/null || echo ?)" \
      "$(port_state "$n")" "$(phys_state "$n")" "$(ip -4 -o addr show "$n" | awk '{print $4}' | tr '\n' ' ')"
  done
}

cmd_probe() {
  need_root probe
  echo "Bringing RoCE ports admin-up (no addresses assigned) ..."
  for n in $(roce_ports); do ip link set "$n" up 2>/dev/null || true; done
  sleep 6
  echo
  cmd_status
  echo
  echo "Transceivers / link (ethtool):"
  local cabled=0
  for n in $(roce_ports); do
    link=$(ethtool "$n" 2>/dev/null | awk -F': ' '/Link detected/{print $2}')
    mod=$(ethtool -m "$n" 2>&1 | awk -F: '/Identifier|Vendor name|Vendor PN/{gsub(/^ +/,"",$2); printf "%s; ", $2}')
    case "$link" in
      *"No cable"*) desc="NIC reports no cable/module in the cage" ;;
      yes)          desc="LINK UP  ${mod:+(module: ${mod%; })}"; cabled=$((cabled+1)) ;;
      *)            desc="${mod:+module: ${mod%; } — }no link (peer/switch port down?)"; [ -n "$mod" ] && cabled=$((cabled+1)) ;;
    esac
    printf "  %-16s link=%-16s %s\n" "$n" "${link:-?}" "$desc"
  done
  echo
  if [ $cabled = 0 ]; then
    echo "RESULT: no port has a cable or transceiver. Nothing to configure on this host;"
    echo "        ask the provider whether these ports are meant to be connected to a fabric."
  else
    echo "RESULT: $cabled port(s) have something plugged in. If they show LINK UP, run 'configure --apply';"
    echo "        if a module is present but there's no link, the switch side is down or unpatched."
  fi
}

cmd_configure() {
  local apply=0; [ "${1:-}" = "--apply" ] && apply=1
  [ $apply = 0 ] || need_root configure --apply
  local h; h=$(host_octet); [ -n "$h" ] || die "cannot determine host octet from bond0"
  local ports=(); for n in $(roce_ports); do ports+=("$n"); done
  [ ${#ports[@]} -gt 0 ] || die "no RoCE ports found"

  local yaml="network:\n  version: 2\n  ethernets:\n"
  local i=0 rules=""
  for n in "${ports[@]}"; do
    local net=$((SUBNET_BASE + i))
    yaml+="    $n:\n      dhcp4: false\n      mtu: 9000\n      addresses: [192.168.$net.$h/24]\n"
    rules+="ufw allow in on $n\nufw allow out on $n\n"
    i=$((i + 1))
  done
  echo "Host octet: $h  ->  port N gets 192.168.$((SUBNET_BASE))+N.$h/24, MTU 9000"
  echo; echo "== $NETPLAN"; printf "$yaml"; echo; echo "== ufw rules"; printf "$rules"
  if [ $apply = 0 ]; then echo; echo "(dry run; add --apply to write and apply)"; return; fi

  printf "$yaml" > "$NETPLAN"; chmod 600 "$NETPLAN"
  netplan generate && netplan apply
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    for n in "${ports[@]}"; do ufw allow in on "$n" >/dev/null; ufw allow out on "$n" >/dev/null; done
    echo "ufw: allowed all traffic on ${ports[*]}"
  fi
  # RoCE v2 is the default on these NICs; make sure and print it.
  for n in "${ports[@]}"; do
    d=$(ibdev_of "$n"); [ -n "$d" ] && cma_roce_mode -d "$d" -p 1 -m 2 >/dev/null 2>&1 || true
  done
  sleep 3; echo; cmd_status
  echo
  echo "Next: on one host 'sudo $0 test-server', on another 'sudo $0 test-client 192.168.$SUBNET_BASE.<octet>'."
}

cmd_test_server() {
  command -v ib_write_bw >/dev/null || die "ib_write_bw (perftest) not installed"
  local n; n=$(roce_ports | head -1); local d; d=$(ibdev_of "$n")
  echo "ib_write_bw server on $d ($n) — run test-client on another host"
  exec ib_write_bw -d "$d" -F --report_gbits -s 1048576 -D 10
}

cmd_test_client() {
  local ip=${1:-}; [ -n "$ip" ] || die "usage: test-client <server-roce-ip>"
  command -v ib_write_bw >/dev/null || die "ib_write_bw (perftest) not installed"
  local n; n=$(roce_ports | head -1); local d; d=$(ibdev_of "$n")
  echo "ib_write_bw client on $d ($n) -> $ip   (expect ~350-390 Gb/s on a 400G port)"
  exec ib_write_bw -d "$d" -F --report_gbits -s 1048576 -D 10 "$ip"
}

case "${1:-}" in
  probe) cmd_probe ;;
  configure) shift; cmd_configure "$@" ;;
  test-server) cmd_test_server ;;
  test-client) shift; cmd_test_client "$@" ;;
  status) cmd_status ;;
  *) sed -n '2,25p' "$0"; exit 1 ;;
esac
