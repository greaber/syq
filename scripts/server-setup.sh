#!/usr/bin/env bash
# server-setup.sh — one idempotent script for everything pcp/RoCE needs on a
# Japanese GPU host. Run as root; rerun any time (it only changes what differs).
#
#   sudo ./server-setup.sh plan      # print exactly what `apply` would change here
#   sudo ./server-setup.sh apply     # do everything below
#   sudo ./server-setup.sh status    # show what is / isn't in place (no changes)
#   sudo ./server-setup.sh roce-clean# remove only the RoCE bits this script added (keep the rest)
#   sudo ./server-setup.sh undo      # best-effort removal of everything this script added
#
# What `apply` does (each step is skipped when already done):
#   1. TCP tuning for long-RTT transfers: 64 MB socket buffers, BBR, fq.
#      -> /etc/sysctl.d/90-pcp-net.conf, /etc/modules-load.d/pcp-bbr.conf
#   2. sshd MaxStartups 100:30:200 so many parallel ssh sessions aren't dropped.
#      -> the MaxStartups line in /etc/ssh/sshd_config itself (uncommented /
#         replaced in place, added if absent) + sshd reload
#   3. ufw: allow pcp's TCP data ports (47600-47699) from the cluster LAN, from
#      each cluster host's public IP, and from the listed client machines.
#   4. RoCE: bring the ConnectX ports up; if any have link, give each an
#      address 192.168.<100+N>.<host octet>/24 with MTU 9000 via
#      /etc/netplan/60-roce.yaml and allow all traffic on those interfaces.
#      Addresses are set live with `ip`; the yaml is only generated (never
#      `netplan apply`, which would re-touch bond0). Ports without a cable are
#      left alone, so this is a no-op on hosts that aren't wired yet.
#
# Everything this script writes carries a "pcp-setup" marker so `undo` can
# find it. Nothing here touches bond0, NFS mounts, or existing ufw rules.

set -euo pipefail

# ---- site configuration ------------------------------------------------------
CLUSTER_LAN=10.2.201.0/24
CLUSTER_PUBLIC=(157.66.255.44 157.66.255.45 157.66.255.46 157.66.255.59)   # j3 j2 j4 j5
CLIENTS=(116.202.146.123)                                                 # grant's Hetzner box
PCP_PORTS=47600:47699
ROCE_SUBNET_BASE=100
MARK=pcp-setup

ETC=${PCP_SETUP_ETC:-/etc}           # overridable for testing only
SYSCTL_FILE=$ETC/sysctl.d/90-pcp-net.conf
OLD_SYSCTL_FILE=$ETC/sysctl.d/99-net.conf
MODULES_FILE=$ETC/modules-load.d/pcp-bbr.conf
SSHD_CONFIG=$ETC/ssh/sshd_config
OLD_SSHD_FILE=$ETC/ssh/sshd_config.d/60-pcp.conf   # from an earlier version of this script
NETPLAN_FILE=$ETC/netplan/60-roce.yaml

die() { echo "error: $*" >&2; exit 1; }
say() { echo "  $*"; }
need_root() { [ "$(id -u)" = 0 ] || die "run as root: sudo $0 $*"; }
DRY=0
# Every command that changes the system goes through run(); `plan` just prints them.
run() { if [ "$DRY" = 1 ]; then echo "    would run: $*"; else "$@"; fi; }
# Same for file writes: write_file PATH <<EOF ... EOF
write_file() { if [ "$DRY" = 1 ]; then echo "    would write: $1"; sed 's/^/      | /'; else cat > "$1"; fi; }

# ---- 1. sysctl -----------------------------------------------------------------
sysctl_wanted() {
  cat <<EOF
# $MARK: TCP tuning for pcp / long-RTT transfers
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 131072 67108864
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
EOF
}
sysctl_status() {
  local cc; cc=$(sysctl -n net.ipv4.tcp_congestion_control)
  local wm; wm=$(sysctl -n net.ipv4.tcp_wmem | awk '{print $3}')
  say "sysctl: congestion=$cc wmem_max=$wm file=$([ -f $SYSCTL_FILE ] && echo present || echo absent)"
  [ "$cc" = bbr ] && [ "$wm" = 67108864 ]
}
sysctl_apply() {
  # Absorb the hand-made file from the first round (same settings, broken comment).
  if [ -f $OLD_SYSCTL_FILE ] && grep -q "tcp_congestion_control" $OLD_SYSCTL_FILE; then
    run rm -f $OLD_SYSCTL_FILE; say "sysctl: hand-made $OLD_SYSCTL_FILE removed (same settings now live in $SYSCTL_FILE)"
  fi
  if [ ! -f $MODULES_FILE ]; then
    echo tcp_bbr | write_file $MODULES_FILE; say "sysctl: tcp_bbr added to modules-load (BBR survives reboot)"
  fi
  if ! sysctl_status >/dev/null 2>&1 || ! diff -q <(sysctl_wanted) $SYSCTL_FILE >/dev/null 2>&1; then
    run modprobe tcp_bbr
    sysctl_wanted | write_file $SYSCTL_FILE
    run sysctl -q --system >/dev/null
    say "sysctl: applied"
  else
    say "sysctl: already in place"
  fi
}
sysctl_undo() {
  rm -f $SYSCTL_FILE $MODULES_FILE
  sysctl -q -w net.ipv4.tcp_congestion_control=cubic net.core.default_qdisc=fq_codel \
    net.core.rmem_max=212992 net.core.wmem_max=212992 \
    net.ipv4.tcp_rmem="4096 131072 6291456" net.ipv4.tcp_wmem="4096 16384 4194304" >/dev/null
  say "sysctl: removed (kernel defaults restored)"
}

# ---- 2. sshd -------------------------------------------------------------------
SSHD_WANT="MaxStartups 100:30:200"
sshd_status() {
  local live; live=$(sshd -T 2>/dev/null | awk '/^maxstartups/{print $2}')
  local n; n=$(grep -cE "^MaxStartups" $SSHD_CONFIG 2>/dev/null || true)
  say "sshd: live MaxStartups=${live:-?}; $SSHD_CONFIG has $n MaxStartups line(s)"
  [ "$live" = "100:30:200" ] && [ "$n" = 1 ] && grep -qE "^$SSHD_WANT$" $SSHD_CONFIG
}
sshd_apply() {
  if [ -f $OLD_SSHD_FILE ]; then run rm -f $OLD_SSHD_FILE; say "sshd: removed old drop-in $OLD_SSHD_FILE"; fi
  if sshd_status >/dev/null 2>&1 && [ ! -f $OLD_SSHD_FILE ]; then say "sshd: already in place"; return; fi
  if grep -qE "^MaxStartups" $SSHD_CONFIG; then
    # Normalize the first active line in place; drop any further active ones.
    run sed -i -E "0,/^MaxStartups.*/s//$SSHD_WANT/; /^MaxStartups/{x;s/^/x/;/^x{2,}/{x;d};x}" $SSHD_CONFIG
    say "sshd: normalized existing MaxStartups line in $SSHD_CONFIG"
  elif grep -qE "^#MaxStartups" $SSHD_CONFIG; then
    # Keep the stock commented default and add the real line right after it.
    run sed -i -E "0,/^#MaxStartups.*/s//&\n$SSHD_WANT/" $SSHD_CONFIG
    say "sshd: added '$SSHD_WANT' after the commented default in $SSHD_CONFIG"
  else
    run sh -c "printf '\n%s\n' '$SSHD_WANT' >> $SSHD_CONFIG"
    say "sshd: appended '$SSHD_WANT' to $SSHD_CONFIG"
  fi
  if [ "$DRY" = 0 ]; then sshd -t && { systemctl reload ssh 2>/dev/null || systemctl reload sshd; }; else echo "    would run: sshd -t && systemctl reload ssh"; fi
}
sshd_undo() {
  rm -f $OLD_SSHD_FILE
  sed -i -E "s/^$SSHD_WANT$/#MaxStartups 10:30:100/" $SSHD_CONFIG
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  say "sshd: MaxStartups line commented out again"
}

# ---- 3. ufw --------------------------------------------------------------------
ufw_sources() { echo "$CLUSTER_LAN"; printf '%s\n' "${CLUSTER_PUBLIC[@]}" "${CLIENTS[@]}"; }
UFW_STATUS=""
ufw_active() {
  command -v ufw >/dev/null || return 1
  [ -n "$UFW_STATUS" ] || UFW_STATUS=$(ufw status verbose 2>/dev/null || true)
  grep -q "Status: active" <<<"$UFW_STATUS"
}
# `ufw status verbose` always prints the direction ("ALLOW IN"); plain status doesn't.
ufw_has() { grep -qE "^$PCP_PORTS/tcp +ALLOW IN +$1( |$)" <<<"$UFW_STATUS"; }
ufw_has_iface() { grep -qE "^Anywhere on $1 +ALLOW IN" <<<"$UFW_STATUS"; }
ufw_status() {
  if ! ufw_active; then say "ufw: inactive (nothing to do)"; return 0; fi
  local ok=0 missing=""
  for s in $(ufw_sources); do ufw_has "$s" || missing="$missing $s"; done
  say "ufw: pcp ports $PCP_PORTS/tcp ${missing:+missing from:$missing}${missing:-allowed from all listed sources}"
  [ -z "$missing" ]
}
ufw_apply() {
  if ! ufw_active; then say "ufw: inactive, skipping"; return; fi
  for s in $(ufw_sources); do
    if ufw_has "$s"; then continue; fi
    run ufw allow from "$s" to any port "$PCP_PORTS" proto tcp comment "$MARK pcp data" >/dev/null
    say "ufw: allowed $PCP_PORTS/tcp from $s"
  done
  say "ufw: done"
}
ufw_undo() {
  ufw_active || return 0
  # Delete every pcp port-range rule, marked or hand-made (highest number first
  # so the numbering stays valid while deleting).
  local nums; nums=$( (ufw status numbered || true) | grep -E "$PCP_PORTS/tcp|$MARK" | sed -E 's/^\[ *([0-9]+)\].*/\1/' | sort -rn)
  for n in $nums; do yes | ufw delete "$n" >/dev/null; done
  say "ufw: removed all pcp port rules"
}

# ---- 4. RoCE -------------------------------------------------------------------
roce_ports() {
  for d in /sys/class/net/*/device; do
    n=$(basename "$(dirname "$d")")
    [ -e "$d/infiniband" ] || continue
    [ "$(basename "$(readlink "$d/driver")")" = mlx5_core ] || continue
    echo "$(basename "$(readlink "$d")") $n"
  done | sort | awk '{print $2}'
}
ibdev_of() { ls "/sys/class/net/$1/device/infiniband" 2>/dev/null | head -1; }
phys_state() { cat "/sys/class/infiniband/$(ibdev_of "$1")/ports/1/phys_state" 2>/dev/null | awk '{print $2}'; }
host_octet() { ip -4 -o addr show bond0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | awk -F. '{print $4}' | head -1; }
link_up() { [ "$(cat /sys/class/net/$1/carrier 2>/dev/null)" = 1 ]; }

roce_status() {
  local ports; ports=$(roce_ports)
  [ -n "$ports" ] || { say "roce: no ConnectX ports"; return 0; }
  local up=0 total=0
  for n in $ports; do
    total=$((total+1))
    printf "    %-16s %-8s carrier=%-3s phys=%-9s %s\n" "$n" "$(ibdev_of "$n")" "$(cat /sys/class/net/$n/carrier 2>/dev/null || echo ?)" "$(phys_state "$n")" "$(ip -4 -o addr show "$n" | awk '{print $4}' | tr '\n' ' ')"
    link_up "$n" && up=$((up+1))
  done
  say "roce: $up/$total ports have link; netplan=$([ -f $NETPLAN_FILE ] && echo present || echo absent)"
}
# A fabric is "pre-configured" if the provider already addressed these ports
# (rail*/roce* interface names, existing IPs, or netplan-generated rail networks).
# In that case we must not touch them — our flat 192.168/24 would clobber it.
roce_preconfigured() {
  ls /run/systemd/network/*rail*.network >/dev/null 2>&1 && return 0
  for n in $(roce_ports); do
    case "$n" in rail*|roce*) return 0;; esac
    [ -n "$(ip -4 -o addr show "$n" | awk '{print $4}')" ] && return 0
  done
  return 1
}
roce_apply() {
  local ports; ports=$(roce_ports)
  [ -n "$ports" ] || { say "roce: no ConnectX ports, skipping"; return; }
  if roce_preconfigured; then
    say "roce: fabric already configured by the provider (rails/addresses present) — leaving it untouched"
    [ -f $NETPLAN_FILE ] && say "roce: NOTE stale $NETPLAN_FILE from a previous run is present; run '$0 roce-clean' to remove it safely"
    return
  fi
  for n in $ports; do run ip link set "$n" up 2>/dev/null || true; done
  [ "$DRY" = 1 ] || sleep 5
  local linked=()
  for n in $ports; do link_up "$n" && linked+=("$n"); done
  if [ ${#linked[@]} = 0 ]; then
    say "roce: no port has link (no cable / switch down) — nothing configured; rerun when wired"
    return
  fi
  local h; h=$(host_octet); [ -n "$h" ] || die "cannot determine host octet from bond0"
  local yaml="# $MARK\nnetwork:\n  version: 2\n  ethernets:\n" i=0
  for n in $ports; do                         # index by PCI order over ALL ports so N is stable
    if printf '%s\n' "${linked[@]}" | grep -qx "$n"; then
      yaml+="    $n:\n      dhcp4: false\n      mtu: 9000\n      addresses: [192.168.$((ROCE_SUBNET_BASE + i)).$h/24]\n"
    fi
    i=$((i+1))
  done
  # Persist via netplan (generate only — `netplan apply` would re-touch bond0,
  # the interface this session probably runs over) and configure live with ip.
  if [ -f $NETPLAN_FILE ] && diff -q <(printf "$yaml") $NETPLAN_FILE >/dev/null; then
    say "roce: netplan already in place (${#linked[@]} ports)"
  else
    printf "$yaml" | write_file $NETPLAN_FILE
    run chmod 600 $NETPLAN_FILE
    run netplan generate
    say "roce: wrote $NETPLAN_FILE for ${linked[*]} (192.168.<100+N>.$h/24, MTU 9000)"
  fi
  i=0
  for n in $ports; do
    if printf '%s\n' "${linked[@]}" | grep -qx "$n"; then
      local addr="192.168.$((ROCE_SUBNET_BASE + i)).$h/24"
      ip -4 -o addr show "$n" | grep -q " $addr " || run ip addr add "$addr" dev "$n"
      [ "$(cat /sys/class/net/$n/mtu)" = 9000 ] || run ip link set "$n" mtu 9000
    fi
    i=$((i+1))
  done
  say "roce: live addresses set on ${linked[*]}"
  if ufw_active; then
    for n in "${linked[@]}"; do
      ufw_has_iface "$n" || run ufw allow in on "$n" comment "$MARK roce" >/dev/null
      grep -qE "^Anywhere +ALLOW OUT +Anywhere on $n" <<<"$UFW_STATUS" || run ufw allow out on "$n" comment "$MARK roce" >/dev/null
    done
    say "roce: ufw allows all traffic on ${linked[*]}"
  fi
  for n in "${linked[@]}"; do d=$(ibdev_of "$n"); [ -n "$d" ] && run cma_roce_mode -d "$d" -p 1 -m 2 >/dev/null 2>&1 || true; done
  say "roce: test with  ib_write_bw -d $(ibdev_of "${linked[0]}") -F --report_gbits   (server)  /  ... <ip>  (client)"
}
# Remove only what THIS script added to RoCE (our netplan file + our 192.168.10x
# addresses), never the provider's fabric addresses.
roce_clean() {
  if [ -f $NETPLAN_FILE ]; then run rm -f $NETPLAN_FILE; run netplan generate; say "roce: removed our $NETPLAN_FILE"; else say "roce: no $NETPLAN_FILE to remove"; fi
  local removed=0
  for n in $(roce_ports); do
    for a in $(ip -4 -o addr show "$n" | awk '{print $4}'); do
      case "$a" in 192.168.10[0-9].*) run ip addr del "$a" dev "$n"; removed=$((removed+1));; esac
    done
  done
  say "roce: removed $removed of our 192.168.10x addresses (provider addresses left intact)"
}
roce_undo() {
  if [ -f $NETPLAN_FILE ]; then rm -f $NETPLAN_FILE; netplan generate; say "roce: netplan file removed"; fi
  for n in $(roce_ports); do ip addr flush dev "$n" 2>/dev/null || true; done
  say "roce: addresses flushed (ports left admin-up; harmless)"
}

# ---- driver ---------------------------------------------------------------------
case "${1:-}" in
  plan)   need_root plan; DRY=1; echo "== plan on $(hostname) (nothing will be changed)"; sysctl_apply; sshd_apply; ufw_apply; roce_apply; echo "== end of plan" ;;
  apply)  need_root apply; echo "== apply on $(hostname)"; sysctl_apply; sshd_apply; ufw_apply; roce_apply; echo "== done" ;;
  status) echo "== status on $(hostname)"; [ "$(id -u)" = 0 ] || say "(run as root for sshd/ufw details)"; sysctl_status || true; sshd_status || true; ufw_status || true; roce_status
          ;;
  roce-clean) need_root roce-clean; echo "== roce-clean on $(hostname)"; roce_clean; echo "== done" ;;
  undo)   need_root undo; echo "== undo on $(hostname)"; roce_undo; ufw_undo; sshd_undo; sysctl_undo; echo "== done" ;;
  *) sed -n '2,26p' "$0"; exit 1 ;;
esac
