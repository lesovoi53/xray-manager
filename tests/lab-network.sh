#!/usr/bin/env bash
# Temporary NAT for only this disposable namespace. Never touches Windows/VPS networking.
set -euo pipefail
LAB=${XM_LAB_ROOT:-/var/tmp/x-manager-debian13-lab/rootfs}
for proc in /proc/[0-9]*; do
    if [ "$(cat "$proc/comm" 2>/dev/null)" = systemd ] && [ -f "$proc/root/.x-manager-test-lab" ] && [ "$(stat -Lc '%d:%i' "$proc/root")" = "$(stat -Lc '%d:%i' "$LAB")" ]; then
        leader=${proc##*/}
        break
    fi
done
: "${leader:?Lab is not running}"
if [ "${1:-}" = down ]; then
    chroot "$LAB" iptables -t nat -D POSTROUTING -s 10.203.0.2/32 -m comment --comment x-manager-lab -j MASQUERADE
    ip link del xmhost
    cat $LAB/../ip-forward.before > /proc/sys/net/ipv4/ip_forward
    exit
fi
cat /proc/sys/net/ipv4/ip_forward > $LAB/../ip-forward.before
echo 1 > /proc/sys/net/ipv4/ip_forward
ip link add xmhost type veth peer name xmlab
ip addr add 10.203.0.1/30 dev xmhost
ip link set xmhost up
ip link set xmlab netns "$leader"
nsenter -t "$leader" -n ip addr add 10.203.0.2/30 dev xmlab
nsenter -t "$leader" -n ip link set xmlab up
nsenter -t "$leader" -n ip route add default via 10.203.0.1
chroot "$LAB" iptables -t nat -A POSTROUTING -s 10.203.0.2/32 -m comment --comment x-manager-lab -j MASQUERADE
