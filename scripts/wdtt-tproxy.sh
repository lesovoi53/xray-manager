#!/usr/bin/env bash
# ==============================================================================
# X-MANAGER: Скрипт маршрутизации трафика WDTT / qwdtt
# Режимы: xray (TPROXY в ядро Xray) | direct (Прямой выход через MASQUERADE)
# ==============================================================================

set -e

WAN_IF=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
[ -z "$WAN_IF" ] && WAN_IF="eth0"

ENV_FILE="/etc/x-manager/gateways.env"
TPROXY_PORT=12345
if [ -f "$ENV_FILE" ]; then
    val=$(grep -oP '^XRAY_TPROXY_PORT=\K[0-9]+' "$ENV_FILE" 2>/dev/null || true)
    [ -n "$val" ] && TPROXY_PORT="$val"
fi

MODE_FILE="/etc/wdtt/routing.mode"
MODE="xray"
[ -f "$MODE_FILE" ] && MODE=$(cat "$MODE_FILE" | tr -d ' \r\n')

SERVER_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

# Очистка предыдущих хуков
iptables -w 5 -t mangle -D PREROUTING -i wdtt0 -j WDTT_TPROXY 2>/dev/null || true
iptables -w 5 -t mangle -D PREROUTING -i wdttraw0 -j WDTT_TPROXY 2>/dev/null || true
iptables -w 5 -t mangle -F WDTT_TPROXY 2>/dev/null || true
iptables -w 5 -t mangle -X WDTT_TPROXY 2>/dev/null || true

if [ "$MODE" = "xray" ]; then
    # 1. Routing table 100
    ip rule show | grep -q "lookup 100" || ip rule add fwmark 1 table 100
    ip route show table 100 | grep -q "local default dev lo" || ip route add local 0.0.0.0/0 dev lo table 100

    # 2. iptables MANGLE rules
    iptables -w 5 -t mangle -N WDTT_TPROXY 2>/dev/null || true
    iptables -w 5 -t mangle -F WDTT_TPROXY 2>/dev/null || true

    # Исключения
    iptables -w 5 -t mangle -A WDTT_TPROXY -d 10.66.0.0/16 -j RETURN
    iptables -w 5 -t mangle -A WDTT_TPROXY -d 10.70.0.0/16 -j RETURN
    iptables -w 5 -t mangle -A WDTT_TPROXY -d 127.0.0.0/8 -j RETURN
    [ -n "$SERVER_IP" ] && iptables -w 5 -t mangle -A WDTT_TPROXY -d "$SERVER_IP" -j RETURN 2>/dev/null || true

    # Перенаправление в TPROXY
    iptables -w 5 -t mangle -A WDTT_TPROXY -p tcp -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark 1
    iptables -w 5 -t mangle -A WDTT_TPROXY -p udp -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark 1

    # Хук в PREROUTING
    iptables -w 5 -t mangle -I PREROUTING 1 -i wdtt0 -j WDTT_TPROXY 2>/dev/null || true
    iptables -w 5 -t mangle -I PREROUTING 1 -i wdttraw0 -j WDTT_TPROXY 2>/dev/null || true

    # Защита TPROXY порта извне
    iptables -w 5 -C INPUT -i "${WAN_IF}" -p tcp --dport "${TPROXY_PORT}" -j DROP 2>/dev/null || iptables -w 5 -I INPUT 1 -i "${WAN_IF}" -p tcp --dport "${TPROXY_PORT}" -j DROP
    iptables -w 5 -C INPUT -i "${WAN_IF}" -p udp --dport "${TPROXY_PORT}" -j DROP 2>/dev/null || iptables -w 5 -I INPUT 1 -i "${WAN_IF}" -p udp --dport "${TPROXY_PORT}" -j DROP

    # Удаление прямого MASQUERADE (Kill Switch)
    while iptables -w 5 -t nat -D POSTROUTING -s 10.66.0.0/16 -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.66.0.0/16 -o "${WAN_IF}" -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.66.0.0/16 -o "${WAN_IF}" -m comment --comment WDTT_MANAGED -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.70.0.0/16 -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.70.0.0/16 -o "${WAN_IF}" -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.70.0.0/16 -o "${WAN_IF}" -m comment --comment WDTT_RAW_MANAGED -j MASQUERADE 2>/dev/null; do :; done
else
    # Режим Direct WAN: Включаем прямой MASQUERADE
    iptables -w 5 -t nat -C POSTROUTING -s 10.66.0.0/16 -o "${WAN_IF}" -m comment --comment WDTT_MANAGED -j MASQUERADE 2>/dev/null || \
        iptables -w 5 -t nat -A POSTROUTING -s 10.66.0.0/16 -o "${WAN_IF}" -m comment --comment WDTT_MANAGED -j MASQUERADE
    iptables -w 5 -t nat -C POSTROUTING -s 10.70.0.0/16 -o "${WAN_IF}" -m comment --comment WDTT_RAW_MANAGED -j MASQUERADE 2>/dev/null || \
        iptables -w 5 -t nat -A POSTROUTING -s 10.70.0.0/16 -o "${WAN_IF}" -m comment --comment WDTT_RAW_MANAGED -j MASQUERADE
fi
