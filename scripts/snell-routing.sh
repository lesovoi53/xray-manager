#!/usr/bin/env bash
# ==============================================================================
# X-MANAGER: Скрипт маршрутизации трафика Snell v5
# Режимы: xray (REDIRECT в ядро Xray) | direct (Прямой выход в WAN)
# ==============================================================================

set -e

MODE_FILE="/etc/snell/routing.mode"
ENV_FILE="/etc/x-manager/gateways.env"

XRAY_REDIRECT_PORT=12346
if [ -f "$ENV_FILE" ]; then
    val=$(grep -oP '^XRAY_REDIRECT_PORT=\K[0-9]+' "$ENV_FILE" 2>/dev/null || true)
    [ -n "$val" ] && XRAY_REDIRECT_PORT="$val"
fi

MODE="xray"
[ -f "$MODE_FILE" ] && MODE=$(cat "$MODE_FILE" | tr -d ' \r\n')

SERVER_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

# Очистка предыдущих правил SNELL_OUT с таймаутом блокировки iptables
iptables -w 5 -t nat -D OUTPUT -m owner --uid-owner snell -j SNELL_OUT 2>/dev/null || true
iptables -w 5 -t nat -F SNELL_OUT 2>/dev/null || true
iptables -w 5 -t nat -X SNELL_OUT 2>/dev/null || true

if [ "$MODE" = "xray" ]; then
    iptables -w 5 -t nat -N SNELL_OUT 2>/dev/null || true
    iptables -w 5 -t nat -F SNELL_OUT 2>/dev/null || true
    iptables -w 5 -t nat -A SNELL_OUT -d 127.0.0.0/8 -j RETURN
    [ -n "$SERVER_IP" ] && iptables -w 5 -t nat -A SNELL_OUT -d "$SERVER_IP" -j RETURN 2>/dev/null || true
    iptables -w 5 -t nat -A SNELL_OUT -p tcp -j REDIRECT --to-ports "${XRAY_REDIRECT_PORT}"
    iptables -w 5 -t nat -C OUTPUT -m owner --uid-owner snell -j SNELL_OUT 2>/dev/null || iptables -w 5 -t nat -I OUTPUT 1 -m owner --uid-owner snell -j SNELL_OUT
fi
