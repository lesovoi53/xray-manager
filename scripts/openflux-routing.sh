#!/usr/bin/env bash
# ==============================================================================
# X-MANAGER: Скрипт маршрутизации трафика OpenFlux (L4 gVisor Proxy)
# Режимы: xray (REDIRECT в ядро Xray) | direct (Прямой выход в WAN)
# ==============================================================================

set -e

MODE_FILE="/etc/openflux/routing.mode"
ENV_FILE="/etc/x-manager/gateways.env"

XRAY_REDIRECT_PORT=12346
if [ -f "$ENV_FILE" ]; then
    val=$(grep -oP '^XRAY_REDIRECT_PORT=\K[0-9]+' "$ENV_FILE" 2>/dev/null || true)
    [ -n "$val" ] && XRAY_REDIRECT_PORT="$val"
fi

MODE="xray"
[ -f "$MODE_FILE" ] && MODE=$(cat "$MODE_FILE" | tr -d ' \r\n')

SERVER_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

# Очистка предыдущих правил OPENFLUX_OUT с таймаутом блокировки iptables
iptables -w 5 -t nat -D OUTPUT -m owner --uid-owner openflux -j OPENFLUX_OUT 2>/dev/null || true
iptables -w 5 -t nat -F OPENFLUX_OUT 2>/dev/null || true
iptables -w 5 -t nat -X OPENFLUX_OUT 2>/dev/null || true

if [ "$MODE" = "xray" ]; then
    iptables -w 5 -t nat -N OPENFLUX_OUT 2>/dev/null || true
    iptables -w 5 -t nat -F OPENFLUX_OUT 2>/dev/null || true
    
    # Исключения: локальный трафик и IP сервера
    iptables -w 5 -t nat -A OPENFLUX_OUT -d 127.0.0.0/8 -j RETURN
    [ -n "$SERVER_IP" ] && iptables -w 5 -t nat -A OPENFLUX_OUT -d "$SERVER_IP" -j RETURN 2>/dev/null || true
    
    # Исключение облачных платформ (Яндекс / Mail.ru / VK / OnlyOffice), чтобы транспортный туннель не зацикливался
    # Яндекс IP подсети
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 5.45.192.0/18 -j RETURN 2>/dev/null || true
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 77.88.0.0/18 -j RETURN 2>/dev/null || true
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 87.250.250.0/24 -j RETURN 2>/dev/null || true
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 93.158.134.0/24 -j RETURN 2>/dev/null || true
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 178.154.131.0/24 -j RETURN 2>/dev/null || true
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 213.180.193.0/24 -j RETURN 2>/dev/null || true
    
    # Mail.ru / VK IP подсети
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 94.100.180.0/24 -j RETURN 2>/dev/null || true
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 217.69.139.0/24 -j RETURN 2>/dev/null || true
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -m multiport --dports 80,443 -d 128.140.168.0/21 -j RETURN 2>/dev/null || true

    # Перенаправление исходящего TCP в REDIRECT Gateway ядра Xray
    iptables -w 5 -t nat -A OPENFLUX_OUT -p tcp -j REDIRECT --to-ports "${XRAY_REDIRECT_PORT}"
    iptables -w 5 -t nat -C OUTPUT -m owner --uid-owner openflux -j OPENFLUX_OUT 2>/dev/null || iptables -w 5 -t nat -I OUTPUT 1 -m owner --uid-owner openflux -j OPENFLUX_OUT
fi
