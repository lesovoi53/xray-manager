#!/usr/bin/env bash
# ==============================================================================
# X-MANAGER: Универсальный инсталлятор шлюзов и прокси-служб
# Поддерживает: Snell v5 (Hybrid TCP+UDP/QUIC), Mieru (mita), WDTT (qwdtt) + Xray-core
# Репозиторий: https://github.com/lesovoi53/xray-manager
# ==============================================================================

set -eE
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Preserve the standalone download workflow by staging one complete distribution.
if [ ! -f "$SCRIPT_DIR/scripts/installer-common.sh" ]; then
    command -v curl >/dev/null || { echo 'curl is required to download the distribution' >&2; exit 1; }
    bundle=$(mktemp -d)
    trap 'rm -rf -- "$bundle"' EXIT
    curl -fL --retry 2 "https://github.com/lesovoi53/xray-manager/archive/refs/tags/v2026.09.26.4.tar.gz" -o "$bundle/source.tar.gz"
    mkdir "$bundle/source"
    tar -xzf "$bundle/source.tar.gz" --strip-components=1 -C "$bundle/source"
    bash "$bundle/source/install.sh" "$@"
    exit $?
fi
. "$SCRIPT_DIR/scripts/installer-common.sh"
xm_preflight
if [ "${1:-}" = --rollback ]; then
    [ -n "${2:-}" ] || xm_die 'Usage: install.sh --rollback /var/backups/x-manager-XXXXXXXX'
    python3 "$2/installer-state.py" restore "$2"
    exit
fi
case "${1:-}" in ''|--quick|--update|--direct|--manual|-m|--interactive|-i) ;; *) xm_die 'Unknown option';; esac

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

clear() {
    command clear 2>/dev/null || true
}

# Проверка прав суперпользователя
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Ошибка: данный скрипт должен быть запущен с правами root (sudo)!${NC}"
    exit 1
fi

# Проверка аргументов
MODE="quick"
if [ "$1" = "--manual" ] || [ "$1" = "-m" ] || [ "$1" = "--interactive" ] || [ "$1" = "-i" ]; then
    MODE="interactive"
fi

# Баннер
clear
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${BOLD}          X-MANAGER: УНИВЕРСАЛЬНЫЙ СЕТЕВОЙ ИНСТАЛЛЯТОР         ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Snell v5 | Mieru Anti-TSPU | WDTT (qwdtt) | OpenFlux L4 | Xray-core ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo 'Checking system dependencies...'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget jq unzip iptables qrencode openssl python3 iproute2 ca-certificates
for dependency in curl wget jq unzip iptables iptables-save iptables-restore openssl python3 ip runuser; do
    command -v "$dependency" >/dev/null || xm_die "Missing dependency: $dependency"
done
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else "Python 3.9 or newer is required before installation")'
port_plan=$(python3 "$SCRIPT_DIR/scripts/plan-ports.py")
eval "$port_plan"
WORK_DIR=$(mktemp -d)

# Архитектура и сетевой интерфейс
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) SNELL_ARCH="linux-amd64"; MIERU_ARCH="linux-amd64" ;;
    *) echo -e "${RED}Неподдерживаемая архитектура: $ARCH${NC}"; exit 1 ;;
esac

WAN_IF=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
[ -z "$WAN_IF" ] && WAN_IF="eth0"

SERVER_IP=$(curl -s4 --max-time 5 https://icanhazip.com 2>/dev/null || curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1)
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

# Выбор режима установки
if [ "$MODE" = "interactive" ]; then
    echo -e "${BOLD}Выберите режим установки:${NC}"
    echo -e "  ${YELLOW}[1]${NC} ⚡ ${BOLD}Быстрый старт${NC} (Автоматическая установка «под ключ» с автоподхватом шлюзов)"
    echo -e "  ${YELLOW}[2]${NC} 🛠️  ${BOLD}Ручная установка${NC} (Выбор компонентов, ввод своих портов, паролей и режимов)"
    echo -e "  ${YELLOW}[0]${NC} 🚪 Выход"
    echo ""
    read -p "Выберите вариант [1-2, по умолчанию 1]: " install_choice
    case "$install_choice" in
        2) MODE="manual" ;;
        0) exit 0 ;;
        *) MODE="quick" ;;
    esac
else
    echo -e "${GREEN}⚡ Режим: Быстрый старт (автоматическая установка «под ключ» с автоподхватом шлюзов)...${NC}"
    echo ""
fi

# Значения по умолчанию
INSTALL_SNELL="yes"
SNELL_PSK=$(openssl rand -hex 15)
SNELL_OBFS="off"

INSTALL_MIERU="yes"
MIERU_USER="ADMIN"
MIERU_PASS="mita_pass_$(openssl rand -hex 4)"
MIERU_ENTROPY_MODE="LOW_ENTROPY_MODE_48"
MIERU_MASK_ROTATION="LOW_ENTROPY_MASK_ROTATE_RIGHT_7"

INSTALL_OPENFLUX="yes"
DEFAULT_ROUTING="${DEFAULT_ROUTING:-xray}"
[ "${1:-}" != --direct ] || DEFAULT_ROUTING=direct

# Если ручной режим — задаем вопросы
if [ "$MODE" = "manual" ]; then
    echo ""
    echo -e "${BOLD}--- Настройка компонентов установки ---${NC}"
    
    # Snell
    read -p "Установить Snell v5 (Hybrid TCP + UDP/QUIC)? [Y/n]: " s_ans
    [ "$s_ans" = "n" ] || [ "$s_ans" = "N" ] && INSTALL_SNELL="no"
    if [ "$INSTALL_SNELL" = "yes" ]; then
        read -p "Порт для Snell v5 [1-65535, по умолчанию 1488]: " custom_s_port
        [ -n "$custom_s_port" ] && SNELL_PORT="$custom_s_port"
        read -p "PSK ключ Snell [Enter для случайного]: " custom_s_psk
        [ -n "$custom_s_psk" ] && SNELL_PSK="$custom_s_psk"
    fi

    # Mieru
    echo ""
    read -p "Установить Mieru (mita)? [Y/n]: " m_ans
    [ "$m_ans" = "n" ] || [ "$m_ans" = "N" ] && INSTALL_MIERU="no"
    if [ "$INSTALL_MIERU" = "yes" ]; then
        read -p "Диапазон или одиночный порт Mieru [по умолчанию 2020-2030]: " custom_m_ports
        [ -n "$custom_m_ports" ] && MIERU_PORTS="$custom_m_ports"
        read -p "Имя пользователя Mieru [по умолчанию ADMIN]: " custom_m_u
        [ -n "$custom_m_u" ] && MIERU_USER="$custom_m_u"
        read -p "Пароль Mieru [Enter для автогенерации]: " custom_m_p
        [ -n "$custom_m_p" ] && MIERU_PASS="$custom_m_p"
    fi

    # OpenFlux
    echo ""
    read -p "Установить OpenFlux (8-канальный L4 туннель через Яндекс/Mail.ru)? [Y/n]: " of_ans
    [ "$of_ans" = "n" ] || [ "$of_ans" = "N" ] && INSTALL_OPENFLUX="no"

    # Маршрутизация по умолчанию
    echo ""
    echo -e "${BOLD}Выберите режим маршрутизации по умолчанию:${NC}"
    echo -e "  ${YELLOW}[1]${NC} 🌐 Правила маршрутизации Xray (Рекомендуется)"
    echo -e "  ${YELLOW}[2]${NC} ⚡ Прямой выход"
    read -p "Выбор [1-2, по умолчанию 1]: " rt_choice
    [ "$rt_choice" = "2" ] && DEFAULT_ROUTING="direct"
fi

xm_validate_ports
if [ "$DEFAULT_ROUTING" = xray ] && [ ! -f /etc/x-ui/x-ui.db ]; then
    python3 "$SCRIPT_DIR/scripts/xray-discovery.py" --verify >/dev/null
    for gateway in "$XRAY_SOCKS_PORT" "$XRAY_REDIRECT_PORT" "$XRAY_TPROXY_PORT"; do
        ss -H -lnt "sport = :$gateway" | grep -q . || xm_die "Xray gateway :$gateway is not listening. Configure Xray first, or explicitly use --direct for a clean direct-routing installation."
    done
fi
# Stage and verify the complete selected component set before managed changes.
asset() { python3 "$SCRIPT_DIR/scripts/release-assets.py" "$1" "$WORK_DIR/$2"; }
[ "$INSTALL_SNELL" != yes ] || asset 'snell-{arch}.zip' snell-package.zip
[ "$INSTALL_MIERU" != yes ] || asset 'mita-{arch}.deb' mita.deb
[ "$INSTALL_OPENFLUX" != yes ] || asset 'openflux-{arch}' openflux
[ "${INSTALL_WEBDAV_TUNNEL:-yes}" != yes ] || asset 'webdav-tunnel-{arch}' webdav-tunnel
xm_begin
echo -e "${CYAN}==> Шаг 2: Анализ и настройка шлюзов ядра Xray (панель / standalone / заданные шлюзы)...${NC}"
mkdir -p /etc/x-manager
ENV_FILE="/etc/x-manager/gateways.env"


XUI_DB="/etc/x-ui/x-ui.db"
if [ -f "$XUI_DB" ]; then
    # Запуск умного Python скрипта детекции и внедрения
    DETECTION_OUT=$(python3 "$SCRIPT_DIR/scripts/detect-gateways.py" "$XUI_DB")

    # Парсим вывод детекции
    for line in $DETECTION_OUT; do
        case "$line" in
            FOUND_TPROXY=*)
                XRAY_TPROXY_PORT="${line#*=}"
                echo -e "  ${GREEN}✓ TPROXY шлюз:${NC} :${XRAY_TPROXY_PORT} (TPROXY Gateway)"
                ;;
            FOUND_SOCKS=*)
                XRAY_SOCKS_PORT="${line#*=}"
                echo -e "  ${GREEN}✓ Mixed/SOCKS5 вход:${NC} :${XRAY_SOCKS_PORT} (Mixed Gateway)"
                ;;
            FOUND_REDIRECT=*)
                XRAY_REDIRECT_PORT="${line#*=}"
                echo -e "  ${GREEN}✓ REDIRECT шлюз:${NC} :${XRAY_REDIRECT_PORT} (REDIRECT Gateway)"
                ;;
            UPDATED_INBOUNDS_MIXED=*)
                echo -e "  ${GREEN}✓ Mixed Gateway (:10808) синхронизирован для Xray (mixed, UDP вкл, NoAuth)${NC}"
                ;;
            INSERTED_INBOUNDS_MIXED=*)
                echo -e "  ${GREEN}✓ Mixed Gateway (:10808) добавлен в шлюзы Xray (mixed)${NC}"
                ;;
            UPDATED_INBOUNDS_TPROXY=*)
                echo -e "  ${GREEN}✓ TPROXY Gateway (:12345) синхронизирован в шлюзах Xray${NC}"
                ;;
            INSERTED_INBOUNDS_TPROXY=*)
                echo -e "  ${GREEN}✓ TPROXY Gateway (:12345) добавлен в шлюзы Xray${NC}"
                ;;
            UPDATED_INBOUNDS_REDIRECT=*)
                echo -e "  ${GREEN}✓ REDIRECT Gateway (:12346) синхронизирован в шлюзах Xray${NC}"
                ;;
            INSERTED_INBOUNDS_REDIRECT=*)
                echo -e "  ${GREEN}✓ REDIRECT Gateway (:12346) добавлен в шлюзах Xray${NC}"
                ;;
            REMOVED_GATEWAYS_FROM_TEMPLATE=1)
                echo -e "  ${GREEN}✓ Дубликаты шлюзов удалены из шаблона ядра (предотвращение конфликта портов)${NC}"
                ;;
            PATCHED_BALANCER_FALLBACK=*)
                b_name="${line#*=}"
                echo -e "  ${GREEN}✓ Настроен Kill Switch для балансировщика [${b_name}]: fallbackTag -> blocked${NC}"
                ;;
            CREATED_BLOCKED_OUTBOUND=1)
                echo -e "  ${GREEN}✓ Добавлен защитный шлюз сброса трафика 'blocked' (blackhole)${NC}"
                ;;
            RELOAD_XUI=1)
                xm_service x-ui
                sleep 2
                ;;
        esac
    done
else
    echo -e "${YELLOW}  ! База панели отсутствует. Используем проверенные шлюзы Xray или прямой выход.${NC}"
fi

# Сохраняем переменные окружения шлюзов
if [ ! -f "$ENV_FILE" ]; then
cat << EOF > "$ENV_FILE"
XRAY_TPROXY_PORT=${XRAY_TPROXY_PORT}
XRAY_REDIRECT_PORT=${XRAY_REDIRECT_PORT}
XRAY_SOCKS_PORT=${XRAY_SOCKS_PORT}
EOF
else
    . "$ENV_FILE"
fi

# Установка Snell v5.0.1
if [ "$INSTALL_SNELL" = "yes" ]; then
    echo -e "${CYAN}==> Шаг 3: Установка и настройка Snell v5.0.1 (Hybrid TCP + UDP/QUIC)...${NC}"
    id -u snell &>/dev/null || useradd -r -s /usr/sbin/nologin snell
    mkdir -p /etc/snell /usr/local/bin

    tmp_snell="$WORK_DIR/snell.zip"
    cp "$WORK_DIR/snell-package.zip" "$tmp_snell"
    unzip -tq "$tmp_snell"
    mkdir "$WORK_DIR/snell"
    unzip -q "$tmp_snell" -d "$WORK_DIR/snell"
    install -m 0755 "$WORK_DIR/snell/snell-server" /usr/local/bin/snell-server.new
    mv -f /usr/local/bin/snell-server.new /usr/local/bin/snell-server

    # Конфигурация Snell
    if [ ! -f "/etc/snell/snell-server.conf" ]; then
        cat << EOF > /etc/snell/snell-server.conf
[snell-server]
listen = 0.0.0.0:${SNELL_PORT}
ipv6 = false
psk = ${SNELL_PSK}
obfs = ${SNELL_OBFS}
EOF
    fi

    [ -f /etc/snell/tag.txt ] || echo "Snell-v5" > /etc/snell/tag.txt
    [ -f /etc/snell/routing.mode ] || echo "$DEFAULT_ROUTING" > /etc/snell/routing.mode
    chown -R snell:snell /etc/snell
    chmod 640 /etc/snell/snell-server.conf
    SNELL_PORT=$(sed -nE 's/^listen[[:space:]]*=[[:space:]]*.*:([0-9]+)$/\1/p' /etc/snell/snell-server.conf)
    [[ "$SNELL_PORT" =~ ^[0-9]+$ ]] || xm_die "Invalid Snell listen port"

    # Скрипт маршрутизации snell-routing.sh с использованием подхваченного REDIRECT порта (TCP + UDP)

    xm_install_asset scripts/snell-routing.sh /usr/local/bin/snell-routing.sh 0755
    chmod +x /usr/local/bin/snell-routing.sh

    # Служба snell.service
    cat << 'EOF' > /etc/systemd/system/snell.service
[Unit]
Description=Snell Proxy Service
After=network.target network-online.target x-ui.service
Wants=network-online.target

[Service]
Type=simple
User=snell
Group=snell
LimitNOFILE=65535
ExecStartPre=+/usr/local/bin/snell-routing.sh
ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # Открытие TCP и UDP в iptables для Snell
    iptables -C INPUT -p tcp --dport "$SNELL_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$SNELL_PORT" -j ACCEPT
    iptables -C INPUT -p udp --dport "$SNELL_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "$SNELL_PORT" -j ACCEPT

    systemctl daemon-reload
    systemctl enable snell
    xm_service snell
    echo -e "  ✓ Snell v5.0.1 запущен на порту ${SNELL_PORT} (TCP + UDP QUIC)"
fi

# Установка Mieru
if [ "$INSTALL_MIERU" = "yes" ]; then
    echo -e "${CYAN}==> Шаг 4: Установка и настройка Mieru (mita) с Anti-TSPU пресетом...${NC}"
    id -u mita &>/dev/null || useradd -r -s /usr/sbin/nologin mita
    mkdir -p /etc/mita /usr/local/bin
    if [ ! -e /etc/mieru ] && [ ! -L /etc/mieru ]; then ln -s /etc/mita /etc/mieru; fi

    dpkg-deb -x "$WORK_DIR/mita.deb" "$WORK_DIR/mita"
    test -x "$WORK_DIR/mita/usr/bin/mita" || xm_die 'Mieru package has no executable'
    install -m 0755 "$WORK_DIR/mita/usr/bin/mita" /usr/local/bin/mita.new
    mv -f /usr/local/bin/mita.new /usr/local/bin/mita
    /usr/local/bin/mita version
    echo -e "  -> Формирование конфигурации Anti-TSPU (Low-Entropy, Nonce, Padding)..."

    # Конфигурация Mieru с использованием подхваченного SOCKS5 порта
    action="PROXY"
    [ "$DEFAULT_ROUTING" = "direct" ] && action="DIRECT"

    if [ ! -f "/etc/mita/config.json" ]; then
        cat << EOF > /etc/mita/config.json
{
  "portBindings": [
    {
      "portRange": "${MIERU_PORTS}",
      "protocol": "${MIERU_PROTO}"
    }
  ],
  "users": [
    {
      "name": "${MIERU_USER}",
      "password": "${MIERU_PASS}",
      "allowPrivateIP": true,
      "allowLoopbackIP": true
    }
  ],
  "trafficPattern": {
    "unlockAll": true,
    "tcpFragment": {
      "enable": true,
      "maxSleepMs": 15
    },
    "nonce": {
      "type": "NONCE_TYPE_PRINTABLE",
      "applyToAllUDPPacket": true,
      "minLen": 6,
      "maxLen": 8
    },
    "padding": {
      "maxMiddlePaddingLen": 64,
      "maxEndPaddingLen": 128
    },
    "lowEntropy": {
      "mode": "${MIERU_ENTROPY_MODE}",
      "maskRotation": "${MIERU_MASK_ROTATION}"
    }
  },
  "loggingLevel": "INFO",
  "mtu": 1400,
  "dns": {
    "dualStack": "PREFER_IPv4"
  },
  "egress": {
    "proxies": [
      {
        "name": "xray_socks",
        "protocol": "SOCKS5_PROXY_PROTOCOL",
        "host": "127.0.0.1",
        "port": ${XRAY_SOCKS_PORT}
      }
    ],
    "rules": [
      {
        "ipRanges": [
          "*"
        ],
        "domainNames": [
          "*"
        ],
        "action": "${action}",
        "proxyNames": [
          "xray_socks"
        ]
      }
    ]
  }
}
EOF
    fi

    if [ ! -f "/etc/mita/users_db.json" ]; then
        jq -e 'reduce .users[] as $u ({}; .[$u.name] = $u.password)' /etc/mita/config.json > /etc/mita/users_db.json
    fi
    [ -f /etc/mita/server_ip.txt ] || echo "$SERVER_IP" > /etc/mita/server_ip.txt
    [ -f /etc/mita/tag.txt ] || echo "Mieru-Home" > /etc/mita/tag.txt

    chown -R mita:mita /etc/mita
    chmod 640 /etc/mita/config.json /etc/mita/users_db.json
    jq -e . /etc/mita/config.json >/dev/null
    jq -e . /etc/mita/users_db.json >/dev/null

    which_mita=/usr/local/bin/mita
    cat << EOF > /etc/systemd/system/mita.service
[Unit]
Description=Mieru proxy server
After=network-online.target network.service networking.service NetworkManager.service systemd-networkd.service x-ui.service
Wants=network-online.target
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=exec
User=mita
Group=mita
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment="MITA_LOG_NO_TIMESTAMP=true"
Environment="MITA_CONFIG_JSON_FILE=/etc/mita/config.json"
ExecStartPre=+/bin/mkdir -p /var/run/mita
ExecStartPre=+/bin/chown -R mita:mita /var/run/mita
ExecStartPre=+/bin/chmod 775 /var/run/mita
ExecStart=${which_mita} run
Nice=-10
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p /etc/systemd/system/mita.service.d
    cat << 'EOF' > /etc/systemd/system/mita.service.d/override.conf
[Service]
Environment="MITA_CONFIG_JSON_FILE=/etc/mita/config.json"
EOF

    ipt_proto=$(echo "$MIERU_PROTO" | tr '[:upper:]' '[:lower:]')
    if [[ "$MIERU_PORTS" =~ - ]]; then
        p_s=$(echo "$MIERU_PORTS" | cut -d'-' -f1)
        p_e=$(echo "$MIERU_PORTS" | cut -d'-' -f2)
        iptables -C INPUT -p "$ipt_proto" --dport "${p_s}:${p_e}" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p "$ipt_proto" --dport "${p_s}:${p_e}" -j ACCEPT
    else
        iptables -C INPUT -p "$ipt_proto" --dport "$MIERU_PORTS" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p "$ipt_proto" --dport "$MIERU_PORTS" -j ACCEPT
    fi

    echo -e "  -> Запуск и проверка службы mita..."
    systemctl daemon-reload
    systemctl enable mita
    xm_service mita
    echo -e "  ✓ Mieru запущен на портах ${MIERU_PORTS}/${MIERU_PROTO} (Anti-TSPU Balanced)"
fi

# Интеграция qwdtt с использованием подхваченного TPROXY порта
echo -e "${CYAN}==> Шаг 5: Интеграция qwdtt / WDTT TPROXY...${NC}"
echo -e "  -> Настройка скрипта wdtt-tproxy.sh и правил перехвата..."

xm_install_asset scripts/wdtt-tproxy.sh /usr/local/bin/wdtt-tproxy.sh 0755
chmod +x /usr/local/bin/wdtt-tproxy.sh

cat << 'EOF' > /etc/systemd/system/wdtt-tproxy.service
[Unit]
Description=WDTT TPROXY Routing to Xray
PartOf=wdtt.service
After=network.target x-ui.service wdtt.service
Wants=wdtt.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 2
ExecStart=/usr/local/bin/wdtt-tproxy.sh

[Install]
WantedBy=multi-user.target wdtt.service
EOF

if [ "$DEFAULT_ROUTING" = "xray" ] && [ -f /etc/systemd/system/wdtt.service ]; then
    systemctl daemon-reload
    systemctl enable wdtt-tproxy
    xm_service wdtt-tproxy
    echo -e "  ✓ WDTT TPROXY маршрутизация активирована (TPROXY :${XRAY_TPROXY_PORT})"
else
    echo -e "  ✓ WDTT маршрутизация: Прямой выход"
fi

# Установка OpenFlux (8 каналов, gVisor L4, Яндекс / Mail.ru Документы)
if [ "$INSTALL_OPENFLUX" = "yes" ]; then
    echo -e "${CYAN}==> Шаг 6: Установка OpenFlux (8 каналов, gVisor L4, Яндекс/Mail.ru)...${NC}"
    id -u openflux &>/dev/null || useradd -r -s /usr/sbin/nologin openflux
    mkdir -p /etc/openflux/instances /var/log/openflux
    
    install -m 0755 "$WORK_DIR/openflux" /usr/local/bin/openflux.new
    mv -f /usr/local/bin/openflux.new /usr/local/bin/openflux
    xm_install_asset scripts/openflux-routing.sh /usr/local/bin/openflux-routing.sh 0755
    xm_install_asset scripts/openflux-runner.sh /usr/local/bin/openflux-runner.sh 0755
    xm_install_asset systemd/openflux@.service /etc/systemd/system/openflux@.service 0644

    # Инициализация конфигураций 8 каналов
    for ch in 1 2 3 4 5 6 7 8; do
        cf="/etc/openflux/instances/${ch}.env"
        if [ ! -f "$cf" ]; then
            cat << EOF_CH > "$cf"
ROLE="exit"
MODE="l4"
TRANSPORT="mailru"
CODEC="legacy"
DEBUG="1"
URL=""
EOF_CH
        fi
    done
    [ -f /etc/openflux/routing.mode ] || echo "$DEFAULT_ROUTING" > /etc/openflux/routing.mode
    chown -R openflux:openflux /etc/openflux
    chmod 0750 /etc/openflux /etc/openflux/instances
    chmod 0640 /etc/openflux/instances/*.env

    # Применение правил маршрутизации
    /usr/local/bin/openflux-routing.sh
    systemctl daemon-reload
    echo -e "  ✓ 8 каналов OpenFlux инициализированы (L4, Xray REDIRECT :${XRAY_REDIRECT_PORT})"
fi

# Установка WebDAV Tunnel (TCP over WebDAV, selfhosted mode)
if [ "${INSTALL_WEBDAV_TUNNEL:-yes}" = "yes" ]; then
    echo -e "${CYAN}==> Шаг 6b: Установка WebDAV Tunnel (TCP over WebDAV, selfhosted)...${NC}"
    WDAVTUNNEL_USER="wdavtunnel"
    WDAVTUNNEL_DIR="/etc/webdav-tunnel"
    WDAVTUNNEL_STORAGE="/var/lib/webdav-tunnel/data"

    id -u "$WDAVTUNNEL_USER" &>/dev/null || useradd -r -s /usr/sbin/nologin "$WDAVTUNNEL_USER"
    mkdir -p "$WDAVTUNNEL_DIR" "$WDAVTUNNEL_STORAGE" "/var/log/webdav-tunnel"

    install -m 0755 "$WORK_DIR/webdav-tunnel" /usr/local/bin/webdav-tunnel.new
    mv -f /usr/local/bin/webdav-tunnel.new /usr/local/bin/webdav-tunnel
    xm_install_asset scripts/webdav-tunnel-runner.sh /usr/local/bin/webdav-tunnel-runner.sh 0755
    xm_install_asset scripts/webdav-tunnel-routing.sh /usr/local/bin/webdav-tunnel-routing.sh 0755
    xm_install_asset systemd/webdav-tunnel.service /etc/systemd/system/webdav-tunnel.service 0644

    # Конфиг по умолчанию (если ещё нет)
    if [ ! -f "$WDAVTUNNEL_DIR/config.env" ]; then
        wdav_pass=$(openssl rand -hex 12)
        cat > "$WDAVTUNNEL_DIR/config.env" <<EOF_WDAV
WEBDAV_MODE="selfhosted"
WEBDAV_LISTEN=":${WDAV_PORT}"
SELFHOSTED_PORT="${WDAV_PORT}"
WEBDAV_STORAGE="${WDAVTUNNEL_STORAGE}"
WEBDAV_URL="https://webdav.yandex.ru"
WEBDAV_LOGIN="wdav"
WEBDAV_PASSWORD="${wdav_pass}"
WEBDAV_ENC="false"
ROUTING_MODE="${DEFAULT_ROUTING}"
XRAY_REDIRECT_PORT="${XRAY_REDIRECT_PORT}"
EOF_WDAV
        chown root:"$WDAVTUNNEL_USER" "$WDAVTUNNEL_DIR/config.env"
        chmod 640 "$WDAVTUNNEL_DIR/config.env"
    fi

    chown root:"$WDAVTUNNEL_USER" "$WDAVTUNNEL_DIR" "$WDAVTUNNEL_DIR/config.env"
    chmod 0770 "$WDAVTUNNEL_DIR"
    chmod 0640 "$WDAVTUNNEL_DIR/config.env"
    if [ -f "$WDAVTUNNEL_DIR/webdav-tunnel.yaml" ]; then
        chown root:"$WDAVTUNNEL_USER" "$WDAVTUNNEL_DIR/webdav-tunnel.yaml"
        chmod 0660 "$WDAVTUNNEL_DIR/webdav-tunnel.yaml"
    fi
    chown -R "$WDAVTUNNEL_USER:$WDAVTUNNEL_USER" "$WDAVTUNNEL_STORAGE" "/var/log/webdav-tunnel"
    # Symlinks
    ln -sf /usr/local/bin/x-manager /usr/local/bin/x-webdav 2>/dev/null || true
    ln -sf /usr/local/bin/x-manager /usr/local/bin/x-wdav 2>/dev/null || true
    systemctl daemon-reload
    echo -e "  ✓ WebDAV Tunnel инициализирован (selfhosted :${WDAV_PORT}, Xray REDIRECT :${XRAY_REDIRECT_PORT})"
    echo -e "  ✓ Управление: x-webdav | x-manager → пункт [3]"
fi

# Настройка безопасности (Блокировка шлюзов извне и открытие портов протоколов)
echo -e "${CYAN}==> Шаг 7: Настройка сетевой безопасности...${NC}"
iptables -C INPUT -i "$WAN_IF" -p tcp --dport "${XRAY_TPROXY_PORT}" -j DROP 2>/dev/null || iptables -I INPUT 1 -i "$WAN_IF" -p tcp --dport "${XRAY_TPROXY_PORT}" -j DROP
iptables -C INPUT -i "$WAN_IF" -p udp --dport "${XRAY_TPROXY_PORT}" -j DROP 2>/dev/null || iptables -I INPUT 1 -i "$WAN_IF" -p udp --dport "${XRAY_TPROXY_PORT}" -j DROP
iptables -C INPUT -i "$WAN_IF" -p tcp --dport "${XRAY_REDIRECT_PORT}" -j DROP 2>/dev/null || iptables -I INPUT 1 -i "$WAN_IF" -p tcp --dport "${XRAY_REDIRECT_PORT}" -j DROP
echo -e "  ✓ Внутренние порты ядра Xray (${XRAY_TPROXY_PORT}, ${XRAY_REDIRECT_PORT}) защищены от внешнего доступа"

if command -v wdtt >/dev/null 2>&1 || [ -f "/etc/systemd/system/wdtt.service" ] || [ -d "/etc/wdtt" ]; then
    wdtt_p="56000"
    [ -f "/etc/systemd/system/wdtt.service" ] && wdtt_p=$(grep -oP -- '(^|\s)-listen\s+[0-9.]+:\K[0-9]+' /etc/systemd/system/wdtt.service 2>/dev/null | head -n 1 || echo "56000")
    iptables -C INPUT -p udp --dport "$wdtt_p" -m comment --comment "WDTT_MANAGED" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "$wdtt_p" -m comment --comment "WDTT_MANAGED" -j ACCEPT
    iptables -C INPUT -p tcp --dport "$wdtt_p" -m comment --comment "WDTT_MANAGED" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$wdtt_p" -m comment --comment "WDTT_MANAGED" -j ACCEPT
    iptables -C INPUT -p tcp --dport 56002 -m comment --comment "WDTT_MANAGED" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 56002 -m comment --comment "WDTT_MANAGED" -j ACCEPT
    iptables -C INPUT -p udp --dport 56002 -m comment --comment "WDTT_MANAGED" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport 56002 -m comment --comment "WDTT_MANAGED" -j ACCEPT
    iptables -C INPUT -p udp --dport 56003 -m comment --comment "WDTT_MANAGED" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport 56003 -m comment --comment "WDTT_MANAGED" -j ACCEPT
    echo -e "  ✓ Порты WDTT (:${wdtt_p}, :56002, :56003) открыты в фаерволе"
fi

if command -v csqtt >/dev/null 2>&1 || [ -f "/etc/systemd/system/csqtt.service" ] || [ -d "/etc/csqtt" ]; then
    csqtt_p="37000"
    [ -f "/etc/systemd/system/csqtt.service" ] && csqtt_p=$(grep -oP -- '--listen\s+0\.0\.0\.0:\K[0-9]+' /etc/systemd/system/csqtt.service 2>/dev/null | head -n 1 || echo "37000")
    iptables -C INPUT -p udp --dport "$csqtt_p" -m comment --comment "CSQTT_MANAGED" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "$csqtt_p" -m comment --comment "CSQTT_MANAGED" -j ACCEPT
    echo -e "  ✓ Порт VPN-туннеля CSQTT (:${csqtt_p}/UDP) открыт в фаерволе"
fi

# Проверка SSL сертификатов
echo -e "${CYAN}==> Шаг 8: Автоопределение SSL-сертификатов (3X-UI / /root/cert / Let's Encrypt)...${NC}"
existing_cert=""
for c_cand in /etc/x-ui/server.crt /etc/x-ui/cert.pem /root/cert/*/*.pem /root/cert/*/*.cer /root/cert/fullchain.pem /etc/letsencrypt/live/*/fullchain.pem /root/.acme.sh/*_ecc/fullchain.cer; do
    if [ -f "$c_cand" ]; then
        existing_cert="$c_cand"
        break
    fi
done
if [ -n "$existing_cert" ]; then
    echo -e "  ✓ Обнаружен SSL сертификат: ${GREEN}${existing_cert}${NC}"
else
    echo -e "  ℹ️ SSL сертификат не найден локально. Укажите существующий сертификат в меню SSL."
fi

# Установка диспетчера x-manager
echo -e "${CYAN}==> Шаг 9: Развертывание диспетчера x-manager...${NC}"
xm_install_asset bin/x-manager /usr/local/bin/x-manager 0755
install -d -m 0755 /usr/local/share/x-manager /usr/local/share/x-manager/patches /usr/local/share/x-manager/scripts
install -m 0644 "$SCRIPT_DIR/patches/openflux-multistream.patch" /usr/local/share/x-manager/patches/
install -m 0644 "$SCRIPT_DIR/scripts/"{webdav-config.py,plan-ports.py,release-assets.py,update-release.sh,xray-discovery.py,menu-v2.sh} /usr/local/share/x-manager/scripts/
install -m 0644 "$SCRIPT_DIR/components.json" /usr/local/share/x-manager/components.json
install -m 0644 "$SCRIPT_DIR/scripts/menu-actions.tsv" /usr/local/share/x-manager/scripts/
install -m 0644 "$SCRIPT_DIR/scripts/installer-state.py" /usr/local/share/x-manager/scripts/
echo -e "  -> Создание системных алиасов (x-snell, x-mieru, x-wdtt, x-csqtt, x-dns, x-ssl, x-fw)..."
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-snell
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-mieru
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-wdtt
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-qwdtt
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-csqtt
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-dns
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-cottendns
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-masterdns
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-ssl
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-cert
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-fw
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-firewall
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-sub
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-tuna
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-openflux
ln -sf /usr/local/bin/x-manager /usr/local/bin/x-flux
echo -e "  ✓ Диспетчер x-manager успешно развернут"

echo -e "${CYAN}==> Шаг 10: Развертывание сервера подписок TUNA (tuna-subscriptions)...${NC}"
XM_PARENT_TRANSACTION=1 XM_PARENT_BACKUP="$XM_BACKUP" bash "$SCRIPT_DIR/tuna-sub-server/install-sub-server.sh"
if [ "${INSTALL_WEBDAV_TUNNEL:-yes}" = yes ]; then
    systemctl enable webdav-tunnel
    xm_service webdav-tunnel
fi
# Preserve existing instance enablement; start only channels with configured URLs.
if [ "$INSTALL_OPENFLUX" = yes ]; then
    for channel in {1..8}; do
        if ( . "/etc/openflux/instances/$channel.env"; [ -n "${URL:-}" ] ); then
            xm_service "openflux@$channel"
        fi
    done
fi
# Keep the full verified source for repeat installation and manual rollback.
# This directory is included in installer-state.py's managed backup scope.
distribution=/usr/local/share/x-manager/distribution
staged_distribution=$(mktemp -d /usr/local/share/x-manager/.distribution-XXXXXXXX)
( set -o pipefail; tar -C "$SCRIPT_DIR" --exclude=__pycache__ -cf - install.sh components.json bin scripts systemd tuna-sub-server patches licenses | tar -C "$staged_distribution" -xf - )
bash -n "$staged_distribution/install.sh"
rm -rf -- "$distribution"
mv "$staged_distribution" "$distribution"
chmod 0755 "$distribution"
python3 - "$XM_BACKUP/state.json" <<'PY'
import json, subprocess, sys
for unit, previous in json.load(open(sys.argv[1]))['services'].items():
    if previous['enabled'] == 'disabled':
        subprocess.run(['systemctl', 'disable', unit], check=True)
PY
XM_TRANSACTION=0
rm -rf -- "$WORK_DIR"
echo "Rollback: bash /usr/local/share/x-manager/distribution/install.sh --rollback $XM_BACKUP"

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}             УСТАНОВКА X-MANAGER УСПЕШНО ЗАВЕРШЕНА!                   ${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Для входа в интерактивное меню запустите:${NC}"
echo -e "  ${CYAN}${BOLD}x-manager${NC}   - Главный центр управления всеми службами"
echo -e "  ${YELLOW}${BOLD}x-openflux${NC}  - Раздел управления OpenFlux (Яндекс/Mail.ru 8 каналов)"
echo -e "  ${PURPLE}${BOLD}x-sub${NC}       - Раздел управления сервером подписок TUNA (tuna-subscriptions)"
echo -e "  ${YELLOW}x-snell${NC}     - Раздел управления Snell v5"
echo -e "  ${YELLOW}x-mieru${NC}     - Раздел управления Mieru"
echo -e "  ${YELLOW}x-wdtt${NC}      - Раздел управления WDTT (qwdtt)"
echo -e "  ${YELLOW}x-csqtt${NC}     - Раздел управления CSQTT (VPN & Защита веб-панели)"
echo -e "  ${YELLOW}x-dns${NC}       - Раздел управления DNS-туннелями (CottenDNS / MasterDnsVPN)"
echo -e "  ${RED}x-fw${NC}        - Центр управления фаерволом портов (отключение протоколов)"
echo ""
echo -e "${BOLD}Шлюзы ядра Xray (подхваченные/настроенные):${NC}"
echo -e "  • TPROXY:   127.0.0.1:${XRAY_TPROXY_PORT}"
echo -e "  • REDIRECT: 127.0.0.1:${XRAY_REDIRECT_PORT}"
echo -e "  • SOCKS5:   127.0.0.1:${XRAY_SOCKS_PORT}"
echo ""
echo 'Existing credentials and subscription formats are preserved. View connection cards in x-manager.'
echo 'New/running services passed startup checks; previously stopped services remain stopped. Empty OpenFlux channels remain unstarted.'
