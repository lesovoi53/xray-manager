#!/usr/bin/env bash
# ==============================================================================
# X-MANAGER: Универсальный инсталлятор шлюзов и прокси-служб
# Поддерживает: Snell v5 (Hybrid TCP+UDP/QUIC), Mieru (mita), WDTT (qwdtt) + Xray-core
# Репозиторий: https://github.com/lesovoi53/xray-manager
# ==============================================================================

set -e

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
MODE="interactive"
if [ "$1" = "--quick" ] || [ "$1" = "-q" ] || [ "$1" = "--auto" ]; then
    MODE="quick"
fi

# Баннер
clear
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${BOLD}          X-MANAGER: УНИВЕРСАЛЬНЫЙ СЕТЕВОЙ ИНСТАЛЛЯТОР         ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}     Snell v5 (Hybrid) | Mieru Anti-TSPU | WDTT (qwdtt) | Xray-core  ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Архитектура и сетевой интерфейс
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) SNELL_ARCH="linux-amd64"; MIERU_ARCH="linux-amd64" ;;
    aarch64|arm64) SNELL_ARCH="linux-aarch64"; MIERU_ARCH="linux-arm64" ;;
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
fi

# Значения по умолчанию
INSTALL_SNELL="yes"
SNELL_PORT="1488"
SNELL_PSK=$(openssl rand -base64 24 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 30 || echo "snell_secret_pass_$(date +%s)")
SNELL_OBFS="off"

INSTALL_MIERU="yes"
MIERU_PORTS="2020-2030"
MIERU_PROTO="TCP"
MIERU_USER="ADMIN"
MIERU_PASS="mita_pass_$(openssl rand -hex 4 2>/dev/null || echo "2026")"
MIERU_ENTROPY_MODE="LOW_ENTROPY_MODE_48"
MIERU_MASK_ROTATION="LOW_ENTROPY_MASK_ROTATE_RIGHT_7"

DEFAULT_ROUTING="xray"

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

    # Маршрутизация по умолчанию
    echo ""
    echo -e "${BOLD}Выберите режим маршрутизации по умолчанию:${NC}"
    echo -e "  ${YELLOW}[1]${NC} 🌐 Правила маршрутизации Xray (Рекомендуется)"
    echo -e "  ${YELLOW}[2]${NC} ⚡ Прямой выход"
    read -p "Выбор [1-2, по умолчанию 1]: " rt_choice
    [ "$rt_choice" = "2" ] && DEFAULT_ROUTING="direct"
fi

echo ""
echo -e "${CYAN}==> Шаг 1: Проверка и установка системных утилит...${NC}"
export DEBIAN_FRONTEND=noninteractive
echo -e "  -> Обновление списков пакетов (apt-get update)..."
apt-get update -qq || true
echo -e "  -> Проверка необходимых утилит (curl, wget, jq, unzip, python3...)..."
apt-get install -y -qq curl wget jq unzip iptables qrencode openssl python3 iproute2 >/dev/null 2>&1 || true
echo -e "  ✓ Системные утилиты готовы"

echo -e "${CYAN}==> Шаг 2: Анализ и настройка шлюзов ядра Xray (3X-UI)...${NC}"
mkdir -p /etc/x-manager
ENV_FILE="/etc/x-manager/gateways.env"

XRAY_TPROXY_PORT=12345
XRAY_REDIRECT_PORT=12346
XRAY_SOCKS_PORT=10808

XUI_DB="/etc/x-ui/x-ui.db"
if [ -f "$XUI_DB" ]; then
    # Запуск умного Python скрипта детекции и внедрения
    DETECTION_OUT=$(python3 - << 'EOF'
import sqlite3, json, sys

db_path = "/etc/x-ui/x-ui.db"
tproxy_port = None
redirect_port = None
socks_port = None

try:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # 1. Проверяем таблицу inbounds (шлюзы, созданные через панель)
    try:
        for row in c.execute("SELECT id, port, protocol, stream_settings, settings, tag FROM inbounds"):
            port, proto, stream_s, settings, tag = row[1], row[2], str(row[3]), str(row[4]), str(row[5])
            if proto == "socks" and not socks_port:
                socks_port = port
            elif proto == "dokodemo-door":
                if "tproxy" in stream_s.lower() or "tproxy" in tag.lower():
                    tproxy_port = port
                elif "redirect" in settings.lower() or "redirect" in tag.lower() or "snell" in tag.lower():
                    redirect_port = port
    except Exception:
        pass

    # 1.1 Обеспечиваем наличие и корректную конфигурацию ВСЕХ 3 шлюзов в таблице inbounds базы 3X-UI
    try:
        # Порт 10808: protocol mixed, UDP включен, без авторизации, sniffing выключен
        mixed_settings = json.dumps({"auth": "noauth", "udp": True, "ip": "127.0.0.1"})
        row_10808 = c.execute("SELECT id FROM inbounds WHERE port=10808").fetchone()
        if row_10808:
            c.execute("""
                UPDATE inbounds 
                SET protocol='mixed', remark='Mixed Gateway', settings=?, stream_settings='{}',
                    tag='in-mixed-gateway', listen='127.0.0.1', enable=1, sniffing='{"enabled":false}'
                WHERE id=?
            """, (mixed_settings, row_10808[0]))
            print("UPDATED_INBOUNDS_MIXED=10808")
        else:
            c.execute("""
                INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
                VALUES (1, 0, 0, 0, 'Mixed Gateway', 1, 0, '127.0.0.1', 10808, 'mixed', ?, '{}', 'in-mixed-gateway', '{"enabled":false}')
            """, (mixed_settings,))
            print("INSERTED_INBOUNDS_MIXED=10808")

        # Порт 12345: protocol dokodemo-door (TPROXY)
        tproxy_settings = json.dumps({"network": "tcp,udp", "followRedirect": True})
        tproxy_stream = json.dumps({"sockopt": {"tproxy": "tproxy"}})
        tproxy_sniffing = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True})
        row_12345 = c.execute("SELECT id FROM inbounds WHERE port=12345").fetchone()
        if row_12345:
            c.execute("""
                UPDATE inbounds
                SET protocol='dokodemo-door', remark='TPROXY Gateway', settings=?, stream_settings=?,
                    tag='in-tproxy-gateway', listen='127.0.0.1', enable=1, sniffing=?
                WHERE id=?
            """, (tproxy_settings, tproxy_stream, tproxy_sniffing, row_12345[0]))
            print("UPDATED_INBOUNDS_TPROXY=12345")
        else:
            c.execute("""
                INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
                VALUES (1, 0, 0, 0, 'TPROXY Gateway', 1, 0, '127.0.0.1', 12345, 'dokodemo-door', ?, ?, 'in-tproxy-gateway', ?)
            """, (tproxy_settings, tproxy_stream, tproxy_sniffing))
            print("INSERTED_INBOUNDS_TPROXY=12345")

        # Порт 12346: protocol dokodemo-door (REDIRECT TCP + UDP)
        redirect_settings = json.dumps({"network": "tcp,udp", "followRedirect": True})
        redirect_sniffing = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True})
        row_12346 = c.execute("SELECT id FROM inbounds WHERE port=12346").fetchone()
        if row_12346:
            c.execute("""
                UPDATE inbounds
                SET protocol='dokodemo-door', remark='REDIRECT Gateway', settings=?, stream_settings='{}',
                    tag='in-redirect-gateway', listen='127.0.0.1', enable=1, sniffing=?
                WHERE id=?
            """, (redirect_settings, redirect_sniffing, row_12346[0]))
            print("UPDATED_INBOUNDS_REDIRECT=12346")
        else:
            c.execute("""
                INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
                VALUES (1, 0, 0, 0, 'REDIRECT Gateway', 1, 0, '127.0.0.1', 12346, 'dokodemo-door', ?, '{}', 'in-redirect-gateway', ?)
            """, (redirect_settings, redirect_sniffing))
            print("INSERTED_INBOUNDS_REDIRECT=12346")

        conn.commit()
    except Exception as e_ib:
        print(f"ERROR_INBOUNDS_TABLE={e_ib}")

    # 2. Проверяем xrayTemplateConfig в таблице settings
    c.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'")
    row = c.fetchone()
    if row:
        cfg = json.loads(row[0])
        inbounds = cfg.setdefault("inbounds", [])
        
        modified = False
        # ВАЖНО: Все 3 шлюза (10808, 12345, 12346) живут в таблице inbounds базы 3X-UI.
        # Чтобы исключить дублирование сокетов (Address already in use) при объединении конфига ядром 3X-UI,
        # удаляем их дубликаты из массива inbounds шаблона.
        gateway_ports = {10808, 12345, 12346}
        gateway_tags = {
            "in-mieru-socks", "in-mieru-gateway", "in-mixed-gateway",
            "in-wdtt-tproxy", "in-tproxy-gateway",
            "in-snell-redirect", "in-redirect-gateway"
        }
        
        inbounds_clean = [ib for ib in inbounds if ib.get("port") not in gateway_ports and ib.get("tag") not in gateway_tags]
        if len(inbounds_clean) != len(inbounds):
            cfg["inbounds"] = inbounds_clean
            inbounds = inbounds_clean
            modified = True
            print("REMOVED_GATEWAYS_FROM_TEMPLATE=1")

        socks_port = 10808
        tproxy_port = 12345
        redirect_port = 12346
        print(f"FOUND_SOCKS={socks_port}")
        print(f"FOUND_TPROXY={tproxy_port}")
        print(f"FOUND_REDIRECT={redirect_port}")

        # Обеспечиваем наличие blackhole outbound 'blocked'
        outbound_tags = [o.get("tag") for o in cfg.get("outbounds", [])]
        if "blocked" not in outbound_tags:
            cfg.setdefault("outbounds", []).append({
                "protocol": "blackhole",
                "tag": "blocked",
                "settings": {}
            })
            modified = True
            print("CREATED_BLOCKED_OUTBOUND=1")

        # Настройка Kill Switch для всех балансировщиков (fallbackTag: blocked)
        balancers = cfg.get("routing", {}).get("balancers", [])
        for b in balancers:
            if b.get("fallbackTag") != "blocked":
                b["fallbackTag"] = "blocked"
                modified = True
                print(f"PATCHED_BALANCER_FALLBACK={b.get('tag', 'balancer')}")

        if modified:
            new_val = json.dumps(cfg, indent=2, ensure_ascii=False)
            c.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (new_val,))
            conn.commit()
            print("RELOAD_XUI=1")

    conn.close()
except Exception as e:
    print(f"ERROR={e}")
EOF
)

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
                systemctl restart x-ui 2>/dev/null || true
                sleep 2
                ;;
        esac
    done
else
    echo -e "${YELLOW}  ! Локальная база Xray не обнаружена. Используем стандартные порты шлюзов ядра.${NC}"
fi

# Сохраняем переменные окружения шлюзов
cat << EOF > "$ENV_FILE"
XRAY_TPROXY_PORT=${XRAY_TPROXY_PORT}
XRAY_REDIRECT_PORT=${XRAY_REDIRECT_PORT}
XRAY_SOCKS_PORT=${XRAY_SOCKS_PORT}
EOF

# Установка Snell v5.0.1
if [ "$INSTALL_SNELL" = "yes" ]; then
    echo -e "${CYAN}==> Шаг 3: Установка и настройка Snell v5.0.1 (Hybrid TCP + UDP/QUIC)...${NC}"
    id -u snell &>/dev/null || useradd -r -s /usr/sbin/nologin snell 2>/dev/null || true
    mkdir -p /etc/snell /usr/local/bin

    SNELL_URL="https://dl.nssurge.com/snell/snell-server-v5.0.1-${SNELL_ARCH}.zip"
    tmp_snell="/tmp/snell.zip"
    echo -e "  -> Загрузка Snell v5.0.1 (${SNELL_ARCH})..."
    if curl -fL --progress-bar -o "$tmp_snell" "$SNELL_URL" || curl -fsSL -o "$tmp_snell" "$SNELL_URL"; then
        echo -e "  -> Распаковка и установка в /usr/local/bin/..."
        unzip -qo "$tmp_snell" -d /usr/local/bin/
        chmod +x /usr/local/bin/snell-server
        rm -f "$tmp_snell"
    else
        echo -e "${RED}  ✗ Не удалось скачать Snell v5 с dl.nssurge.com! Пропускаем.${NC}"
    fi

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

    echo "Snell-v5" > /etc/snell/tag.txt
    echo "$DEFAULT_ROUTING" > /etc/snell/routing.mode
    chown -R snell:snell /etc/snell
    chmod 644 /etc/snell/snell-server.conf

    # Скрипт маршрутизации snell-routing.sh с использованием подхваченного REDIRECT порта (TCP + UDP)
    cat << EOF > /usr/local/bin/snell-routing.sh
#!/usr/bin/env bash
MODE_FILE="/etc/snell/routing.mode"
MODE="xray"
[ -f "\$MODE_FILE" ] && MODE=\$(cat "\$MODE_FILE" | tr -d ' \r\n')

iptables -w 5 -t nat -D OUTPUT -m owner --uid-owner snell -j SNELL_OUT 2>/dev/null || true
iptables -w 5 -t nat -F SNELL_OUT 2>/dev/null || true
iptables -w 5 -t nat -X SNELL_OUT 2>/dev/null || true

if [ "\$MODE" = "xray" ]; then
    SNELL_PORT=\$(grep -oP '^listen\s*=\s*.*:\K[0-9]+' /etc/snell/snell-server.conf 2>/dev/null || echo "1488")

    iptables -w 5 -t nat -N SNELL_OUT 2>/dev/null || true
    iptables -w 5 -t nat -F SNELL_OUT 2>/dev/null || true
    
    # Исключения: локальный трафик и IP сервера
    iptables -w 5 -t nat -A SNELL_OUT -d 127.0.0.0/8 -j RETURN
    iptables -w 5 -t nat -A SNELL_OUT -d ${SERVER_IP} -j RETURN 2>/dev/null || true
    
    # Исключения: установленные соединения и ответы клиентам с собственного порта Snell (TCP/QUIC)
    iptables -w 5 -t nat -A SNELL_OUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
    [ -n "\$SNELL_PORT" ] && iptables -w 5 -t nat -A SNELL_OUT -p udp --sport "\$SNELL_PORT" -j RETURN 2>/dev/null || true
    [ -n "\$SNELL_PORT" ] && iptables -w 5 -t nat -A SNELL_OUT -p tcp --sport "\$SNELL_PORT" -j RETURN 2>/dev/null || true

    # Перехват исходящего TCP и UDP трафика в REDIRECT шлюз Xray
    iptables -w 5 -t nat -A SNELL_OUT -p tcp -j REDIRECT --to-ports ${XRAY_REDIRECT_PORT}
    iptables -w 5 -t nat -A SNELL_OUT -p udp -j REDIRECT --to-ports ${XRAY_REDIRECT_PORT}

    iptables -w 5 -t nat -C OUTPUT -m owner --uid-owner snell -j SNELL_OUT 2>/dev/null || iptables -w 5 -t nat -I OUTPUT 1 -m owner --uid-owner snell -j SNELL_OUT
fi
EOF
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
    iptables -I INPUT 1 -p tcp --dport "$SNELL_PORT" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT 1 -p udp --dport "$SNELL_PORT" -j ACCEPT 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable snell 2>/dev/null || true
    systemctl restart snell 2>/dev/null || true
    echo -e "  ✓ Snell v5.0.1 запущен на порту ${SNELL_PORT} (TCP + UDP QUIC)"
fi

# Установка Mieru
if [ "$INSTALL_MIERU" = "yes" ]; then
    echo -e "${CYAN}==> Шаг 4: Установка и настройка Mieru (mita) с Anti-TSPU пресетом...${NC}"
    id -u mita &>/dev/null || useradd -r -s /usr/sbin/nologin mita 2>/dev/null || true
    mkdir -p /etc/mita /usr/local/bin
    ln -sfn /etc/mita /etc/mieru

    echo -e "  -> Проверка последней доступной версии Mieru (mita) на GitHub..."
    latest_tag=$(curl -fsSL -I -o /dev/null -w '%{url_effective}' https://github.com/enfein/mieru/releases/latest 2>/dev/null | sed -e 's#.*/tag/##' -e 's#.*/tag/v##' -e 's#^v##')
    if [ -z "$latest_tag" ] || [[ "$latest_tag" =~ "github.com" ]]; then
        latest_tag=$(curl -fsSL https://api.github.com/repos/enfein/mieru/releases/latest 2>/dev/null | grep -o '"tag_name": *"[^"]*' | sed -e 's/"tag_name": *"//' -e 's/^v//')
    fi
    mita_ver="${latest_tag:-3.37.0}"
    echo -e "  -> Актуальная версия Mieru: ${GREEN}v${mita_ver}${NC}"

    case "$ARCH" in
        x86_64) DEB_ARCH="amd64" ;;
        aarch64|arm64) DEB_ARCH="arm64" ;;
        *) DEB_ARCH="amd64" ;;
    esac

    need_download=false
    if ! command -v mita &>/dev/null; then
        need_download=true
    else
        cur_mita_ver=$(mita version 2>/dev/null | head -n1 | tr -d 'v[:space:]')
        if [ "$cur_mita_ver" != "$mita_ver" ]; then
            echo -e "  -> Обнаружена версия v${cur_mita_ver}. Обновляем до последней v${mita_ver}..."
            need_download=true
        else
            echo -e "  ✓ Mieru уже установлен актуальной версии (v${cur_mita_ver})."
        fi
    fi

    if $need_download; then
        echo -e "  -> Скачивание пакета Mieru v${mita_ver} с GitHub (~30 MB, подождите)..."
        if curl -fL --progress-bar -o /tmp/mita.deb "https://github.com/enfein/mieru/releases/download/v${mita_ver}/mita_${mita_ver}_${DEB_ARCH}.deb" || curl -fsSL -o /tmp/mita.deb "https://github.com/enfein/mieru/releases/download/v${mita_ver}/mita_${mita_ver}_${DEB_ARCH}.deb"; then
            if [ -s /tmp/mita.deb ]; then
                echo -e "  -> Распаковка и установка пакета mita через dpkg..."
                dpkg -i /tmp/mita.deb 2>/dev/null || apt-get install -f -y 2>/dev/null || true
                rm -f /tmp/mita.deb
            fi
        fi
        if ! command -v mita &>/dev/null || [ "$(mita version 2>/dev/null | head -n1 | tr -d 'v[:space:]')" != "$mita_ver" ]; then
            echo -e "  -> Резервный канал: скачивание архива tar.gz..."
            curl -fL --progress-bar "https://github.com/enfein/mieru/releases/download/v${mita_ver}/mita_${mita_ver}_linux_${DEB_ARCH}.tar.gz" | tar -xz -C /usr/local/bin/ mita 2>/dev/null || true
            chmod +x /usr/local/bin/mita 2>/dev/null || true
        fi
    fi
    ln -sf /usr/bin/mita /usr/local/bin/mita 2>/dev/null || true
    ln -sf /usr/local/bin/mita /usr/bin/mita 2>/dev/null || true
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
        echo "{\"${MIERU_USER}\": \"${MIERU_PASS}\"}" > /etc/mita/users_db.json
    fi
    echo "$SERVER_IP" > /etc/mita/server_ip.txt
    echo "Mieru-Home" > /etc/mita/tag.txt

    chown -R mita:mita /etc/mita
    chmod 664 /etc/mita/config.json /etc/mita/users_db.json 2>/dev/null || true

    which_mita=$(command -v mita || echo "/usr/bin/mita")
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
        iptables -I INPUT 1 -p "$ipt_proto" --dport "${p_s}:${p_e}" -j ACCEPT 2>/dev/null || true
    else
        iptables -I INPUT 1 -p "$ipt_proto" --dport "$MIERU_PORTS" -j ACCEPT 2>/dev/null || true
    fi

    echo -e "  -> Запуск и проверка службы mita..."
    systemctl daemon-reload
    systemctl enable mita 2>/dev/null || true
    systemctl restart mita 2>/dev/null || true
    echo -e "  ✓ Mieru запущен на портах ${MIERU_PORTS}/${MIERU_PROTO} (Anti-TSPU Balanced)"
fi

# Интеграция qwdtt с использованием подхваченного TPROXY порта
echo -e "${CYAN}==> Шаг 5: Интеграция qwdtt / WDTT TPROXY...${NC}"
echo -e "  -> Настройка скрипта wdtt-tproxy.sh и правил перехвата..."
cat << EOF > /usr/local/bin/wdtt-tproxy.sh
#!/usr/bin/env bash
set -e
WAN_IF="${WAN_IF}"
TPROXY_PORT="${XRAY_TPROXY_PORT}"
SERVER_IP="${SERVER_IP}"

MODE_FILE="/etc/wdtt/routing.mode"
MODE="xray"
[ -f "\$MODE_FILE" ] && MODE=\$(cat "\$MODE_FILE" | tr -d ' \r\n')

# Очистка предыдущих хуков
iptables -w 5 -t mangle -D PREROUTING -i wdtt0 -j WDTT_TPROXY 2>/dev/null || true
iptables -w 5 -t mangle -D PREROUTING -i wdttraw0 -j WDTT_TPROXY 2>/dev/null || true
iptables -w 5 -t mangle -F WDTT_TPROXY 2>/dev/null || true
iptables -w 5 -t mangle -X WDTT_TPROXY 2>/dev/null || true

if [ "\$MODE" = "xray" ]; then
    # 1. Routing table 100
    ip rule show | grep -q "lookup 100" || ip rule add fwmark 1 table 100
    ip route show table 100 | grep -q "local default dev lo" || ip route add local 0.0.0.0/0 dev lo table 100

    # 2. iptables MANGLE rules
    iptables -w 5 -t mangle -N WDTT_TPROXY 2>/dev/null || true
    iptables -w 5 -t mangle -F WDTT_TPROXY 2>/dev/null || true

    # Exclude local/internal
    iptables -w 5 -t mangle -A WDTT_TPROXY -d 10.66.0.0/16 -j RETURN
    iptables -w 5 -t mangle -A WDTT_TPROXY -d 10.70.0.0/16 -j RETURN
    iptables -w 5 -t mangle -A WDTT_TPROXY -d 127.0.0.0/8 -j RETURN
    [ -n "\$SERVER_IP" ] && iptables -w 5 -t mangle -A WDTT_TPROXY -d "\$SERVER_IP" -j RETURN 2>/dev/null || true

    # TPROXY to 127.0.0.1
    iptables -w 5 -t mangle -A WDTT_TPROXY -p tcp -j TPROXY --on-port \${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark 1
    iptables -w 5 -t mangle -A WDTT_TPROXY -p udp -j TPROXY --on-port \${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark 1

    # Hook to PREROUTING
    iptables -w 5 -t mangle -I PREROUTING 1 -i wdtt0 -j WDTT_TPROXY 2>/dev/null || true
    iptables -w 5 -t mangle -I PREROUTING 1 -i wdttraw0 -j WDTT_TPROXY 2>/dev/null || true

    # 3. Block external access from internet
    iptables -w 5 -C INPUT -i "\${WAN_IF}" -p tcp --dport "\${TPROXY_PORT}" -j DROP 2>/dev/null || iptables -w 5 -I INPUT 1 -i "\${WAN_IF}" -p tcp --dport "\${TPROXY_PORT}" -j DROP
    iptables -w 5 -C INPUT -i "\${WAN_IF}" -p udp --dport "\${TPROXY_PORT}" -j DROP 2>/dev/null || iptables -w 5 -I INPUT 1 -i "\${WAN_IF}" -p udp --dport "\${TPROXY_PORT}" -j DROP

    # 4. Remove direct MASQUERADE (Kill Switch for direct leak)
    while iptables -w 5 -t nat -D POSTROUTING -s 10.66.0.0/16 -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.66.0.0/16 -o "\${WAN_IF}" -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.66.0.0/16 -o "\${WAN_IF}" -m comment --comment WDTT_MANAGED -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.70.0.0/16 -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.70.0.0/16 -o "\${WAN_IF}" -j MASQUERADE 2>/dev/null; do :; done
    while iptables -w 5 -t nat -D POSTROUTING -s 10.70.0.0/16 -o "\${WAN_IF}" -m comment --comment WDTT_RAW_MANAGED -j MASQUERADE 2>/dev/null; do :; done
else
    # Режим Direct WAN: Включаем прямой MASQUERADE
    iptables -w 5 -t nat -C POSTROUTING -s 10.66.0.0/16 -o "\${WAN_IF}" -m comment --comment WDTT_MANAGED -j MASQUERADE 2>/dev/null || \
        iptables -w 5 -t nat -A POSTROUTING -s 10.66.0.0/16 -o "\${WAN_IF}" -m comment --comment WDTT_MANAGED -j MASQUERADE
    iptables -w 5 -t nat -C POSTROUTING -s 10.70.0.0/16 -o "\${WAN_IF}" -m comment --comment WDTT_RAW_MANAGED -j MASQUERADE 2>/dev/null || \
        iptables -w 5 -t nat -A POSTROUTING -s 10.70.0.0/16 -o "\${WAN_IF}" -m comment --comment WDTT_RAW_MANAGED -j MASQUERADE
fi
EOF
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

if [ "$DEFAULT_ROUTING" = "xray" ]; then
    systemctl daemon-reload
    systemctl enable wdtt-tproxy 2>/dev/null || true
    systemctl restart wdtt-tproxy 2>/dev/null || true
    echo -e "  ✓ WDTT TPROXY маршрутизация активирована (TPROXY :${XRAY_TPROXY_PORT})"
else
    echo -e "  ✓ WDTT маршрутизация: Прямой выход"
fi

# Настройка безопасности (Блокировка шлюзов извне и открытие портов протоколов)
echo -e "${CYAN}==> Шаг 6: Настройка сетевой безопасности...${NC}"
iptables -I INPUT 1 -i "$WAN_IF" -p tcp --dport "${XRAY_TPROXY_PORT}" -j DROP 2>/dev/null || true
iptables -I INPUT 1 -i "$WAN_IF" -p udp --dport "${XRAY_TPROXY_PORT}" -j DROP 2>/dev/null || true
iptables -I INPUT 1 -i "$WAN_IF" -p tcp --dport "${XRAY_REDIRECT_PORT}" -j DROP 2>/dev/null || true
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
echo -e "${CYAN}==> Шаг 7: Автоопределение SSL-сертификатов (3X-UI / /root/cert / Let's Encrypt)...${NC}"
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
    echo -e "  ℹ️ SSL сертификат не найден локально (выпускается штатно в панели 3X-UI)"
fi

# Установка диспетчера x-manager
echo -e "${CYAN}==> Шаг 8: Развертывание диспетчера x-manager...${NC}"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ -f "$SCRIPT_DIR/bin/x-manager" ]; then
    echo -e "  -> Установка x-manager из локального каталога..."
    cp -f "$SCRIPT_DIR/bin/x-manager" /usr/local/bin/x-manager
else
    echo -e "  -> Загрузка диспетчера x-manager с GitHub..."
    curl -fL --progress-bar -o /usr/local/bin/x-manager "https://raw.githubusercontent.com/lesovoi53/xray-manager/main/bin/x-manager?v=$(date +%s)" || curl -fsSL -o /usr/local/bin/x-manager "https://raw.githubusercontent.com/lesovoi53/xray-manager/main/bin/x-manager?v=$(date +%s)" 2>/dev/null || true
fi
chmod +x /usr/local/bin/x-manager

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
echo -e "  ✓ Диспетчер x-manager успешно развернут"

echo -e "${CYAN}==> Шаг 9: Развертывание сервера подписок TUNA (tuna-subscriptions)...${NC}"
if [ -f "$SCRIPT_DIR/tuna-sub-server/install-sub-server.sh" ]; then
    bash "$SCRIPT_DIR/tuna-sub-server/install-sub-server.sh" || true
else
    echo -e "  -> Загрузка компонентов сервера подписок с GitHub..."
    mkdir -p /tmp/tuna-sub-install
    curl -fsSL -o /tmp/tuna-sub-install/tuna-subscriptions.py "https://raw.githubusercontent.com/lesovoi53/xray-manager/main/tuna-sub-server/tuna-subscriptions.py?v=$(date +%s)" 2>/dev/null || true
    curl -fsSL -o /tmp/tuna-sub-install/config.toml.example "https://raw.githubusercontent.com/lesovoi53/xray-manager/main/tuna-sub-server/config.toml.example?v=$(date +%s)" 2>/dev/null || true
    curl -fsSL -o /tmp/tuna-sub-install/tuna-subscriptions.service "https://raw.githubusercontent.com/lesovoi53/xray-manager/main/tuna-sub-server/tuna-subscriptions.service?v=$(date +%s)" 2>/dev/null || true
    curl -fsSL -o /tmp/tuna-sub-install/install-sub-server.sh "https://raw.githubusercontent.com/lesovoi53/xray-manager/main/tuna-sub-server/install-sub-server.sh?v=$(date +%s)" 2>/dev/null || true
    if [ -f /tmp/tuna-sub-install/install-sub-server.sh ]; then
        bash /tmp/tuna-sub-install/install-sub-server.sh || true
    fi
    rm -rf /tmp/tuna-sub-install
fi

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}             УСТАНОВКА X-MANAGER УСПЕШНО ЗАВЕРШЕНА!                   ${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Для входа в интерактивное меню запустите:${NC}"
echo -e "  ${CYAN}${BOLD}x-manager${NC}   - Главный центр управления всеми службами"
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
if [ "$INSTALL_SNELL" = "yes" ]; then
    echo -e "${BOLD}Параметры Snell v5 (Hybrid TCP + UDP/QUIC):${NC}"
    echo -e "  • Сервер: ${SERVER_IP}:${SNELL_PORT}"
    echo -e "  • PSK:    ${GREEN}${SNELL_PSK}${NC}"
    echo -e "  • Режим:  Гибридный (NekoBox+: TCP, Surge: QUIC/UDP 0-RTT)"
    echo -e "  • Ссылка: ${CYAN}snell://${SNELL_PSK}@${SERVER_IP}:${SNELL_PORT}/?version=5#Snell-v5${NC}"
    echo ""
fi
if [ "$INSTALL_MIERU" = "yes" ]; then
    echo -e "${BOLD}Параметры Mieru (mita):${NC}"
    echo -e "  • Сервер: ${SERVER_IP} (Порты: ${MIERU_PORTS})"
    echo -e "  • Логин:  ${MIERU_USER} | Пароль: ${GREEN}${MIERU_PASS}${NC}"
    echo -e "  • Защита: Low-Entropy 48-bit + Rotate Right 7"
    pattern=$(mita export traffic-pattern 2>/dev/null || echo "")
    echo -e "  • Ссылка: ${CYAN}mierus://${MIERU_USER}:${MIERU_PASS}@${SERVER_IP}/?profile=Mieru-Home&port=${MIERU_PORTS}&protocol=${MIERU_PROTO}&multiplexing=MULTIPLEXING_HIGH&traffic-pattern=${pattern}&low-entropy-mode=LOW_ENTROPY_MODE_48&low-entropy-mask-rotation=LOW_ENTROPY_MASK_ROTATE_RIGHT_7${NC}"
    echo ""
fi
if command -v wdtt >/dev/null 2>&1 || [ -f "/etc/systemd/system/wdtt.service" ] || [ -d "/etc/wdtt" ]; then
    wdtt_p="56000"
    [ -f "/etc/systemd/system/wdtt.service" ] && wdtt_p=$(grep -oP -- '(^|\s)-listen\s+[0-9.]+:\K[0-9]+' /etc/systemd/system/wdtt.service 2>/dev/null | head -n 1 || echo "56000")
    wdtt_pass="sad_534188_sad"
    [ -f "/etc/wdtt/main.password" ] && wdtt_pass=$(cat /etc/wdtt/main.password | tr -d '\r\n')
    prof_name="WDTT-${SERVER_IP}"
    [ -f "/etc/wdtt/profile_name.txt" ] && prof_name=$(cat /etc/wdtt/profile_name.txt | tr -d '\r\n')
    
    qwdtt_link=$(python3 -c "
import urllib.parse, sys
name, ip, port, password = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
print(f'qwdtt://config?name={urllib.parse.quote_plus(name)}&peer={ip}%3A{port}&hashes=&workers=18&port=9000&pass={urllib.parse.quote_plus(password)}')
" "$prof_name" "$SERVER_IP" "$wdtt_p" "$wdtt_pass" 2>/dev/null || echo "")

    echo -e "${BOLD}Параметры WDTT / qwdtt:${NC}"
    echo -e "  • Сервер:   ${SERVER_IP}:${wdtt_p}"
    echo -e "  • Профиль:  ${prof_name}"
    echo -e "  • Пароль:   ${GREEN}${wdtt_pass}${NC}"
    echo -e "  • Ссылка:   ${CYAN}${qwdtt_link}${NC}"
    echo ""
fi
echo -e "${GREEN}Все службы запущены и работают в фоновом режиме.${NC}"
