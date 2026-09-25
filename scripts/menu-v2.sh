#!/usr/bin/env bash
# Presentation/navigation only. Opening a page must never change the firewall.
xm_choose_action() {
    local xm_name=$1 xm_target=$2 xm_file xm_title xm_section xm_row xm_action xm_label xm_pick xm_group
    local -a xm_sections=() xm_ids=() xm_labels=()
    xm_file="$(dirname "${BASH_SOURCE[0]}")/menu-actions.tsv"
    [ -r "$xm_file" ] || { echo 'Missing menu action catalog' >&2; return 1; }
    while IFS='|' read -r xm_row xm_title xm_section xm_action xm_label; do
        [ "$xm_row" = "$xm_name" ] || continue
        if [ "$xm_section" = 'Панель 3X-UI' ] && [ ! -f /etc/x-ui/x-ui.db ]; then continue; fi
        [[ "|${xm_sections[*]}|" = *"$xm_section"* ]] || xm_sections+=("$xm_section")
    done < "$xm_file"
    xm_title=$(awk -F'|' -v n="$xm_name" '$1==n {print $2; exit}' "$xm_file")
    while true; do
        xm_header "$xm_title"
        case "$xm_name" in
            menu_mieru) printf '  Служба: %b\n' "$(get_mieru_status)";;
            menu_snell) printf '  Служба: %b\n' "$(get_snell_status)";;
            menu_openflux) printf '  Служба: %b | режим: %s\n' "$(get_openflux_status)" "$(get_openflux_pool_mode_label)";;
            menu_webdav_tunnel) printf '  Служба: %b | %s\n' "$(get_wdavtunnel_status)" "$(get_wdavtunnel_provider_label)";;
            menu_subscriptions) printf '  Служба: %b\n  Включение OpenFlux/WebDAV задаётся отдельно у каждого пользователя.\n' "$(get_sub_server_status)";;
        esac
        for xm_pick in "${!xm_sections[@]}"; do printf '  [%d] %s\n' "$((xm_pick+1))" "${xm_sections[xm_pick]}"; done
        printf '  [0] Назад\n'
        read -r -p 'Раздел: ' xm_pick || return 1
        [ "$xm_pick" != 0 ] || { printf -v "$xm_target" '%s' 0; return; }
        [[ "$xm_pick" =~ ^[1-9][0-9]*$ ]] && ((xm_pick<=${#xm_sections[@]})) || continue
        xm_group=${xm_sections[xm_pick-1]}
        xm_ids=(); xm_labels=()
        while IFS='|' read -r xm_row xm_title xm_section xm_action xm_label; do
            [ "$xm_row" = "$xm_name" ] && [ "$xm_section" = "$xm_group" ] || continue
            if [ "$xm_name" = menu_webdav_tunnel ] && [ "$xm_action" = 6 ]; then
                case "$(get_wdavtunnel_mode)" in selfhosted|custom) ;; *) continue;; esac
            fi
            xm_ids+=("$xm_action"); xm_labels+=("$xm_label")
        done < "$xm_file"
        xm_header "$xm_group"
        for xm_pick in "${!xm_ids[@]}"; do printf '  [%d] %s\n' "$((xm_pick+1))" "${xm_labels[xm_pick]}"; done
        echo '  [0] Назад'
        read -r -p 'Действие: ' xm_pick || return 1
        [ "$xm_pick" != 0 ] || continue
        [[ "$xm_pick" =~ ^[1-9][0-9]*$ ]] && ((xm_pick<=${#xm_ids[@]})) || continue
        printf -v "$xm_target" '%s' "${xm_ids[xm_pick-1]}"
        return
    done
}
xm_pause() { read -r -p 'Enter — назад: ' _ || return 0; }
xm_confirm() {
    printf '\n%s\n  [1] Продолжить\n  [0] Отмена\n' "$1"
    local answer
    read -r -p 'Выбор: ' answer && [ "$answer" = 1 ]
}
xm_header() { clear; printf '\n  X-MANAGER / %s\n  ────────────────────────────────────────────────\n' "$1"; }
xm_release_update() {
    xm_header 'Обновление полного выпуска'
    python3 -c 'import json; d=json.load(open("/usr/local/share/x-manager/components.json")); print("Установленный выпуск:",d["release"]); print("Компоненты:", ", ".join(k+" "+v for k,v in d["versions"].items()))' || return 1
    echo 'Источник: lesovoi53/xray-manager. Версии компонентов закреплены выпуском.'
    echo 'Будут сохранены данные и настройки; службы пакета будут перезапущены.'
    xm_confirm 'Получить и установить последний опубликованный выпуск?' || return 1
    if bash /usr/local/share/x-manager/scripts/update-release.sh; then
        echo 'Обновление завершено. Открываю новую версию меню.'
        exec /usr/local/bin/x-manager
    else
        echo 'Обновление не завершено. Проверьте ошибку и результат восстановления выше.' >&2
        xm_pause
        return 1
    fi
}
xm_services_menu() {
    local choice
    while true; do
        xm_header 'Службы и туннели'
        printf '  [1] Mieru              %b\n' "$(get_mieru_status)"
        printf '  [2] Snell              %b\n' "$(get_snell_status)"
        printf '  [3] WebDAV             %b\n' "$(get_wdavtunnel_status)"
        printf '  [4] OpenFlux           %b\n' "$(get_openflux_status)"
        printf '  [5] DNS-туннели        %b\n' "$(get_dns_status)"
        printf '  [6] WDTT / qwdtt       %b\n' "$(get_wdtt_status)"
        printf '  [7] CSQTT              %b\n' "$(get_csqtt_status)"
        printf '\n  [0] Назад\n'
        read -r -p 'Служба: ' choice || return
        case "$choice" in
            1) menu_mieru;; 2) menu_snell;; 3) menu_webdav_tunnel;;
            4) menu_openflux;; 5) menu_dns;; 6) menu_wdtt;; 7) menu_csqtt;;
            0) return;; *) echo 'Выберите номер из списка'; sleep 1;;
        esac
    done
}
xm_xray_menu() {
    local choice
    while true; do
        xm_header 'Xray и маршрутизация'
        echo 'Поддерживаются standalone Xray и ядро под управлением панели.'
        echo 'Сохранённые шлюзы:'
        if [ -r /etc/x-manager/gateways.env ]; then
            grep -E '^XRAY_(SOCKS|REDIRECT|TPROXY)_PORT=[0-9]+$' /etc/x-manager/gateways.env
        else
            echo 'Пока не заданы.'
        fi
        printf '\n  [1] Обнаружить шлюзы в конфигурации Xray\n  [2] Проверить доступность сохранённых шлюзов\n  [3] Маршрутизация отдельных служб\n  [4] Справка для standalone Xray\n  [0] Назад\n'
        read -r -p 'Действие: ' choice || return
        case "$choice" in
            1) python3 /usr/local/share/x-manager/scripts/xray-discovery.py; xm_pause;;
            2) (
                set -a
                [ ! -r /etc/x-manager/gateways.env ] || . /etc/x-manager/gateways.env
                python3 /usr/local/share/x-manager/scripts/xray-discovery.py --verify && echo 'TCP-шлюзы доступны; SOCKS5 принял соединение без авторизации. UDP/маршрут проверяются отдельно.'
                ); xm_pause;;
            3) xm_services_menu;;
            4) printf '%s\n' 'При установке: XM_XRAY_CONFIG=/путь/config.json bash install.sh' 'Также поддерживается каталог конфигураций и явно заданные XRAY_*_PORT.' 'Шлюзы: SOCKS5 без авторизации, dokodemo-door REDIRECT и TPROXY tcp,udp; listen 127.0.0.1.' 'Конфигурация standalone Xray не перезаписывается. Порты 443 и 8443 исключены.' 'Если Xray не нужен: bash install.sh --direct'; xm_pause;;
            0) return;; *) echo 'Выберите номер из списка'; sleep 1;;
        esac
    done
}
xm_security_menu() {
    local choice
    while true; do
        xm_header 'Сеть и безопасность'
        printf '  [1] Фаервол и доступ к портам\n  [2] SSL-сертификаты\n  [3] DNS системы / BBR / Swap / Fail2ban\n  [0] Назад\n'
        read -r -p 'Раздел: ' choice || return
        case "$choice" in 1) menu_firewall;; 2) menu_ssl;; 3) menu_system_opt;; 0) return;; *) echo 'Неверный выбор';; esac
    done
}
xm_backup_menu() {
    local choice backup
    local -a backups=()
    xm_header 'Восстановление'
    while IFS= read -r backup; do
        [ ! -f "$backup/state.json" ] || backups+=("$backup")
    done < <(find /var/backups -mindepth 1 -maxdepth 1 -type d -name 'x-manager-*' | sort -r)
    if [ "${#backups[@]}" = 0 ]; then echo 'Резервных копий установщика нет.'; xm_pause; return; fi
    for choice in "${!backups[@]}"; do printf '  [%d] %s\n' "$((choice+1))" "${backups[choice]}"; done
    echo '  [0] Назад'
    read -r -p 'Копия: ' choice || return
    [[ "$choice" =~ ^[1-9][0-9]*$ ]] && ((choice<=${#backups[@]})) || return
    backup=${backups[choice-1]}
    xm_confirm 'Восстановить файлы, данные и состояние служб из выбранной копии? Более новые изменения будут заменены.' || return
    (
        flock -n 9 || { echo 'Установка уже выполняется' >&2; exit 1; }
        python3 "$backup/installer-state.py" restore "$backup"
    ) 9>/run/lock/x-manager-install.lock || { echo 'Восстановление не завершено' >&2; xm_pause; return 1; }
    exec /usr/local/bin/x-manager
}
xm_maintenance_menu() {
    local choice
    while true; do
        xm_header 'Обслуживание'
        printf '  [1] Обновить полный выпуск\n  [2] Восстановить резервную копию\n  [3] Пересканировать и подхватить службы\n  [4] Перезапустить службы пакета\n  [0] Назад\n'
        read -r -p 'Действие: ' choice || return
        case "$choice" in
            1) xm_release_update;; 2) xm_backup_menu;;
            3) xm_confirm 'Подхватить обнаруженные службы? Это может обновить служебные настройки.' && rescan_and_adopt_protocols;;
            4) xm_confirm 'Перезапуск прервёт текущие подключения.' && restart_all_services;;
            0) return;; *) echo 'Неверный выбор';;
        esac
    done
}
xm_home() {
    local choice
    while true; do
        xm_header 'Главная'
        printf '  Сервер: %s\n  Подписки: %b\n' "$SERVER_IP" "$(get_sub_server_status)"
        printf '\n  [1] Пользователи и подписки TUNA\n  [2] Службы и туннели\n  [3] Xray и маршрутизация\n  [4] Сеть и безопасность\n  [5] Диагностика и состояние служб\n  [6] Обновление и восстановление\n  [7] Справка\n  [0] Выход\n\n'
        read -r -p 'Раздел: ' choice || return
        case "$choice" in
            1) menu_subscriptions;; 2) xm_services_menu;; 3) xm_xray_menu;; 4) xm_security_menu;;
            5) view_global_status;; 6) xm_maintenance_menu;;
            7) printf '%s\n' '0 — назад; изменения выполняются только выбранным действием.' 'Выход из меню не останавливает службы и не запускает обновление.' 'Состояние службы, включение в подписку и состояние теста на телефоне — разные статусы.' 'URL-test / Speedtest запускаются клиентом после явного подключения.' 'Все реквизиты сохраняются при обновлении. Секретные ссылки показываются отдельным действием.'; xm_pause;;
            0) echo 'Меню закрыто. Службы продолжают работать.'; return;;
            *) echo 'Выберите номер из списка'; sleep 1;;
        esac
    done
}
