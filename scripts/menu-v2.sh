#!/usr/bin/env bash
# Presentation/navigation only. Opening a page must never change the firewall.
xm_service_menu_unit() {
    case "$1" in
        menu_mieru) echo mita.service;; menu_snell) echo snell.service;;
        menu_webdav_tunnel) echo webdav-tunnel.service;; menu_subscriptions) echo tuna-subscriptions.service;;
        menu_wdtt) echo wdtt.service;; menu_csqtt) echo csqtt.service;;
        *) return 1;;
    esac
}
xm_direct_service_action() {
    local action=$1 unit=$2 warning
    case "$action" in on) ;; off)
        warning="Выключить $unit постоянно? Настройки и ссылки сохранятся."
        [ "$unit" != fail2ban.service ] || warning+=' Это отключит защиту от перебора паролей.'
        xm_confirm "$warning" || return 0;; *) return 1;;
    esac
    if [ "$action" = on ] && [ "$unit" = snell.service ]; then
        xm_confirm 'Активировать Snell v5 вместо v6? При ошибке прежнее состояние будет восстановлено.' || return 0
        python3 "$(dirname "${BASH_SOURCE[0]}")/snell-switch.py" switch --version 5 || { echo 'Переключение не выполнено.' >&2; return 1; }
        return 0
    fi
    python3 "$(dirname "${BASH_SOURCE[0]}")/service-control.py" "$action" "$unit" || {
        echo 'Операция не завершена; проверьте ошибку выше.' >&2; xm_pause; return 1;
    }
}
xm_openflux_all_action() {
    local action=$1 channel url failed=0 helper="$(dirname "${BASH_SOURCE[0]}")/service-control.py"
    case "$action" in
        off) xm_confirm 'Выключить все 8 каналов OpenFlux постоянно? Настройки и ссылки сохранятся.' || return 0;;
        on) ;; *) return 1;;
    esac
    for channel in {1..8}; do
        if [ "$action" = on ]; then
            url=$(get_openflux_channel_prop "$channel" URL '') || { failed=1; continue; }
            [[ "$url" =~ [^[:space:]] ]] || continue
        fi
        python3 "$helper" "$action" "openflux@$channel.service" || failed=1
    done
    if [ "$failed" = 1 ]; then echo 'Не все каналы обработаны; проверьте ошибки выше.' >&2; xm_pause; return 1; fi
}
xm_print_service_controls() {
    local unit
    if unit=$(xm_service_menu_unit "$1"); then
        printf '  [90] Включить службу\n  [91] Выключить постоянно\n'
    elif [ "$1" = menu_dns ]; then
        printf '  [90] Включить CottenDNS\n  [91] Выключить CottenDNS постоянно\n'
        printf '  [92] Включить MasterDNS\n  [93] Выключить MasterDNS постоянно\n'
    elif [ "$1" = menu_openflux ]; then
        printf '  [90] Включить настроенные каналы\n  [91] Выключить все каналы постоянно\n'
    fi
}
xm_handle_service_control() {
    local name=$1 choice=$2 unit action
    case "$name:$choice" in
        menu_openflux:90) xm_openflux_all_action on || return 0; return 0;;
        menu_openflux:91) xm_openflux_all_action off || return 0; return 0;;
        menu_dns:90) unit=cottendns.service; action=on;; menu_dns:91) unit=cottendns.service; action=off;;
        menu_dns:92) unit=masterdns.service; action=on;; menu_dns:93) unit=masterdns.service; action=off;;
        *:90|*:91)
            unit=$(xm_service_menu_unit "$name") || return 1
            [ "$choice" != 90 ] && action=off || action=on;;
        *) return 1;;
    esac
    xm_direct_service_action "$action" "$unit" || return 0
}
xm_openflux_channel_actions() {
    local channel=$1 choice
    [[ "$channel" =~ ^[1-8]$ ]] || return 1
    while true; do
        xm_header "OpenFlux — канал $channel"
        printf '  [1] Изменить ссылку и транспорт\n  [90] Включить канал\n  [91] Выключить канал постоянно\n  [0] Назад\n'
        read -r -p 'Действие канала: ' choice || return 1
        case "$choice" in
            1) return 0;; 90) xm_direct_service_action on "openflux@$channel.service";;
            91) xm_direct_service_action off "openflux@$channel.service";; 0) return 1;;
        esac
    done
}
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
        [ "$xm_name" != menu_snell ] || xm_title='Snell v5'
        xm_header "$xm_title"
        case "$xm_name" in
            menu_mieru) printf '  Служба: %b\n' "$(get_mieru_status)";;
            menu_snell) printf '  Служба Snell v5: %b\n' "$(get_snell_status)"
                printf '  Snell v6: настройки находятся в разделе Snell → [2].\n'
                printf '  Кнопки включения и постоянного отключения находятся ниже.\n';;
            menu_openflux) printf '  Служба: %b | режим: %s\n' "$(get_openflux_status)" "$(get_openflux_pool_mode_label)";;
            menu_webdav_tunnel) printf '  Служба: %b | %s\n' "$(get_wdavtunnel_status)" "$(get_wdavtunnel_provider_label)";;
            menu_subscriptions) printf '  Служба: %b\n  Включение OpenFlux/WebDAV задаётся отдельно у каждого пользователя.\n' "$(get_sub_server_status)";;
        esac
        for xm_pick in "${!xm_sections[@]}"; do printf '  [%d] %s\n' "$((xm_pick+1))" "${xm_sections[xm_pick]}"; done
        xm_print_service_controls "$xm_name"
        printf '  [0] Назад\n'
        read -r -p 'Раздел: ' xm_pick || return 1
        if xm_handle_service_control "$xm_name" "$xm_pick"; then continue; fi
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
        if [ "$xm_name" = menu_snell ]; then xm_header "Snell v5 / $xm_group"; else xm_header "$xm_group"; fi
        for xm_pick in "${!xm_ids[@]}"; do printf '  [%d] %s\n' "$((xm_pick+1))" "${xm_labels[xm_pick]}"; done
        xm_print_service_controls "$xm_name"
        echo '  [0] Назад'
        read -r -p 'Действие: ' xm_pick || return 1
        if xm_handle_service_control "$xm_name" "$xm_pick"; then continue; fi
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
    echo 'Данные, настройки и автозапуск сохраняются; перезапускаются ранее работавшие службы.'
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
xm_snell_menu() {
    local choice
    while true; do
        xm_header 'Snell — версия сервера'
        printf '  [1] Snell v5   %b\n' "$(get_snell_status)"
        printf '  [2] Snell v6\n'
        printf '  Выбор открывает настройки. Одновременно активна одна версия.\n'
        printf '  Включение и постоянное отключение — в настройках выбранной реализации.\n'
        printf '  [0] Назад\n'
        read -r -p 'Реализация: ' choice || return
        case "$choice" in
            1) menu_snell;;
            2) python3 "$(dirname "${BASH_SOURCE[0]}")/snell6-endpoints.py" menu || { echo 'Операция Snell v6 не завершена; проверьте ошибку выше.' >&2; xm_pause; };;
            0) return;; *) echo 'Выберите номер из списка';;
        esac
    done
}
xm_services_menu() {
    local choice
    while true; do
        xm_header 'Службы и туннели'
        printf '  [1] Mieru              %b\n' "$(get_mieru_status)"
        printf '  [2] Snell — v5 / v6\n'
        printf '  [3] WebDAV             %b\n' "$(get_wdavtunnel_status)"
        printf '  [4] OpenFlux           %b\n' "$(get_openflux_status)"
        printf '  [5] DNS-туннели        %b\n' "$(get_dns_status)"
        printf '  [6] WDTT / qwdtt       %b\n' "$(get_wdtt_status)"
        printf '  [7] CSQTT              %b\n' "$(get_csqtt_status)"
        printf '  [8] Включение, постоянное отключение и автозапуск\n'
        printf '\n  [0] Назад\n'
        read -r -p 'Служба: ' choice || return
        case "$choice" in
            1) menu_mieru;; 2) xm_snell_menu;; 3) menu_webdav_tunnel;;
            4) menu_openflux;; 5) menu_dns;; 6) menu_wdtt;; 7) menu_csqtt;;
            8) python3 "$(dirname "${BASH_SOURCE[0]}")/service-control.py" menu;;
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
        printf '  [90] Включить standalone Xray\n  [91] Выключить standalone Xray постоянно\n'
        printf '  [92] Включить ядро и панель 3X-UI\n  [93] Выключить ядро и панель 3X-UI постоянно\n'
        read -r -p 'Действие: ' choice || return
        case "$choice" in
            90) xm_direct_service_action on xray.service;; 91) xm_direct_service_action off xray.service;;
            92) xm_direct_service_action on x-ui.service;; 93) xm_direct_service_action off x-ui.service;;
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
        printf '  [1] Фаервол и доступ к портам\n  [2] SSL-сертификаты\n  [3] DNS системы / BBR / Swap / Fail2ban\n  [4] Управляемый профиль BBR/fq с откатом\n  [0] Назад\n'
        read -r -p 'Раздел: ' choice || return
        case "$choice" in 1) menu_firewall;; 2) menu_ssl;; 3) menu_system_opt;; 4) xm_network_profile_menu;; 0) return;; *) echo 'Неверный выбор';; esac
    done
}
xm_network_profile_menu() {
    local choice helper ready=0
    helper="$(dirname "${BASH_SOURCE[0]}")/network-profile.py"
    python3 "$helper" plan || ready=$?
    printf '  [1] Применить показанный профиль\n  [2] Откатить профиль\n  [0] Назад\n'
    read -r -p 'Действие: ' choice || return
    case "$choice" in
        1) [ "$ready" = 0 ] || { echo 'План не готов; доступен откат и диагностика.' >&2; return 1; }
           xm_confirm 'Применить BBR/fq для новых соединений и очередей?' && python3 "$helper" apply;;
        2) xm_confirm 'Восстановить сохранённые значения профиля?' && python3 "$helper" rollback;;
        0) return;;
    esac
    xm_pause
}
xm_diagnostics_menu() {
    local choice script_dir
    script_dir=$(dirname "${BASH_SOURCE[0]}")
    while true; do
        xm_header 'Диагностика и ресурсы'
        printf '  [1] Состояние служб\n  [2] Диагностика сети и системы\n  [3] Память OpenFlux: каналы и резерв системы\n  [4] Настроить общий бюджет памяти OpenFlux\n  [5] Конфликты watchdog\n  [6] Watchdog — восстановление служб\n  [0] Назад\n'
        read -r -p 'Действие: ' choice || return
        case "$choice" in
            1) view_global_status;;
            2) python3 "$script_dir/network-diagnostics.py"; xm_pause;;
            3) python3 "$script_dir/openflux-resources.py" report; xm_pause;;
            4) xm_openflux_resources_menu;;
            5) python3 "$script_dir/service-control.py" conflicts --human; xm_pause;;
            6) xm_watchdog_menu;;
            0) return;;
        esac
    done
}
xm_watchdog_menu() {
    local choice script_dir
    script_dir=$(dirname "${BASH_SOURCE[0]}")
    while true; do
        xm_header 'Watchdog — восстановление служб'
        echo 'Падение процесса: systemd. Проверка работающей службы: локальный контроль.'
        echo 'Постоянное отключение и ручной стоп сохраняются. Чужой watchdog автоматически не отключается.'
        printf '  [1] Службы: действующие политики и настройка лимитов\n  [2] Проверки работающих служб: состояние и остаток попыток\n  [3] Применить базовую защиту для ещё не настроенных служб\n  [4] Дополнительные локальные проверки\n  [5] Конфликты с другим watchdog\n  [0] Назад\n'
        read -r -p 'Действие: ' choice || return
        case "$choice" in
            1) python3 "$script_dir/tuna-watchdog.py" menu || echo 'Не удалось открыть настройки watchdog.' >&2;;
            2) python3 "$script_dir/watchdog-health.py" report --human; xm_pause;;
            3)
                xm_confirm 'Применить базовую защиту: до 5 повторных запусков с паузой 30 с; для OpenFlux общий лимит 20/30; добавить контроль Xray панели, если он ещё не настроен? Работающие службы не перезапускаются.' || continue
                if python3 "$script_dir/tuna-watchdog.py" defaults --attempts 5 --delay 30; then
                    python3 "$script_dir/watchdog-health.py" bootstrap --enable-timer --human || echo 'Контроль Xray не настроен; см. ошибку выше. Политики аварийного перезапуска применены.' >&2
                else
                    echo 'Базовые политики не применены; см. ошибку выше.' >&2
                fi
                xm_pause;;
            4) xm_health_menu;;
            5) python3 "$script_dir/service-control.py" conflicts --human; xm_pause;;
            0) return;;
            *) echo 'Выберите номер из списка';;
        esac
    done
}
xm_health_configure() {
    local helper=$1 unit kind_pick kind host_pick host port path failures cooldown attempts
    local -a args=()
    echo 'Укажите имя установленной службы, например xray, snell или openflux@1.'
    read -r -p 'Служба: ' unit || return 1
    [ -n "$unit" ] || { echo 'Имя службы не задано.' >&2; return 1; }
    printf '  [1] Только наличие процесса\n  [2] TCP-слушатель на loopback\n  [3] Локальный HTTP с ответом 2xx\n'
    read -r -p 'Проверка [Enter=1]: ' kind_pick || return 1
    case "${kind_pick:-1}" in
        1) kind=process;; 2) kind=tcp;; 3) kind=http;;
        *) echo 'Нужен номер 1–3.' >&2; return 1;;
    esac
    args=(set "$unit" --kind "$kind")
    if [ "$kind" != process ]; then
        read -r -p 'Loopback: [1] 127.0.0.1, [2] ::1 [Enter=1]: ' host_pick || return 1
        case "${host_pick:-1}" in 1) host=127.0.0.1;; 2) host=::1;; *) echo 'Нужен номер 1 или 2.' >&2; return 1;; esac
        read -r -p 'Локальный порт этой службы: ' port || return 1
        args+=(--host "$host" --port "$port")
        if [ "$kind" = http ]; then
            read -r -p 'HTTP-путь без query/секретов [Enter=/]: ' path || return 1
            args+=(--path "${path:-/}")
        fi
    fi
    read -r -p 'Последовательных ошибок до действия [Enter=3]: ' failures || return 1
    read -r -p 'Пауза между попытками, секунд [Enter=300]: ' cooldown || return 1
    read -r -p 'Всего перезапусков до ручного сброса; 0 — наблюдение [Enter=3]: ' attempts || return 1
    args+=(--failures "${failures:-3}" --cooldown "${cooldown:-300}" --max-restarts "${attempts:-3}")
    printf 'Служба: %s; проверка: %s; ошибок: %s; пауза: %s с; попыток: %s.\n' "$unit" "$kind" "${failures:-3}" "${cooldown:-300}" "${attempts:-3}"
    [ "$kind" = process ] || printf 'Локальная цель: %s:%s%s\n' "$host" "$port" "${path:-}"
    echo 'Настройка сохраняет проверку. Таймер включается отдельным пунктом; существующий лимит попыток не сбрасывается.'
    xm_confirm 'Сохранить эту проверку?' || return 0
    python3 "$helper" "${args[@]}" --human
}
xm_health_menu() {
    local choice unit script_dir status
    script_dir=$(dirname "${BASH_SOURCE[0]}")
    while true; do
        xm_header 'Локальные проверки зависаний'
        echo 'Проверка зависаний активных служб. Остановленные службы не запускаются.'
        echo 'Начните с [1]: состояние таймера, выбранные службы и лимиты. Настройка — [2].'
        printf '  [1] Отчёт, проверки и остаток попыток\n  [2] Добавить или изменить проверку\n  [3] Удалить проверку службы\n  [4] Сбросить попытки после устранения причины\n  [5] Включить таймер проверок\n  [6] Выключить таймер проверок\n  [7] Проверить сейчас (возможен перезапуск)\n  [0] Назад\n'
        read -r -p 'Действие: ' choice || return
        status=0
        case "$choice" in
            1) python3 "$script_dir/watchdog-health.py" report --human || status=$?;;
            2) xm_health_configure "$script_dir/watchdog-health.py" || status=$?;;
            3|4)
                read -r -p 'Имя службы: ' unit || return
                if [ "$choice" = 3 ]; then
                    xm_confirm 'Удалить только проверку этой службы?' || continue
                    python3 "$script_dir/watchdog-health.py" remove "$unit" --human || status=$?
                else
                    xm_confirm 'Причина устранена? Сброс разрешит новые попытки перезапуска.' || continue
                    python3 "$script_dir/watchdog-health.py" reset "$unit" --human || status=$?
                fi;;
            5)
                python3 "$script_dir/watchdog-health.py" report --human --require-configured || { xm_pause; continue; }
                xm_confirm 'Включить таймер? Сохранённые проверки смогут перезапускать службы в пределах своих лимитов.' || continue
                python3 "$script_dir/service-control.py" on tuna-healthcheck.timer || status=$?;;
            6)
                xm_confirm 'Прекратить новые плановые проверки и выключить автозапуск таймера?' || continue
                python3 "$script_dir/service-control.py" off tuna-healthcheck.timer || status=$?;;
            7)
                python3 "$script_dir/watchdog-health.py" report --human --require-configured || { xm_pause; continue; }
                xm_confirm 'Выполнить проверки сейчас с разрешёнными для них попытками перезапуска?' || continue
                python3 "$script_dir/watchdog-health.py" check --human || status=$?;;
            0) return;;
            *) echo 'Выберите номер из списка'; continue;;
        esac
        [ "$status" = 0 ] || echo 'Операция проверки служб не завершена; ошибка показана выше.' >&2
        xm_pause
    done
}
xm_openflux_resources_menu() {
    local total snapshot script_dir
    script_dir=$(dirname "${BASH_SOURCE[0]}")
    python3 "$script_dir/openflux-resources.py" report || return
    echo 'Изменения применятся при следующем запуске каналов; текущие соединения сохраняются.'
    read -r -p 'Общий бюджет MiB; Enter — рекомендуемый; R — откат: ' total || return
    if [[ "$total" = [Rr] ]]; then
        read -r -p 'Идентификатор резервной копии ресурсов: ' snapshot || return
        python3 "$script_dir/openflux-resources.py" rollback "$snapshot"
    elif [[ -z "$total" || "$total" =~ ^[0-9]+$ ]]; then
        local -a args=()
        [ -z "$total" ] || args=(--total-mib "$total")
        python3 "$script_dir/openflux-resources.py" plan "${args[@]}" || return
        xm_confirm 'Сохранить показанный бюджет каналов?' || return
        python3 "$script_dir/openflux-resources.py" apply "${args[@]}"
    else
        echo 'Нужно целое число MiB.' >&2
        return 1
    fi
    xm_pause
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
        printf '  [1] Обновить полный выпуск\n  [2] Восстановить резервную копию\n  [3] Пересканировать и подхватить службы\n  [4] Перезапустить службы пакета\n  [5] Watchdog — восстановление служб\n  [0] Назад\n'
        read -r -p 'Действие: ' choice || return
        case "$choice" in
            1) xm_release_update;; 2) xm_backup_menu;;
            3) xm_confirm 'Подхватить обнаруженные службы? Это может обновить служебные настройки.' && rescan_and_adopt_protocols;;
            4) xm_confirm 'Перезапуск прервёт текущие подключения.' && restart_all_services;;
            5) xm_watchdog_menu;;
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
            5) xm_diagnostics_menu;; 6) xm_maintenance_menu;;
            7) printf '%s\n' '0 — назад; изменения выполняются только выбранным действием.' 'Выход из меню не останавливает службы и не запускает обновление.' 'Состояние службы, включение в подписку и состояние теста на телефоне — разные статусы.' 'URL-test / Speedtest запускаются клиентом после явного подключения.' 'Все реквизиты сохраняются при обновлении. Секретные ссылки показываются отдельным действием.'; xm_pause;;
            0) echo 'Меню закрыто. Службы продолжают работать.'; return;;
            *) echo 'Выберите номер из списка'; sleep 1;;
        esac
    done
}
