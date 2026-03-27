#!/usr/bin/env bash
# =============================================================================
# wazuh_health_check.sh — Interactive Wazuh Health Check Script (Bash version)
#
# Based on: README_Version1.md — Wazuh Health Check — Guía Completa Paso a Paso
#
# Usage:
#   sudo bash wazuh_health_check.sh [-o /custom/path/report.txt]
#                                   [--indexer-user USER] [--indexer-pass PASS]
#                                   [--indexer-url URL]
#                                   [--api-user USER] [--api-pass PASS]
#                                   [--api-url URL]
# =============================================================================

# ─── Shell options (individual command failures handled per-function) ─────────
set -uo pipefail

# ─── Color helpers ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    GREEN="\033[92m"
    YELLOW="\033[93m"
    RED="\033[91m"
    CYAN="\033[96m"
    BOLD="\033[1m"
    RESET="\033[0m"
else
    GREEN=""
    YELLOW=""
    RED=""
    CYAN=""
    BOLD=""
    RESET=""
fi

SYM_GOOD="🟢"
SYM_WARN="🟡"
SYM_CRIT="🔴"
STATUS_GOOD="BUENO"
STATUS_WARN="REGULAR"
STATUS_CRIT="MALO"

# ─── Global state ─────────────────────────────────────────────────────────────
DEPLOY_TYPE=""
REPORT_PATH=""
REPORT_CONTENT=""      # accumulated report (ANSI-stripped)
GOOD_COUNT=0
WARN_COUNT=0
CRIT_COUNT=0

# Findings stored as parallel arrays
FIND_IDS=()
FIND_NAMES=()
FIND_STATUSES=()
FIND_MESSAGES=()
FIND_HINTS=()

# Credentials (defaults, overridden by flags)
IDX_USER="admin"
IDX_PASS="admin"
IDX_URL="https://localhost:9200"
API_USER="wazuh-wui"
API_PASS="wazuh-wui"
API_URL="https://localhost:55000"

# ─── Helpers ──────────────────────────────────────────────────────────────────

# Strip ANSI escape codes
strip_ansi() {
    sed 's/\x1b\[[0-9;]*m//g'
}

# Print to stdout AND append (ANSI-stripped) to REPORT_CONTENT
tee_out() {
    local line="$1"
    echo -e "$line"
    REPORT_CONTENT+="$(echo -e "$line" | strip_ansi)"$'\n'
}

# Record a finding for the final summary
record() {
    local id="$1" name="$2" status="$3" message="$4" hint="${5:-}"
    FIND_IDS+=("$id")
    FIND_NAMES+=("$name")
    FIND_STATUSES+=("$status")
    FIND_MESSAGES+=("$message")
    FIND_HINTS+=("$hint")

    case "$status" in
        "$STATUS_GOOD") (( GOOD_COUNT++ )) ;;
        "$STATUS_WARN") (( WARN_COUNT++ )) ;;
        "$STATUS_CRIT") (( CRIT_COUNT++ )) ;;
    esac
}

# Print a section header
print_header() {
    local title="$1"
    local line
    line=$(printf '═%.0s' {1..64})
    tee_out ""
    tee_out "${CYAN}${BOLD}${line}${RESET}"
    tee_out "${CYAN}${BOLD}  ${title}${RESET}"
    tee_out "${CYAN}${BOLD}${line}${RESET}"
}

# Print a status line with traffic-light symbol
print_status() {
    local label="$1" status="$2" detail="${3:-}"
    local sym color
    case "$status" in
        "$STATUS_GOOD") sym="$SYM_GOOD"; color="$GREEN" ;;
        "$STATUS_WARN") sym="$SYM_WARN"; color="$YELLOW" ;;
        "$STATUS_CRIT") sym="$SYM_CRIT"; color="$RED" ;;
        *) sym="❓"; color="" ;;
    esac
    local msg="  ${sym} ${color}${status}${RESET}  ${label}"
    if [ -n "$detail" ]; then
        msg+="  →  ${detail}"
    fi
    tee_out "$msg"
}

# Run a command safely — return stdout; stderr goes to /dev/null unless captured
run_cmd() {
    local cmd="$1"
    local timeout_sec="${2:-30}"
    timeout "$timeout_sec" bash -c "$cmd" 2>/dev/null || true
}

# ─── FASE 1: Server ───────────────────────────────────────────────────────────

fase1_recursos() {
    local component="$1"
    print_header "FASE 1.1: Recursos del Sistema"

    # ── CPU cores ──────────────────────────────────────────────────────────
    local cores
    cores=$(nproc 2>/dev/null || echo "0")
    tee_out "\n  CPU cores: ${cores}"

    if [[ "$component" == "manager" || "$component" == "aio" ]]; then
        local st detail
        if (( cores >= 4 )); then
            st="$STATUS_GOOD"; detail="${cores} cores (≥4 recomendado)"
        elif (( cores >= 2 )); then
            st="$STATUS_WARN"; detail="${cores} cores (recomendado ≥4)"
        else
            st="$STATUS_CRIT"; detail="${cores} core(s) — insuficiente para Manager"
        fi
        print_status "CPU (Manager)" "$st" "$detail"
        record "1.1" "Recursos - CPU (Manager)" "$st" "$detail" \
            "Añadir CPUs al Manager (mínimo 4 cores recomendado)"
    fi

    if [[ "$component" == "indexer" || "$component" == "aio" ]]; then
        local st detail
        if (( cores >= 8 )); then
            st="$STATUS_GOOD"; detail="${cores} cores (≥8 recomendado)"
        elif (( cores >= 4 )); then
            st="$STATUS_WARN"; detail="${cores} cores (recomendado ≥8)"
        else
            st="$STATUS_CRIT"; detail="${cores} cores — insuficiente para Indexer"
        fi
        print_status "CPU (Indexer)" "$st" "$detail"
        record "1.1" "Recursos - CPU (Indexer)" "$st" "$detail" \
            "Añadir CPUs al Indexer (mínimo 8 cores recomendado)"
    fi

    # ── RAM ────────────────────────────────────────────────────────────────
    local free_out
    free_out=$(free -m 2>/dev/null || echo "")
    tee_out "\n${free_out}"

    local ram_mb=0
    ram_mb=$(echo "$free_out" | awk '/^Mem:/ {print $2}' || echo "0")
    local ram_gb
    ram_gb=$(echo "$ram_mb" | awk '{printf "%.1f", $1/1024}')
    local ram_gb_int
    ram_gb_int=$(echo "$ram_mb" | awk '{printf "%d", $1/1024}')

    if [[ "$component" == "manager" || "$component" == "aio" ]]; then
        local st detail
        if (( ram_gb_int >= 8 )); then
            st="$STATUS_GOOD"; detail="${ram_gb} GB RAM (≥8 GB recomendado)"
        elif (( ram_gb_int >= 4 )); then
            st="$STATUS_WARN"; detail="${ram_gb} GB RAM (recomendado ≥8 GB)"
        else
            st="$STATUS_CRIT"; detail="${ram_gb} GB RAM — insuficiente para Manager"
        fi
        print_status "RAM (Manager)" "$st" "$detail"
        record "1.1" "Recursos - RAM (Manager)" "$st" "$detail" \
            "Ampliar RAM del Manager (mínimo 8 GB recomendado)"
    fi

    if [[ "$component" == "indexer" || "$component" == "aio" ]]; then
        local st detail
        if (( ram_gb_int >= 16 )); then
            st="$STATUS_GOOD"; detail="${ram_gb} GB RAM (≥16 GB recomendado)"
        elif (( ram_gb_int >= 8 )); then
            st="$STATUS_WARN"; detail="${ram_gb} GB RAM (recomendado ≥16 GB)"
        else
            st="$STATUS_CRIT"; detail="${ram_gb} GB RAM — insuficiente para Indexer"
        fi
        print_status "RAM (Indexer)" "$st" "$detail"
        record "1.1" "Recursos - RAM (Indexer)" "$st" "$detail" \
            "Ampliar RAM del Indexer (mínimo 16 GB recomendado para producción)"
    fi

    if [[ "$component" == "dashboard" || "$component" == "aio" ]]; then
        local st detail
        if (( ram_gb_int >= 4 )); then
            st="$STATUS_GOOD"; detail="${ram_gb} GB RAM (≥4 GB recomendado)"
        elif (( ram_gb_int >= 2 )); then
            st="$STATUS_WARN"; detail="${ram_gb} GB RAM (recomendado ≥4 GB)"
        else
            st="$STATUS_CRIT"; detail="${ram_gb} GB RAM — insuficiente para Dashboard"
        fi
        print_status "RAM (Dashboard)" "$st" "$detail"
        record "1.1" "Recursos - RAM (Dashboard)" "$st" "$detail" \
            "Ampliar RAM del Dashboard (mínimo 4 GB recomendado)"
    fi

    # ── Disk / ─────────────────────────────────────────────────────────────
    local df_root
    df_root=$(df -h / 2>/dev/null || echo "")
    tee_out "\n${df_root}"

    local use_pct
    use_pct=$(echo "$df_root" | awk 'NR==2 {gsub(/%/,"",$5); print $5}' || echo "0")
    use_pct="${use_pct:-0}"

    local st detail
    if (( use_pct < 75 )); then
        st="$STATUS_GOOD"; detail="${use_pct}% usado (<75%)"
    elif (( use_pct <= 85 )); then
        st="$STATUS_WARN"; detail="${use_pct}% usado (75-85%)"
    else
        st="$STATUS_CRIT"; detail="${use_pct}% usado — CRÍTICO (>85%)"
    fi
    print_status "Disco /" "$st" "$detail"
    record "1.1" "Recursos - Disco /" "$st" "$detail" \
        "Liberar espacio en / o ampliar disco"

    # ── Disk /var (Indexer) ────────────────────────────────────────────────
    if [[ "$component" == "indexer" || "$component" == "aio" ]]; then
        local df_var
        df_var=$(df -h /var 2>/dev/null || echo "")
        tee_out "\n${df_var}"

        local var_pct
        var_pct=$(echo "$df_var" | awk 'NR==2 {gsub(/%/,"",$5); print $5}' || echo "0")
        var_pct="${var_pct:-0}"

        if (( var_pct < 70 )); then
            st="$STATUS_GOOD"; detail="${var_pct}% usado (<70%)"
        elif (( var_pct <= 85 )); then
            st="$STATUS_WARN"; detail="${var_pct}% usado (70-85%)"
        else
            st="$STATUS_CRIT"; detail="${var_pct}% usado — CRÍTICO (>85%)"
        fi
        print_status "Disco /var (Indexer)" "$st" "$detail"
        record "1.1" "Recursos - Disco /var" "$st" "$detail" \
            "Liberar espacio en /var o ampliar disco del Indexer"
    fi

    # ── OS info ────────────────────────────────────────────────────────────
    tee_out "\n  Sistema Operativo:"
    tee_out "$(cat /etc/os-release 2>/dev/null | head -5)"
}

fase1_servicios() {
    local component="$1"
    print_header "FASE 1.2: Estado de los Servicios"

    local services=()
    [[ "$component" == "manager" || "$component" == "aio" ]] && services+=("wazuh-manager")
    [[ "$component" == "indexer"  || "$component" == "aio" ]] && services+=("wazuh-indexer")
    [[ "$component" == "dashboard"|| "$component" == "aio" ]] && services+=("wazuh-dashboard")
    [[ "$component" == "manager" || "$component" == "aio" ]] && services+=("filebeat")

    local svc
    for svc in "${services[@]}"; do
        tee_out "\n  Servicio: ${BOLD}${svc}${RESET}"

        local active_state
        active_state=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        tee_out "  Estado:   ${active_state}"

        local status_out
        status_out=$(systemctl status "$svc" --no-pager 2>/dev/null | head -10 || echo "")
        tee_out "$status_out"

        local st detail
        case "$active_state" in
            active)
                st="$STATUS_GOOD"; detail="active (running)" ;;
            activating|reloading)
                st="$STATUS_WARN"; detail="${active_state} — monitoreando" ;;
            *)
                st="$STATUS_CRIT"; detail="${active_state} — servicio no activo" ;;
        esac

        print_status "Servicio ${svc}" "$st" "$detail"
        record "1.2" "Servicio ${svc}" "$st" "$detail" \
            "Revisar: systemctl status ${svc} && journalctl -u ${svc} -n 50"

        if [[ "$active_state" != "active" ]]; then
            tee_out "\n  ${RED}Últimas entradas de journalctl:${RESET}"
            tee_out "$(journalctl -u "$svc" --no-pager -n 15 2>/dev/null || echo '  (sin datos)')"
        fi
    done
}

fase1_carga() {
    print_header "FASE 1.3: Carga del Sistema"

    # ── uptime / load average ──────────────────────────────────────────────
    local uptime_out
    uptime_out=$(uptime 2>/dev/null || echo "")
    tee_out "  ${uptime_out}"

    local cores
    cores=$(nproc 2>/dev/null || echo "1")
    (( cores == 0 )) && cores=1

    local load_1
    load_1=$(echo "$uptime_out" | grep -oP 'load average[s]?:\s*\K[\d.]+' || echo "")

    if [[ -n "$load_1" ]] && echo "$load_1" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
        local load_per_core
        load_per_core=$(echo "$load_1 $cores" | awk '{printf "%.2f", $1/$2}')
        local load_int
        load_int=$(echo "$load_per_core" | awk '{printf "%d", $1*100}')

        local st detail
        if (( load_int < 70 )); then
            st="$STATUS_GOOD"; detail="load/core=${load_per_core} (<0.7)"
        elif (( load_int <= 100 )); then
            st="$STATUS_WARN"; detail="load/core=${load_per_core} (0.7-1.0 — atención)"
        else
            st="$STATUS_CRIT"; detail="load/core=${load_per_core} (>1.0 — sobrecarga)"
        fi
        print_status "Load Average" "$st" "$detail"
        record "1.3" "Carga - Load Average" "$st" "$detail" \
            "Load alto. Verificar procesos: top -bn1 | head -20"
    fi

    # ── top — CPU usage ────────────────────────────────────────────────────
    local top_out
    top_out=$(top -bn1 2>/dev/null | head -5 || echo "")
    tee_out "\n${top_out}"

    local cpu_idle
    cpu_idle=$(echo "$top_out" | grep -oP '[\d.]+\s*id' | grep -oP '[\d.]+' | head -1 || echo "")

    if [[ -n "$cpu_idle" ]]; then
        local cpu_used_int
        cpu_used_int=$(echo "$cpu_idle" | awk '{printf "%d", 100 - $1}')
        local cpu_used_f
        cpu_used_f=$(echo "$cpu_idle" | awk '{printf "%.1f", 100 - $1}')

        local st detail
        if (( cpu_used_int < 70 )); then
            st="$STATUS_GOOD"; detail="${cpu_used_f}% CPU usado (<70%)"
        elif (( cpu_used_int <= 90 )); then
            st="$STATUS_WARN"; detail="${cpu_used_f}% CPU usado (70-90%)"
        else
            st="$STATUS_CRIT"; detail="${cpu_used_f}% CPU usado — CRÍTICO (>90%)"
        fi
        print_status "CPU Total" "$st" "$detail"
        record "1.3" "Carga - CPU Total" "$st" "$detail" \
            "CPU alta. Investigar: ps aux --sort=-%cpu | head -10"
    fi

    # ── free — RAM usage ───────────────────────────────────────────────────
    local free_out
    free_out=$(free -m 2>/dev/null || echo "")
    tee_out "\n${free_out}"

    local ram_total ram_used
    ram_total=$(echo "$free_out" | awk '/^Mem:/ {print $2}' || echo "1")
    ram_used=$(echo "$free_out"  | awk '/^Mem:/ {print $3}' || echo "0")
    (( ram_total == 0 )) && ram_total=1

    local ram_pct_int ram_pct_f
    ram_pct_int=$(echo "$ram_total $ram_used" | awk '{printf "%d", ($2/$1)*100}')
    ram_pct_f=$(echo "$ram_total $ram_used"   | awk '{printf "%.1f", ($2/$1)*100}')

    local st detail
    if (( ram_pct_int < 80 )); then
        st="$STATUS_GOOD"; detail="${ram_pct_f}% RAM usado (<80%)"
    elif (( ram_pct_int <= 90 )); then
        st="$STATUS_WARN"; detail="${ram_pct_f}% RAM usado (80-90%)"
    else
        st="$STATUS_CRIT"; detail="${ram_pct_f}% RAM usado — CRÍTICO (>90%)"
    fi
    print_status "RAM Usada" "$st" "$detail"
    record "1.3" "Carga - RAM Usada" "$st" "$detail" \
        "RAM alta. Verificar heap del Indexer y procesos con alto consumo"

    # ── Swap ───────────────────────────────────────────────────────────────
    local swap_used
    swap_used=$(echo "$free_out" | awk '/^Swap:/ {print $3}' || echo "0")
    swap_used="${swap_used:-0}"

    if (( swap_used == 0 )); then
        st="$STATUS_GOOD"; detail="0 MB swap usado"
    elif (( swap_used < 500 )); then
        st="$STATUS_WARN"; detail="${swap_used} MB swap usado (<500 MB)"
    else
        st="$STATUS_CRIT"; detail="${swap_used} MB swap usado — CRÍTICO (>500 MB)"
    fi
    print_status "Swap" "$st" "$detail"
    record "1.3" "Carga - Swap" "$st" "$detail" \
        "Uso de swap degrada rendimiento gravemente. Añadir RAM o reducir heap del Indexer"

    # ── Wazuh processes ────────────────────────────────────────────────────
    tee_out "\n  Procesos Wazuh/ossec activos:"
    local procs
    procs=$(ps aux 2>/dev/null | grep -E 'wazuh|ossec' | grep -v grep || echo "  (ninguno encontrado)")
    tee_out "${procs}"
}

fase1_daemons() {
    print_header "FASE 1.4: Daemons Internos de Wazuh"

    local daemon_out
    daemon_out=$(run_cmd "/var/ossec/bin/wazuh-control status" 30 || echo "")
    tee_out "${daemon_out:-  (sin output)}"

    local critical_daemons=(
        "wazuh-analysisd"
        "wazuh-remoted"
        "wazuh-db"
        "wazuh-modulesd"
        "wazuh-logcollector"
        "wazuh-syscheckd"
        "wazuh-monitord"
        "wazuh-execd"
        "wazuh-apid"
    )

    local all_ok=true
    local daemon
    for daemon in "${critical_daemons[@]}"; do
        if echo "$daemon_out" | grep -q "${daemon} not running..."; then
            tee_out "  ${SYM_CRIT} ${RED}${daemon} NOT RUNNING${RESET}"
            record "1.4" "Daemon ${daemon}" "$STATUS_CRIT" \
                "${daemon} no está corriendo" \
                "Reiniciar Manager: systemctl restart wazuh-manager"
            all_ok=false
        fi
    done

    if [[ "$all_ok" == "true" && -n "$daemon_out" ]]; then
        print_status "Daemons Críticos" "$STATUS_GOOD" \
            "Todos los daemons críticos corriendo"
        record "1.4" "Daemons Internos" "$STATUS_GOOD" \
            "Todos los daemons críticos OK"
    elif [[ -z "$daemon_out" ]]; then
        print_status "Daemons Críticos" "$STATUS_WARN" \
            "No se pudo ejecutar wazuh-control status"
        record "1.4" "Daemons Internos" "$STATUS_WARN" \
            "wazuh-control status no disponible" \
            "Verificar que /var/ossec/bin/wazuh-control existe y es ejecutable"
    fi
}

# ─── FASE 2: Manager ──────────────────────────────────────────────────────────

fase2_version() {
    print_header "FASE 2.1: Versión y Configuración del Manager"

    local ver_out
    ver_out=$(run_cmd "/var/ossec/bin/wazuh-control info" 15 || echo "  (sin output)")
    tee_out "${ver_out}"

    tee_out "\n  Primeras líneas de ossec.conf:"
    local conf_out
    conf_out=$(head -50 /var/ossec/etc/ossec.conf 2>/dev/null || echo "  (no se pudo leer ossec.conf)")
    tee_out "${conf_out}"

    # XML validation using python3
    local xml_check
    xml_check=$(python3 -c "
import xml.etree.ElementTree as ET
try:
    ET.parse('/var/ossec/etc/ossec.conf')
    print('XML OK')
except Exception as e:
    print(f'XML ERROR: {e}')
" 2>/dev/null || echo "XML check no disponible")

    if echo "$xml_check" | grep -q "XML OK"; then
        print_status "ossec.conf XML" "$STATUS_GOOD" "XML válido"
        record "2.1" "Manager - ossec.conf XML" "$STATUS_GOOD" "XML válido"
    elif echo "$xml_check" | grep -q "XML ERROR"; then
        print_status "ossec.conf XML" "$STATUS_CRIT" "Error de XML en ossec.conf"
        record "2.1" "Manager - ossec.conf XML" "$STATUS_CRIT" \
            "ossec.conf tiene errores XML" \
            "Verificar ossec.conf con: xmllint --noout /var/ossec/etc/ossec.conf"
    fi

    record "2.1" "Versión Manager" "$STATUS_GOOD" \
        "Versión consultada (verificar que coincide con Indexer y Dashboard)"
}

fase2_logs() {
    print_header "FASE 2.2: Logs del Manager"

    tee_out "  Últimos errores/warnings en ossec.log:"
    local err_tail
    err_tail=$(grep -iE 'error|critical|warning' /var/ossec/logs/ossec.log 2>/dev/null | tail -30 || echo "")
    tee_out "${err_tail:-  (sin errores recientes)}"

    local error_count
    error_count=$(grep -icE 'error|critical' /var/ossec/logs/ossec.log 2>/dev/null || echo "0")
    error_count="${error_count:-0}"

    local st detail
    if (( error_count == 0 )); then
        st="$STATUS_GOOD"; detail="0 ERROR/CRITICAL en ossec.log"
    elif (( error_count < 20 )); then
        st="$STATUS_WARN"; detail="${error_count} ERROR/CRITICAL en ossec.log"
    else
        st="$STATUS_CRIT"; detail="${error_count} ERROR/CRITICAL — revisar urgente"
    fi
    print_status "Errores en ossec.log" "$st" "$detail"
    record "2.2" "Logs Manager - Errores" "$st" "$detail" \
        "Revisar: grep -iE 'error|critical' /var/ossec/logs/ossec.log | tail -50"

    # Log file size
    tee_out "\n  Tamaño ossec.log:"
    tee_out "$(ls -lah /var/ossec/logs/ossec.log 2>/dev/null || echo '  (no encontrado)')"

    local size_bytes
    size_bytes=$(du -sb /var/ossec/logs/ossec.log 2>/dev/null | awk '{print $1}' || echo "0")
    size_bytes="${size_bytes:-0}"
    local size_mb
    size_mb=$(echo "$size_bytes" | awk '{printf "%d", $1/1048576}')

    if (( size_mb < 500 )); then
        st="$STATUS_GOOD"; detail="${size_mb} MB (<500 MB)"
    elif (( size_mb < 1024 )); then
        st="$STATUS_WARN"; detail="${size_mb} MB (500 MB–1 GB)"
    else
        st="$STATUS_CRIT"; detail="${size_mb} MB (>1 GB — rotación posiblemente rota)"
    fi
    print_status "Tamaño ossec.log" "$st" "$detail"
    record "2.2" "Logs Manager - Tamaño ossec.log" "$st" "$detail" \
        "Verificar rotación de logs en /var/ossec/etc/ossec.conf"

    # Log directory size
    tee_out "\n  Tamaño directorio /var/ossec/logs/:"
    tee_out "$(du -sh /var/ossec/logs/ 2>/dev/null || echo '  (no disponible)')"

    local dir_bytes
    dir_bytes=$(du -sb /var/ossec/logs/ 2>/dev/null | awk '{print $1}' || echo "0")
    dir_bytes="${dir_bytes:-0}"
    local dir_gb
    dir_gb=$(echo "$dir_bytes" | awk '{printf "%.1f", $1/1073741824}')
    local dir_gb_int
    dir_gb_int=$(echo "$dir_bytes" | awk '{printf "%d", $1/1073741824}')

    if (( dir_gb_int < 2 )); then
        st="$STATUS_GOOD"; detail="${dir_gb} GB (<2 GB)"
    elif (( dir_gb_int < 5 )); then
        st="$STATUS_WARN"; detail="${dir_gb} GB (2-5 GB)"
    else
        st="$STATUS_CRIT"; detail="${dir_gb} GB (>5 GB)"
    fi
    print_status "Tamaño directorio logs" "$st" "$detail"
    record "2.2" "Logs Manager - Directorio" "$st" "$detail" \
        "Limpiar logs antiguos o revisar política de retención"

    # Cluster log errors
    tee_out "\n  Errores en cluster.log:"
    local cluster_errs
    cluster_errs=$(grep -iE 'error|critical' /var/ossec/logs/cluster.log 2>/dev/null | tail -20 || echo "")
    tee_out "${cluster_errs:-  (sin errores en cluster.log)}"
}

fase2_cluster() {
    print_header "FASE 2.3: Estado del Cluster Wazuh"

    local cluster_out
    cluster_out=$(run_cmd "/var/ossec/bin/cluster_control -l" 15 || echo "")
    tee_out "${cluster_out:-  (sin output — ¿cluster no configurado?)}"

    local st detail
    if echo "$cluster_out" | grep -qi "connected" && ! echo "$cluster_out" | grep -qi "disconnected"; then
        st="$STATUS_GOOD"; detail="Todos los nodos conectados"
    elif echo "$cluster_out" | grep -qi "disconnected"; then
        st="$STATUS_CRIT"; detail="Nodo(s) desconectado(s) detectados"
    elif [[ -z "$cluster_out" ]]; then
        st="$STATUS_WARN"; detail="Cluster no configurado o no se pudo consultar"
    else
        st="$STATUS_WARN"; detail="Estado del cluster no determinado"
    fi

    print_status "Cluster Wazuh" "$st" "$detail"
    record "2.3" "Cluster Manager" "$st" "$detail" \
        "Verificar conectividad y certificados entre nodos del cluster"

    local cluster_info
    cluster_info=$(run_cmd "/var/ossec/bin/cluster_control -i" 15 || echo "")
    if [[ -n "$cluster_info" ]]; then
        tee_out "\n  Cluster info:\n${cluster_info}"
    fi
}

fase2_agentes() {
    print_header "FASE 2.4: Agentes Conectados"

    local agents_out
    agents_out=$(run_cmd "/var/ossec/bin/agent_control -l" 30 | head -30 || echo "")
    tee_out "${agents_out:-  (sin output)}"

    local active disconnected never
    active=$(run_cmd "/var/ossec/bin/agent_control -l" 30 | grep -c 'Active' || echo "0")
    disconnected=$(run_cmd "/var/ossec/bin/agent_control -l" 30 | grep -c 'Disconnected' || echo "0")
    never=$(run_cmd "/var/ossec/bin/agent_control -l" 30 | grep -c 'Never connected' || echo "0")

    active="${active:-0}"; disconnected="${disconnected:-0}"; never="${never:-0}"
    local total=$(( active + disconnected + never ))

    tee_out "\n  Agentes Activos:       ${active}"
    tee_out "  Agentes Desconectados: ${disconnected}"
    tee_out "  Nunca conectados:      ${never}"
    tee_out "  Total:                 ${total}"

    if (( total > 0 )); then
        local pct_active pct_active_int pct_disc pct_disc_int
        pct_active=$(echo "$active $total" | awk '{printf "%.1f", ($1/$2)*100}')
        pct_active_int=$(echo "$active $total" | awk '{printf "%d", ($1/$2)*100}')
        pct_disc=$(echo "$disconnected $total" | awk '{printf "%.1f", ($1/$2)*100}')
        pct_disc_int=$(echo "$disconnected $total" | awk '{printf "%d", ($1/$2)*100}')

        local st detail
        if (( pct_active_int > 95 )); then
            st="$STATUS_GOOD"; detail="${pct_active}% activos (${active}/${total})"
        elif (( pct_active_int >= 80 )); then
            st="$STATUS_WARN"; detail="${pct_active}% activos (${active}/${total}) — por debajo del 95%"
        else
            st="$STATUS_CRIT"; detail="${pct_active}% activos (${active}/${total}) — CRÍTICO (<80%)"
        fi
        print_status "Agentes Activos" "$st" "$detail"
        record "2.4" "Agentes - % Activos" "$st" "$detail" \
            "Investigar agentes desconectados: revisar red y certificados"

        if (( pct_disc_int == 0 )); then
            st="$STATUS_GOOD"; detail="0 agentes desconectados"
        elif (( pct_disc_int < 5 )); then
            st="$STATUS_WARN"; detail="${disconnected} desconectados (${pct_disc}%)"
        else
            st="$STATUS_CRIT"; detail="${disconnected} desconectados (${pct_disc}%) — CRÍTICO"
        fi
        print_status "Agentes Desconectados" "$st" "$detail"
        record "2.4" "Agentes - Desconectados" "$st" "$detail" \
            "Revisar conectividad de agentes y estado del Manager"
    else
        tee_out "  (sin agentes registrados o Manager sin acceso al agente DB)"
        record "2.4" "Agentes" "$STATUS_WARN" \
            "No se pudo obtener conteo de agentes" \
            "Verificar: /var/ossec/bin/agent_control -l"
    fi
}

fase2_queue() {
    print_header "FASE 2.5: Cola de Eventos (Event Queue)"

    tee_out "  Mensajes de cola en ossec.log:"
    local queue_tail
    queue_tail=$(grep -i 'queue' /var/ossec/logs/ossec.log 2>/dev/null | tail -10 || echo "")
    tee_out "${queue_tail:-  (sin mensajes de cola)}"

    local queue_full
    queue_full=$(grep -ic 'event queue is full' /var/ossec/logs/ossec.log 2>/dev/null || echo "0")
    queue_full="${queue_full:-0}"

    local st detail
    if (( queue_full == 0 )); then
        st="$STATUS_GOOD"; detail="0 mensajes 'event queue is full'"
    elif (( queue_full < 10 )); then
        st="$STATUS_WARN"; detail="${queue_full} mensajes 'event queue is full' (esporádico)"
    else
        st="$STATUS_CRIT"; detail="${queue_full} mensajes 'event queue is full' — CRÍTICO"
    fi
    print_status "Cola de Eventos" "$st" "$detail"
    record "2.5" "Cola de Eventos" "$st" "$detail" \
        "Aumentar analysisd.event_queue_size en ossec.conf o añadir CPU al Manager"
}

# ─── FASE 3: Indexer ──────────────────────────────────────────────────────────

fase3_cluster_health() {
    print_header "FASE 3.1: Salud del Cluster del Indexer"

    local health_out
    health_out=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \"${IDX_URL}/_cluster/health?pretty\"" \
        20 || echo "")
    tee_out "${health_out:-  (sin respuesta del Indexer)}"

    local cluster_status unassigned active_pct
    cluster_status=$(echo "$health_out" | grep '"status"' | awk -F'"' '{print $4}' | head -1 || echo "unknown")
    unassigned=$(echo "$health_out"     | grep '"unassigned_shards"' | awk '{print $3}' | tr -d ',' | head -1 || echo "-1")
    active_pct=$(echo "$health_out"     | grep '"active_shards_percent_as_number"' | awk '{print $3}' | tr -d ',' | head -1 || echo "-1")

    unassigned="${unassigned:--1}"; active_pct="${active_pct:--1}"

    # ── Cluster status ─────────────────────────────────────────────────────
    local st detail
    case "$cluster_status" in
        green)  st="$STATUS_GOOD"; detail="Cluster status: GREEN" ;;
        yellow) st="$STATUS_WARN"; detail="Cluster status: YELLOW — réplicas sin asignar" ;;
        red)    st="$STATUS_CRIT"; detail="Cluster status: RED — POSIBLE PÉRDIDA DE DATOS" ;;
        *)      st="$STATUS_WARN"; detail="Estado no determinado: ${cluster_status}" ;;
    esac
    print_status "Cluster Indexer Status" "$st" "$detail"
    record "3.1" "Indexer - Cluster Status" "$st" "$detail" \
        "RED: acción inmediata. YELLOW en AIO/single-node es normal (sin réplicas)"

    # ── Unassigned shards ──────────────────────────────────────────────────
    local unassigned_int
    unassigned_int=$(echo "$unassigned" | awk '{printf "%d", $1}' 2>/dev/null || echo "-1")
    if (( unassigned_int >= 0 )); then
        if (( unassigned_int == 0 )); then
            st="$STATUS_GOOD"; detail="0 shards sin asignar"
        elif (( unassigned_int <= 5 )); then
            st="$STATUS_WARN"; detail="${unassigned_int} shards sin asignar"
        else
            st="$STATUS_CRIT"; detail="${unassigned_int} shards sin asignar — CRÍTICO (>5)"
        fi
        print_status "Unassigned Shards" "$st" "$detail"
        record "3.1" "Indexer - Unassigned Shards" "$st" "$detail" \
            "En AIO single-node, réplicas UNASSIGNED es normal. Verificar primarios si status=RED"
    fi

    # ── Active shards % ────────────────────────────────────────────────────
    local active_pct_int
    active_pct_int=$(echo "$active_pct" | awk '{printf "%d", $1}' 2>/dev/null || echo "-1")
    if (( active_pct_int >= 0 )); then
        if (( active_pct_int >= 100 )); then
            st="$STATUS_GOOD"; detail="100% shards activos"
        elif (( active_pct_int >= 90 )); then
            st="$STATUS_WARN"; detail="${active_pct}% shards activos"
        else
            st="$STATUS_CRIT"; detail="${active_pct}% shards activos — CRÍTICO (<90%)"
        fi
        print_status "Active Shards %" "$st" "$detail"
        record "3.1" "Indexer - Active Shards %" "$st" "$detail" \
            "Investigar shards no asignados: _cat/shards?v"
    fi

    # ── Nodes list ─────────────────────────────────────────────────────────
    tee_out "\n  Nodos del cluster:"
    tee_out "$(run_cmd "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \"${IDX_URL}/_cat/nodes?v\"" 20)"
}

fase3_jvm() {
    print_header "FASE 3.2: JVM Heap Memory"

    local jvm_out
    jvm_out=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \
        \"${IDX_URL}/_cat/nodes?v&h=name,heap.percent,heap.current,heap.max,ram.percent,cpu\"" \
        20 || echo "")
    tee_out "${jvm_out:-  (sin respuesta)}"

    # Parse each data line (skip header)
    while IFS= read -r line; do
        local node_name heap_pct
        node_name=$(echo "$line" | awk '{print $1}')
        heap_pct=$(echo "$line"  | awk '{print $2}')
        [[ -z "$heap_pct" || "$heap_pct" == "heap.percent" ]] && continue

        local heap_int
        heap_int=$(echo "$heap_pct" | awk '{printf "%d", $1}' 2>/dev/null || echo "0")

        local st detail
        if (( heap_int < 75 )); then
            st="$STATUS_GOOD"; detail="Heap ${heap_pct}% (<75%)"
        elif (( heap_int <= 85 )); then
            st="$STATUS_WARN"; detail="Heap ${heap_pct}% (75-85%)"
        else
            st="$STATUS_CRIT"; detail="Heap ${heap_pct}% — CRÍTICO (>85%)"
        fi
        print_status "JVM Heap (${node_name})" "$st" "$detail"
        record "3.2" "Indexer - JVM Heap (${node_name})" "$st" "$detail" \
            "Ajustar Xmx/Xms en /etc/wazuh-indexer/jvm.options (50% de RAM, máx 32 GB)"
    done <<< "$(echo "$jvm_out" | tail -n +2)"

    # Heap max details
    tee_out "\n  Detalles JVM heap_max:"
    tee_out "$(run_cmd "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \
        \"${IDX_URL}/_nodes/stats/jvm?pretty\" | grep -A5 'heap_max_in_bytes'" 20 || echo "  (no disponible)")"
}

fase3_disco() {
    print_header "FASE 3.3: Disco y Watermarks"

    local alloc_out
    alloc_out=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \"${IDX_URL}/_cat/allocation?v&s=node\"" \
        20 || echo "")
    tee_out "${alloc_out:-  (sin respuesta de _cat/allocation)}"

    # Parse disk percent (column 6 in _cat/allocation output)
    while IFS= read -r line; do
        local disk_pct node
        disk_pct=$(echo "$line" | awk '{print $6}' | tr -d '%')
        node=$(echo "$line" | awk '{print $NF}')
        [[ -z "$disk_pct" || "$disk_pct" == "disk.percent" ]] && continue

        local disk_int
        disk_int=$(echo "$disk_pct" | awk '{printf "%d", $1}' 2>/dev/null || echo "0")

        local st detail
        if (( disk_int < 75 )); then
            st="$STATUS_GOOD"; detail="${disk_pct}% disco usado (<75%)"
        elif (( disk_int <= 85 )); then
            st="$STATUS_WARN"; detail="${disk_pct}% disco (watermark low: 85%)"
        else
            st="$STATUS_CRIT"; detail="${disk_pct}% disco — CRÍTICO (>85% watermark)"
        fi
        print_status "Disco Indexer (${node})" "$st" "$detail"
        record "3.3" "Indexer - Disco (${node})" "$st" "$detail" \
            "Liberar espacio o ampliar disco. Si >95%, índices pasan a read-only (flood stage)"
    done <<< "$(echo "$alloc_out" | tail -n +2)"

    # Watermarks
    tee_out "\n  Watermarks configurados:"
    tee_out "$(run_cmd "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \
        \"${IDX_URL}/_cluster/settings?include_defaults=true&pretty\" \
        | grep -A3 'watermark' | head -20" 20 || echo "  (no disponible)")"

    # OS disk for Indexer data
    tee_out "\n  Disco SO (/var/lib/wazuh-indexer/):"
    tee_out "$(df -h /var/lib/wazuh-indexer/ 2>/dev/null || echo "  (no disponible)")"
}

fase3_shards() {
    print_header "FASE 3.4: Shards — Conteo y Estado"

    tee_out "  Shards UNASSIGNED:"
    local unassigned_out
    unassigned_out=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \
        \"${IDX_URL}/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason\" \
        | grep UNASSIGNED | head -20" 20 || echo "")
    tee_out "${unassigned_out:-  (ninguno)}"

    local total_shards unassigned_count
    total_shards=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \"${IDX_URL}/_cat/shards\" | wc -l" 20 || echo "0")
    unassigned_count=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \"${IDX_URL}/_cat/shards\" \
        | grep -c UNASSIGNED" 20 || echo "0")

    total_shards="${total_shards:-0}"
    unassigned_count="${unassigned_count:-0}"

    tee_out "\n  Total shards:  ${total_shards}"
    tee_out "  Unassigned:    ${unassigned_count}"

    local node_count
    node_count=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \"${IDX_URL}/_cat/nodes?v&h=name\" \
        | grep -v name | wc -l" 20 || echo "1")
    node_count="${node_count:-1}"
    (( node_count == 0 )) && node_count=1

    local shards_per_node
    shards_per_node=$(echo "$total_shards $node_count" | awk '{printf "%d", $1/$2}')

    local st detail
    if (( shards_per_node < 1000 )); then
        st="$STATUS_GOOD"; detail="~${shards_per_node} shards/nodo (<1000)"
    elif (( shards_per_node <= 1500 )); then
        st="$STATUS_WARN"; detail="~${shards_per_node} shards/nodo (1000-1500)"
    else
        st="$STATUS_CRIT"; detail="~${shards_per_node} shards/nodo — CRÍTICO (>1500)"
    fi
    print_status "Shards por Nodo" "$st" "$detail"
    record "3.4" "Indexer - Shards por Nodo" "$st" "$detail" \
        "Reducir shards cerrando índices antiguos o configurando ISM rollover"
}

fase3_indices() {
    print_header "FASE 3.5: Índices — Tamaño y Estado"

    local idx_out
    idx_out=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \
        \"${IDX_URL}/_cat/indices/wazuh-*?v&s=index\" | head -30" 20 || echo "")
    tee_out "${idx_out:-  (sin índices wazuh-*)}"

    local red_count yellow_count
    red_count=$(echo "$idx_out"    | awk 'NR>1 && $1=="red"    {count++} END {print count+0}')
    yellow_count=$(echo "$idx_out" | awk 'NR>1 && $1=="yellow" {count++} END {print count+0}')

    local st detail
    if (( red_count > 0 )); then
        st="$STATUS_CRIT"; detail="${red_count} índice(s) en estado RED — CRÍTICO"
    elif (( yellow_count > 0 )); then
        st="$STATUS_WARN"; detail="${yellow_count} índice(s) en estado YELLOW"
    else
        st="$STATUS_GOOD"; detail="Todos los índices open/green"
    fi
    print_status "Estado Índices" "$st" "$detail"
    record "3.5" "Indexer - Estado Índices" "$st" "$detail" \
        "RED: verificar shards primarios no asignados. YELLOW en single-node es normal"
}

# ─── FASE 4: Filebeat ─────────────────────────────────────────────────────────

fase4_filebeat() {
    print_header "FASE 4.1: Filebeat — Estado y Conectividad"

    local active
    active=$(systemctl is-active filebeat 2>/dev/null || echo "unknown")
    tee_out "  Estado filebeat: ${active}"
    tee_out "$(systemctl status filebeat --no-pager 2>/dev/null | head -10 || echo '')"

    local st detail
    case "$active" in
        active)
            st="$STATUS_GOOD"; detail="active (running)" ;;
        activating)
            st="$STATUS_WARN"; detail="activating — iniciando" ;;
        *)
            st="$STATUS_CRIT"; detail="${active} — servicio no activo" ;;
    esac
    print_status "Filebeat Service" "$st" "$detail"
    record "4.1" "Filebeat - Servicio" "$st" "$detail" \
        "Revisar: systemctl status filebeat && journalctl -u filebeat -n 50"

    # filebeat test output
    tee_out "\n  filebeat test output:"
    local fb_test_out
    fb_test_out=$(timeout 30 filebeat test output 2>&1 || echo "ERROR al ejecutar filebeat test output")
    tee_out "${fb_test_out}"

    if echo "$fb_test_out" | grep -q "OK" && ! echo "$fb_test_out" | grep -qi "refused"; then
        st="$STATUS_GOOD"; detail="Conexión al Indexer OK"
    elif echo "$fb_test_out" | grep -qi "connection refused\|certificate"; then
        st="$STATUS_CRIT"; detail="Conexión rechazada o error de certificado"
    else
        st="$STATUS_WARN"; detail="Respuesta inesperada — verificar manualmente"
    fi
    print_status "filebeat test output" "$st" "$detail"
    record "4.1" "Filebeat - Test Output" "$st" "$detail" \
        "Verificar certificados TLS y conectividad entre Filebeat e Indexer"

    # filebeat test config
    tee_out "\n  filebeat test config:"
    local fb_cfg_out
    fb_cfg_out=$(timeout 15 filebeat test config 2>&1 || echo "ERROR")
    tee_out "${fb_cfg_out}"

    if echo "$fb_cfg_out" | grep -q "Config OK"; then
        st="$STATUS_GOOD"; detail="Config OK"
    elif echo "$fb_cfg_out" | grep -qi "error"; then
        st="$STATUS_CRIT"; detail="Error en configuración de Filebeat"
    else
        st="$STATUS_WARN"; detail="Verificar manualmente la configuración"
    fi
    print_status "filebeat test config" "$st" "$detail"
    record "4.1" "Filebeat - Test Config" "$st" "$detail" \
        "Verificar /etc/filebeat/filebeat.yml"
}

fase4_filebeat_perf() {
    print_header "FASE 4.2: Filebeat — Cola y Rendimiento"

    tee_out "  Últimos errores/warnings/dropping en filebeat log:"
    local fb_log
    fb_log=$(grep -iE 'error|warn|dropping' /var/log/filebeat/filebeat 2>/dev/null | tail -20 || echo "")
    tee_out "${fb_log:-  (sin errores en filebeat log)}"

    local dropping
    dropping=$(grep -ic 'dropping' /var/log/filebeat/filebeat 2>/dev/null || echo "0")
    dropping="${dropping:-0}"

    local st detail
    if (( dropping == 0 )); then
        st="$STATUS_GOOD"; detail="0 eventos descartados"
    elif (( dropping < 10 )); then
        st="$STATUS_WARN"; detail="${dropping} eventos descartados (esporádico)"
    else
        st="$STATUS_CRIT"; detail="${dropping} eventos descartados — CRÍTICO"
    fi
    print_status "Dropping Events" "$st" "$detail"
    record "4.2" "Filebeat - Dropping Events" "$st" "$detail" \
        "Verificar capacidad del Indexer y aumentar queue.mem.events en filebeat.yml"

    tee_out "\n  Métricas de rendimiento (últimas líneas):"
    tee_out "$(grep -iE 'harvester|output|queue|pipeline' \
        /var/log/filebeat/filebeat 2>/dev/null | tail -10 || echo '  (sin métricas disponibles)')"
}

# ─── FASE 5: Certificados ─────────────────────────────────────────────────────

fase5_certs() {
    local component="$1"
    print_header "FASE 5.1: Certificados SSL/TLS"

    # Build cert list based on component
    local cert_paths=()
    local cert_names=()

    if [[ "$component" == "indexer"   || "$component" == "aio" ]]; then
        cert_paths+=("/etc/wazuh-indexer/certs/wazuh-indexer.pem")
        cert_names+=("Indexer")
    fi
    if [[ "$component" == "manager"   || "$component" == "aio" ]]; then
        cert_paths+=("/var/ossec/etc/sslmanager.cert")
        cert_names+=("Manager SSL")
    fi
    if [[ "$component" == "dashboard" || "$component" == "aio" ]]; then
        cert_paths+=("/etc/wazuh-dashboard/certs/wazuh-dashboard.pem")
        cert_names+=("Dashboard")
    fi

    local i
    for i in "${!cert_paths[@]}"; do
        local cert_path="${cert_paths[$i]}"
        local cert_name="${cert_names[$i]}"

        tee_out "\n  ${BOLD}Certificado: ${cert_name}${RESET}"
        tee_out "  Path: ${cert_path}"

        if [[ ! -f "$cert_path" ]]; then
            tee_out "  ${SYM_WARN} Archivo no encontrado: ${cert_path}"
            record "5.1" "Cert - ${cert_name}" "$STATUS_WARN" \
                "Archivo no encontrado: ${cert_path}" \
                "Verificar path del certificado para el componente correspondiente"
            continue
        fi

        local expiry_out
        expiry_out=$(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null || echo "")
        tee_out "  ${expiry_out}"

        local expiry_str
        expiry_str=$(echo "$expiry_out" | sed 's/notAfter=//')

        if [[ -n "$expiry_str" ]]; then
            local expiry_epoch now_epoch days_left
            expiry_epoch=$(date -d "$expiry_str" +%s 2>/dev/null || \
                           date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_str" +%s 2>/dev/null || \
                           echo "0")
            now_epoch=$(date +%s)
            days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

            local st detail
            if (( days_left < 0 )); then
                st="$STATUS_CRIT"; detail="EXPIRADO hace $((days_left * -1)) días — URGENTE"
            elif (( days_left < 30 )); then
                st="$STATUS_CRIT"; detail="Expira en ${days_left} días — CRÍTICO (<30 días)"
            elif (( days_left <= 90 )); then
                st="$STATUS_WARN"; detail="Expira en ${days_left} días (30-90 días)"
            else
                st="$STATUS_GOOD"; detail="Expira en ${days_left} días (>90 días)"
            fi
            print_status "Cert ${cert_name}" "$st" "$detail"
            record "5.1" "Cert - ${cert_name}" "$st" "$detail" \
                "Renovar certificados antes de expiración para evitar interrupción del servicio"
        else
            tee_out "  (No se pudo leer la fecha de expiración)"
            record "5.1" "Cert - ${cert_name}" "$STATUS_WARN" \
                "No se pudo leer fecha de expiración" \
                "Verificar: openssl x509 -enddate -noout -in ${cert_path}"
        fi

        # Subject and issuer
        tee_out "$(openssl x509 -subject -issuer -noout -in "$cert_path" 2>/dev/null || echo '')"
    done
}

# ─── FASE 6: API ──────────────────────────────────────────────────────────────

fase6_api() {
    print_header "FASE 6.1: Wazuh API — Conectividad y Respuesta"

    # Get token
    tee_out "  Obteniendo token de API..."
    local t_start token
    t_start=$(date +%s%3N)
    token=$(run_cmd \
        "curl -s -u \"${API_USER}:${API_PASS}\" -k \
        \"${API_URL}/security/user/authenticate?raw=true\"" 15 || echo "")
    # date +%s%3N gives epoch in seconds with 3 trailing nanosecond digits — delta is milliseconds
    local elapsed_ms=$(( $(date +%s%3N) - t_start ))

    if [[ -n "$token" && ${#token} -gt 20 ]] && ! echo "$token" | grep -qi "error"; then
        tee_out "  Token: ${token:0:20}...(truncado)"

        local elapsed_f
        elapsed_f=$(echo "$elapsed_ms" | awk '{printf "%.2f", $1/1000}')
        local elapsed_int
        elapsed_int=$(echo "$elapsed_ms" | awk '{printf "%d", $1/1000}')

        local st detail
        if (( elapsed_int < 2 )); then
            st="$STATUS_GOOD"; detail="Token obtenido en ${elapsed_f}s"
        elif (( elapsed_int < 5 )); then
            st="$STATUS_WARN"; detail="Token obtenido en ${elapsed_f}s (lento)"
        else
            st="$STATUS_CRIT"; detail="Token obtenido en ${elapsed_f}s — MUY LENTO"
        fi
        print_status "API Token" "$st" "$detail"
        record "6.1" "API - Token" "$st" "$detail" \
            "API lenta: verificar carga del Manager y wazuh-apid"
    else
        tee_out "  ERROR: ${token}"
        print_status "API Token" "$STATUS_CRIT" "No se obtuvo token de API"
        record "6.1" "API - Token" "$STATUS_CRIT" \
            "No se obtuvo token de API" \
            "Verificar: systemctl status wazuh-manager y credenciales wazuh-wui"
        tee_out "  ${RED}No se puede continuar sin token de API.${RESET}"
        return
    fi

    # GET /
    tee_out "\n  GET ${API_URL}/ ..."
    local t_start2
    t_start2=$(date +%s%3N)
    local http_code
    http_code=$(run_cmd \
        "curl -s -k -o /dev/null -w \"%{http_code}\" \
        -X GET \"${API_URL}/?pretty\" \
        -H \"Authorization: Bearer ${token}\"" 15 || echo "000")
    # date +%s%3N gives epoch in seconds with 3 trailing nanosecond digits — delta is milliseconds
    local elapsed2_ms=$(( $(date +%s%3N) - t_start2 ))
    local elapsed2
    elapsed2=$(echo "$elapsed2_ms" | awk '{printf "%.2f", $1/1000}')
    local elapsed2_int
    elapsed2_int=$(echo "$elapsed2_ms" | awk '{printf "%d", $1/1000}')
    tee_out "  HTTP Status: ${http_code} (${elapsed2}s)"

    local st detail
    if [[ "$http_code" == "200" ]]; then
        if (( elapsed2_int < 2 )); then
            st="$STATUS_GOOD"; detail="HTTP 200 en ${elapsed2}s"
        elif (( elapsed2_int < 5 )); then
            st="$STATUS_WARN"; detail="HTTP 200 en ${elapsed2}s (lento)"
        else
            st="$STATUS_CRIT"; detail="HTTP 200 en ${elapsed2}s — MUY LENTO (>5s)"
        fi
    else
        st="$STATUS_CRIT"; detail="HTTP ${http_code} — Error de conectividad"
    fi
    print_status "API GET /" "$st" "$detail"
    record "6.1" "API - GET /" "$st" "$detail" \
        "API responde HTTP ${http_code}. Verificar Manager si no es HTTP 200"

    # GET /agents/summary/status
    tee_out "\n  GET ${API_URL}/agents/summary/status ..."
    local agents_summary
    agents_summary=$(run_cmd \
        "curl -s -k -X GET \"${API_URL}/agents/summary/status?pretty\" \
        -H \"Authorization: Bearer ${token}\"" 15 || echo "")
    tee_out "${agents_summary:0:600}"

    # GET /manager/info
    tee_out "\n  GET ${API_URL}/manager/info ..."
    local mgr_info
    mgr_info=$(run_cmd \
        "curl -s -k -X GET \"${API_URL}/manager/info?pretty\" \
        -H \"Authorization: Bearer ${token}\"" 15 || echo "")
    tee_out "${mgr_info:0:600}"
}

# ─── FASE 7: Dashboard ────────────────────────────────────────────────────────

fase7_dashboard() {
    print_header "FASE 7.1: Wazuh Dashboard — Verificar Servicio y Acceso"

    local active
    active=$(systemctl is-active wazuh-dashboard 2>/dev/null || echo "unknown")
    tee_out "  Estado wazuh-dashboard: ${active}"
    tee_out "$(systemctl status wazuh-dashboard --no-pager 2>/dev/null | head -10 || echo '')"

    local st detail
    case "$active" in
        active)
            st="$STATUS_GOOD"; detail="active (running)" ;;
        activating)
            st="$STATUS_WARN"; detail="activating — iniciando" ;;
        *)
            st="$STATUS_CRIT"; detail="${active} — no activo" ;;
    esac
    print_status "Dashboard Service" "$st" "$detail"
    record "7.1" "Dashboard - Servicio" "$st" "$detail" \
        "Revisar: systemctl status wazuh-dashboard && journalctl -u wazuh-dashboard -n 50"

    # Port 443
    tee_out "\n  Puerto 443 (ss -tlnp):"
    local port443
    port443=$(ss -tlnp 2>/dev/null | grep 443 || echo "")
    tee_out "${port443:-  (no escucha en puerto 443)}"

    if [[ -n "$port443" ]]; then
        st="$STATUS_GOOD"; detail="Puerto 443 escuchando"
    else
        st="$STATUS_CRIT"; detail="Puerto 443 NO escucha — Dashboard puede estar caído"
    fi
    print_status "Puerto 443" "$st" "$detail"
    record "7.1" "Dashboard - Puerto 443" "$st" "$detail" \
        "Verificar configuración del Dashboard y si el servicio está activo"

    # HTTP status
    tee_out "\n  Test HTTP https://localhost:443 ..."
    local http_code
    http_code=$(run_cmd \
        'curl -sk -o /dev/null -w "%{http_code}" "https://localhost:443"' 15 || echo "000")
    tee_out "  HTTP Status: ${http_code}"

    case "$http_code" in
        302) st="$STATUS_GOOD"; detail="HTTP 302 (redirect a login) — OK" ;;
        200) st="$STATUS_WARN"; detail="HTTP 200 (sin redirect a login)" ;;
        502|503|000|"") st="$STATUS_CRIT"; detail="HTTP ${http_code} — Error de conectividad" ;;
        *) st="$STATUS_WARN"; detail="HTTP ${http_code} — verificar manualmente" ;;
    esac
    print_status "Dashboard HTTP" "$st" "$detail"
    record "7.1" "Dashboard - HTTP Status" "$st" "$detail" \
        "502/503: Dashboard no puede conectar al Indexer. Verificar certificados y Indexer"
}

# ─── FASE 8: End-to-End ───────────────────────────────────────────────────────

fase8_e2e() {
    print_header "FASE 8.1: Verificación End-to-End"

    # wazuh-logtest
    tee_out "  Ejecutando wazuh-logtest con mensaje de prueba..."
    local t_start
    t_start=$(date +%s%3N)
    local logtest_out
    logtest_out=$(echo '{"message":"test health check alert"}' \
        | timeout 15 /var/ossec/bin/wazuh-logtest 2>&1 || echo "ERROR")
    # date +%s%3N gives epoch in seconds with 3 trailing nanosecond digits — delta is milliseconds
    local elapsed_ms=$(( $(date +%s%3N) - t_start ))
    local elapsed elapsed_int
    elapsed=$(echo "$elapsed_ms" | awk '{printf "%.2f", $1/1000}')
    elapsed_int=$(echo "$elapsed_ms" | awk '{printf "%d", $1/1000}')

    tee_out "${logtest_out:0:800}"

    local st detail
    if echo "$logtest_out" | grep -qE 'No rule|Phase 1|full_log|\*\*Phase|Processing'; then
        if (( elapsed_int < 5 )); then
            st="$STATUS_GOOD"; detail="wazuh-logtest responde en ${elapsed}s"
        else
            st="$STATUS_WARN"; detail="wazuh-logtest responde pero lento (${elapsed}s)"
        fi
    elif [[ "$logtest_out" == "ERROR" || -z "$logtest_out" ]]; then
        st="$STATUS_CRIT"; detail="wazuh-logtest no responde o error"
    else
        st="$STATUS_GOOD"; detail="wazuh-logtest responde en ${elapsed}s"
    fi
    print_status "wazuh-logtest" "$st" "$detail"
    record "8.1" "E2E - wazuh-logtest" "$st" "$detail" \
        "Si logtest falla, verificar wazuh-analysisd: /var/ossec/bin/wazuh-control status"

    # Recent alerts in Indexer
    tee_out "\n  Verificando alertas recientes en el Indexer..."
    local alerts_out
    alerts_out=$(run_cmd \
        "curl -sk -u \"${IDX_USER}:${IDX_PASS}\" \
        \"${IDX_URL}/wazuh-alerts-*/_search?pretty&size=1&sort=timestamp:desc\" | head -30" \
        20 || echo "")
    tee_out "${alerts_out:-  (sin respuesta del Indexer)}"

    if echo "$alerts_out" | grep -q '"hits"' && echo "$alerts_out" | grep -q '"total"'; then
        st="$STATUS_GOOD"; detail="Alertas presentes en el Indexer"
    else
        st="$STATUS_WARN"; detail="No se pudieron verificar alertas en el Indexer"
    fi
    print_status "Alertas en Indexer" "$st" "$detail"
    record "8.1" "E2E - Alertas en Indexer" "$st" "$detail" \
        "Si no hay alertas: verificar cadena Manager → Filebeat → Indexer"

    # Filebeat event flow
    tee_out "\n  Verificando flujo de Filebeat..."
    local fb_events
    fb_events=$(grep -c 'events' /var/log/filebeat/filebeat 2>/dev/null | tail -1 || echo "0")
    tee_out "  Líneas con 'events' en filebeat log: ${fb_events}"
}

# ─── Final Summary ────────────────────────────────────────────────────────────

print_summary() {
    local deploy_type="$1"
    local rpath="$2"
    local width=64
    local border
    border=$(printf '═%.0s' $(seq 1 $width))
    local now
    now=$(date "+%Y-%m-%d %H:%M:%S")

    local deploy_label
    case "$deploy_type" in
        aio)       deploy_label="AIO (All-In-One)" ;;
        manager)   deploy_label="Manager Only"     ;;
        indexer)   deploy_label="Indexer Only"     ;;
        dashboard) deploy_label="Dashboard Only"   ;;
        *)         deploy_label="${deploy_type^^}"  ;;
    esac

    tee_out ""
    tee_out "╔${border}╗"
    tee_out "║$(printf '%*s' $(( (width + 30) / 2 )) 'RESUMEN DIAGNÓSTICO WAZUH')$(printf '%*s' $(( (width - 30 + 1) / 2 )) '')║"
    tee_out "╠${border}╣"
    tee_out "║  Tipo de despliegue: ${deploy_label}"
    tee_out "║  Fecha: ${now}"
    tee_out "╠${border}╣"

    local i
    for i in "${!FIND_IDS[@]}"; do
        local id="${FIND_IDS[$i]}"
        local name="${FIND_NAMES[$i]}"
        local status="${FIND_STATUSES[$i]}"
        local hint="${FIND_HINTS[$i]}"

        local sym color status_label
        case "$status" in
            "$STATUS_GOOD") sym="$SYM_GOOD"; color="$GREEN"; status_label="OK  " ;;
            "$STATUS_WARN") sym="$SYM_WARN"; color="$YELLOW"; status_label="WARN" ;;
            "$STATUS_CRIT") sym="$SYM_CRIT"; color="$RED"; status_label="CRIT" ;;
            *)               sym="❓"; color=""; status_label="????" ;;
        esac

        # Truncate name for display
        local name_trunc="${name:0:38}"
        tee_out "║  ${sym} ${color}$(printf '%-38s' "$name_trunc")${RESET} ${status_label}║"

        if [[ -n "$hint" && ( "$status" == "$STATUS_WARN" || "$status" == "$STATUS_CRIT" ) ]]; then
            local hint_trunc="${hint:0:$(( width - 7 ))}"
            tee_out "║    ${YELLOW}→ ${hint_trunc}${RESET}"
        fi
    done

    tee_out "╠${border}╣"
    tee_out "║  Total: ${SYM_GOOD} ${GOOD_COUNT}  ${SYM_WARN} ${WARN_COUNT}  ${SYM_CRIT} ${CRIT_COUNT}"
    tee_out "║  Reporte guardado: ${rpath}"
    tee_out "╚${border}╝"
}

# ─── Argument parsing ─────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                REPORT_PATH="$2"
                shift 2
                ;;
            --indexer-user)
                IDX_USER="$2"
                shift 2
                ;;
            --indexer-pass)
                IDX_PASS="$2"
                shift 2
                ;;
            --indexer-url)
                IDX_URL="$2"
                shift 2
                ;;
            --api-user)
                API_USER="$2"
                shift 2
                ;;
            --api-pass)
                API_PASS="$2"
                shift 2
                ;;
            --api-url)
                API_URL="$2"
                shift 2
                ;;
            -h|--help)
                echo "Uso: sudo bash $0 [-o /ruta/reporte.txt]"
                echo "         [--indexer-user USER] [--indexer-pass PASS] [--indexer-url URL]"
                echo "         [--api-user USER]     [--api-pass PASS]     [--api-url URL]"
                exit 0
                ;;
            *)
                echo "Opción desconocida: $1" >&2
                exit 1
                ;;
        esac
    done
}

# ─── Interactive menu ─────────────────────────────────────────────────────────

show_menu() {
    echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║      === Wazuh Health Check ===      ║${RESET}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════╣${RESET}"
    echo -e "${BOLD}${CYAN}║  Seleccione el tipo de despliegue:   ║${RESET}"
    echo -e "${BOLD}${CYAN}║                                      ║${RESET}"
    echo -e "${BOLD}${CYAN}║  1) AIO (All-In-One) — TODOS         ║${RESET}"
    echo -e "${BOLD}${CYAN}║  2) Dashboard only                   ║${RESET}"
    echo -e "${BOLD}${CYAN}║  3) Manager only                     ║${RESET}"
    echo -e "${BOLD}${CYAN}║  4) Indexer only                     ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════╝${RESET}"

    while true; do
        echo -en "\n  ${BOLD}Ingrese su opción [1-4]: ${RESET}"
        read -r choice
        case "$choice" in
            1) DEPLOY_TYPE="aio"       ; break ;;
            2) DEPLOY_TYPE="dashboard" ; break ;;
            3) DEPLOY_TYPE="manager"   ; break ;;
            4) DEPLOY_TYPE="indexer"   ; break ;;
            *) echo -e "  ${RED}Opción inválida. Por favor ingrese 1, 2, 3 o 4.${RESET}" ;;
        esac
    done
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    # Parse args first so --help works without root
    parse_args "$@"

    # Root check
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}ERROR: Este script debe ejecutarse como root (sudo).${RESET}"
        echo -e "  Ejecute: sudo bash $0"
        exit 1
    fi

    # Determine report path
    if [[ -z "$REPORT_PATH" ]]; then
        local ts
        ts=$(date "+%Y%m%d_%H%M%S")
        local report_dir="/var/ossec/logs"
        mkdir -p "$report_dir" 2>/dev/null || report_dir="/tmp"
        REPORT_PATH="${report_dir}/wazuh_health_check_${ts}.txt"
    else
        local report_dir
        report_dir=$(dirname "$REPORT_PATH")
        mkdir -p "$report_dir" 2>/dev/null || true
    fi

    # Interactive menu
    show_menu

    tee_out "\n${BOLD}$(printf '=%.0s' {1..64})${RESET}"
    tee_out "${BOLD}  Wazuh Health Check — Inicio de Diagnóstico${RESET}"
    tee_out "${BOLD}$(printf '=%.0s' {1..64})${RESET}"
    tee_out "  Tipo de despliegue : ${DEPLOY_TYPE^^}"
    tee_out "  Fecha              : $(date '+%Y-%m-%d %H:%M:%S')"
    tee_out "  Reporte            : ${REPORT_PATH}"
    tee_out "  Indexer URL        : ${IDX_URL}"
    tee_out "  API URL            : ${API_URL}"
    tee_out "${BOLD}$(printf '=%.0s' {1..64})${RESET}\n"

    # ── FASE 1: Server basics (ALL deployment types) ───────────────────────
    fase1_recursos    "$DEPLOY_TYPE"
    fase1_servicios   "$DEPLOY_TYPE"
    fase1_carga

    if [[ "$DEPLOY_TYPE" == "manager" || "$DEPLOY_TYPE" == "aio" ]]; then
        fase1_daemons
    fi

    # ── FASE 2: Manager ────────────────────────────────────────────────────
    if [[ "$DEPLOY_TYPE" == "manager" || "$DEPLOY_TYPE" == "aio" ]]; then
        fase2_version
        fase2_logs
        fase2_cluster
        fase2_agentes
        fase2_queue
    fi

    # ── FASE 3: Indexer ────────────────────────────────────────────────────
    if [[ "$DEPLOY_TYPE" == "indexer" || "$DEPLOY_TYPE" == "aio" ]]; then
        fase3_cluster_health
        fase3_jvm
        fase3_disco
        fase3_shards
        fase3_indices
    fi

    # ── FASE 4: Filebeat ───────────────────────────────────────────────────
    if [[ "$DEPLOY_TYPE" == "manager" || "$DEPLOY_TYPE" == "aio" ]]; then
        fase4_filebeat
        fase4_filebeat_perf
    fi

    # ── FASE 5: Certificates ───────────────────────────────────────────────
    fase5_certs "$DEPLOY_TYPE"

    # ── FASE 6: API ────────────────────────────────────────────────────────
    if [[ "$DEPLOY_TYPE" == "manager" || "$DEPLOY_TYPE" == "aio" ]]; then
        fase6_api
    fi

    # ── FASE 7: Dashboard ──────────────────────────────────────────────────
    if [[ "$DEPLOY_TYPE" == "dashboard" || "$DEPLOY_TYPE" == "aio" ]]; then
        fase7_dashboard
    fi

    # ── FASE 8: End-to-End ─────────────────────────────────────────────────
    if [[ "$DEPLOY_TYPE" == "aio" ]]; then
        fase8_e2e
    fi

    # ── Final Summary ──────────────────────────────────────────────────────
    print_summary "$DEPLOY_TYPE" "$REPORT_PATH"

    # Write report to file
    if echo "$REPORT_CONTENT" > "$REPORT_PATH" 2>/dev/null; then
        echo -e "\n${GREEN}${BOLD}✅ Reporte guardado en: ${REPORT_PATH}${RESET}"
    else
        echo -e "\n${RED}ERROR al guardar reporte en: ${REPORT_PATH}${RESET}"
    fi
}

main "$@"
