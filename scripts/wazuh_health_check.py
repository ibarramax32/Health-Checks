#!/usr/bin/env python3
"""
wazuh_health_check.py — Interactive Wazuh Health Check Script

Based on: README_Version1.md — Wazuh Health Check — Guía Completa Paso a Paso

Usage:
    sudo python3 wazuh_health_check.py [-o /custom/path/report.txt]
                                       [--indexer-user USER] [--indexer-pass PASS]
                                       [--indexer-url URL]
                                       [--api-user USER] [--api-pass PASS]
                                       [--api-url URL]
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time

# ─── Color helpers ────────────────────────────────────────────────────────────
_IS_TTY = sys.stdout.isatty()

def _c(code):
    return code if _IS_TTY else ""

GREEN  = _c("\033[92m")
YELLOW = _c("\033[93m")
RED    = _c("\033[91m")
CYAN   = _c("\033[96m")
BOLD   = _c("\033[1m")
RESET  = _c("\033[0m")

# Traffic-light symbols and labels
SYM_GOOD = "🟢"
SYM_WARN = "🟡"
SYM_CRIT = "🔴"
STATUS_GOOD = "BUENO"
STATUS_WARN = "REGULAR"
STATUS_CRIT = "MALO"

# ─── Global state ─────────────────────────────────────────────────────────────
# Each finding: (section_id, section_name, status, message, hint)
findings = []
# All output lines (ANSI-stripped) for report file
output_lines = []


def record(section_id, section_name, status, message, hint=""):
    """Store a finding for the final summary."""
    findings.append((section_id, section_name, status, message, hint))


def tee(text, end="\n"):
    """Print to stdout and store for report file."""
    print(text, end=end)
    # Strip ANSI escape codes for file
    clean = re.sub(r"\033\[[0-9;]*m", "", text + end)
    output_lines.append(clean)


# ─── Command runner ───────────────────────────────────────────────────────────
def run_cmd(cmd, timeout=30):
    """Run a shell command. Returns (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except Exception as exc:
        return "", str(exc), -1


# ─── Formatting helpers ───────────────────────────────────────────────────────
BOX_WIDTH = 64


def print_header(title):
    line = "═" * BOX_WIDTH
    tee(f"\n{CYAN}{BOLD}{line}{RESET}")
    tee(f"{CYAN}{BOLD}  {title}{RESET}")
    tee(f"{CYAN}{BOLD}{line}{RESET}")


def print_status(label, status, detail=""):
    sym = {STATUS_GOOD: SYM_GOOD, STATUS_WARN: SYM_WARN, STATUS_CRIT: SYM_CRIT}.get(status, "❓")
    color = {STATUS_GOOD: GREEN, STATUS_WARN: YELLOW, STATUS_CRIT: RED}.get(status, RESET)
    msg = f"  {sym} {color}{status}{RESET}  {label}"
    if detail:
        msg += f"  →  {detail}"
    tee(msg)


# ─── FASE 1: Server ───────────────────────────────────────────────────────────

def fase1_recursos(component):
    print_header("FASE 1.1: Recursos del Sistema")

    # ── CPU cores ──────────────────────────────────────────────────────────
    stdout, _, _ = run_cmd("nproc")
    cores = 0
    try:
        cores = int(stdout.strip())
    except ValueError:
        pass
    tee(f"\n  CPU cores: {stdout.strip()}")

    if component in ("manager", "aio"):
        if cores >= 4:
            st, detail = STATUS_GOOD, f"{cores} cores (≥4 recomendado)"
        elif cores >= 2:
            st, detail = STATUS_WARN, f"{cores} cores (recomendado ≥4)"
        else:
            st, detail = STATUS_CRIT, f"{cores} core(s) — insuficiente para Manager"
        print_status("CPU (Manager)", st, detail)
        record("1.1", "Recursos - CPU (Manager)", st, detail,
               "Añadir CPUs al Manager (mínimo 4 cores recomendado)")

    if component in ("indexer", "aio"):
        if cores >= 8:
            st, detail = STATUS_GOOD, f"{cores} cores (≥8 recomendado)"
        elif cores >= 4:
            st, detail = STATUS_WARN, f"{cores} cores (recomendado ≥8)"
        else:
            st, detail = STATUS_CRIT, f"{cores} cores — insuficiente para Indexer"
        print_status("CPU (Indexer)", st, detail)
        record("1.1", "Recursos - CPU (Indexer)", st, detail,
               "Añadir CPUs al Indexer (mínimo 8 cores recomendado)")

    # ── RAM ────────────────────────────────────────────────────────────────
    stdout, _, _ = run_cmd("free -m")
    tee(f"\n{stdout.strip()}")
    ram_mb = 0
    for line in stdout.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            try:
                ram_mb = int(parts[1])
            except (ValueError, IndexError):
                pass
            break
    ram_gb = ram_mb / 1024.0

    if component in ("manager", "aio"):
        if ram_gb >= 8:
            st, detail = STATUS_GOOD, f"{ram_gb:.1f} GB RAM (≥8 GB recomendado)"
        elif ram_gb >= 4:
            st, detail = STATUS_WARN, f"{ram_gb:.1f} GB RAM (recomendado ≥8 GB)"
        else:
            st, detail = STATUS_CRIT, f"{ram_gb:.1f} GB RAM — insuficiente para Manager"
        print_status("RAM (Manager)", st, detail)
        record("1.1", "Recursos - RAM (Manager)", st, detail,
               "Ampliar RAM del Manager (mínimo 8 GB recomendado)")

    if component in ("indexer", "aio"):
        if ram_gb >= 16:
            st, detail = STATUS_GOOD, f"{ram_gb:.1f} GB RAM (≥16 GB recomendado)"
        elif ram_gb >= 8:
            st, detail = STATUS_WARN, f"{ram_gb:.1f} GB RAM (recomendado ≥16 GB)"
        else:
            st, detail = STATUS_CRIT, f"{ram_gb:.1f} GB RAM — insuficiente para Indexer"
        print_status("RAM (Indexer)", st, detail)
        record("1.1", "Recursos - RAM (Indexer)", st, detail,
               "Ampliar RAM del Indexer (mínimo 16 GB recomendado para producción)")

    if component in ("dashboard", "aio"):
        if ram_gb >= 4:
            st, detail = STATUS_GOOD, f"{ram_gb:.1f} GB RAM (≥4 GB recomendado)"
        elif ram_gb >= 2:
            st, detail = STATUS_WARN, f"{ram_gb:.1f} GB RAM (recomendado ≥4 GB)"
        else:
            st, detail = STATUS_CRIT, f"{ram_gb:.1f} GB RAM — insuficiente para Dashboard"
        print_status("RAM (Dashboard)", st, detail)
        record("1.1", "Recursos - RAM (Dashboard)", st, detail,
               "Ampliar RAM del Dashboard (mínimo 4 GB recomendado)")

    # ── Disk / ─────────────────────────────────────────────────────────────
    stdout, _, _ = run_cmd("df -h /")
    tee(f"\n{stdout.strip()}")
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[5] == "/":
            try:
                use_pct = int(parts[4].replace("%", ""))
                if use_pct < 75:
                    st, detail = STATUS_GOOD, f"{use_pct}% usado (<75%)"
                elif use_pct <= 85:
                    st, detail = STATUS_WARN, f"{use_pct}% usado (75-85%)"
                else:
                    st, detail = STATUS_CRIT, f"{use_pct}% usado — CRÍTICO (>85%)"
                print_status("Disco /", st, detail)
                record("1.1", "Recursos - Disco /", st, detail,
                       "Liberar espacio en / o ampliar disco")
            except (ValueError, IndexError):
                pass
            break

    # ── Disk /var (Indexer specific) ───────────────────────────────────────
    if component in ("indexer", "aio"):
        stdout, _, _ = run_cmd("df -h /var")
        tee(f"\n{stdout.strip()}")
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[5] in ("/var", "/var/lib"):
                try:
                    use_pct = int(parts[4].replace("%", ""))
                    if use_pct < 70:
                        st, detail = STATUS_GOOD, f"{use_pct}% usado (<70%)"
                    elif use_pct <= 85:
                        st, detail = STATUS_WARN, f"{use_pct}% usado (70-85%)"
                    else:
                        st, detail = STATUS_CRIT, f"{use_pct}% usado — CRÍTICO (>85%)"
                    print_status("Disco /var (Indexer)", st, detail)
                    record("1.1", "Recursos - Disco /var", st, detail,
                           "Liberar espacio en /var o ampliar disco del Indexer")
                except (ValueError, IndexError):
                    pass
                break

    # ── OS info ────────────────────────────────────────────────────────────
    stdout, _, _ = run_cmd("cat /etc/os-release 2>/dev/null | head -5")
    tee(f"\n  Sistema Operativo:\n{stdout.strip()}")


def fase1_servicios(component):
    print_header("FASE 1.2: Estado de los Servicios")

    services = []
    if component in ("manager", "aio"):
        services.append("wazuh-manager")
    if component in ("indexer", "aio"):
        services.append("wazuh-indexer")
    if component in ("dashboard", "aio"):
        services.append("wazuh-dashboard")
    if component in ("manager", "aio"):
        services.append("filebeat")

    for svc in services:
        stdout, _, _ = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
        active_state = stdout.strip()
        tee(f"\n  Servicio: {BOLD}{svc}{RESET}")
        tee(f"  Estado:   {active_state}")

        # Show full status output
        stdout2, _, _ = run_cmd(f"systemctl status {svc} --no-pager 2>/dev/null | head -10")
        tee(stdout2.strip())

        if active_state == "active":
            st, detail = STATUS_GOOD, "active (running)"
        elif active_state in ("activating", "reloading"):
            st, detail = STATUS_WARN, f"{active_state} — monitoreando"
        else:
            st, detail = STATUS_CRIT, f"{active_state} — servicio no activo"

        print_status(f"Servicio {svc}", st, detail)
        record("1.2", f"Servicio {svc}", st, detail,
               f"Revisar: systemctl status {svc} && journalctl -u {svc} -n 50")

        # Show recent journal entries if not active
        if active_state != "active":
            tee(f"\n  {RED}Últimas entradas de journalctl:{RESET}")
            stdout3, _, _ = run_cmd(f"journalctl -u {svc} --no-pager -n 15 2>/dev/null")
            tee(stdout3.strip())


def fase1_carga():
    print_header("FASE 1.3: Carga del Sistema")

    # ── uptime / load average ──────────────────────────────────────────────
    stdout, _, _ = run_cmd("uptime")
    tee(f"  {stdout.strip()}")

    load_avg_1 = None
    match = re.search(r"load average[s]?:\s*([\d.]+)", stdout)
    if match:
        try:
            load_avg_1 = float(match.group(1))
        except ValueError:
            pass

    stdout_cores, _, _ = run_cmd("nproc")
    try:
        cores = int(stdout_cores.strip())
    except ValueError:
        cores = 1

    if load_avg_1 is not None and cores > 0:
        load_per_core = load_avg_1 / cores
        if load_per_core < 0.7:
            st = STATUS_GOOD
            detail = f"load/core={load_per_core:.2f} (<0.7 — saludable)"
        elif load_per_core <= 1.0:
            st = STATUS_WARN
            detail = f"load/core={load_per_core:.2f} (0.7-1.0 — atención)"
        else:
            st = STATUS_CRIT
            detail = f"load/core={load_per_core:.2f} (>1.0 — sobrecarga)"
        print_status("Load Average", st, detail)
        record("1.3", "Carga - Load Average", st, detail,
               "Load alto. Verificar procesos: top -bn1 | head -20")

    # ── top — CPU usage ────────────────────────────────────────────────────
    stdout, _, _ = run_cmd("top -bn1 | head -5")
    tee(f"\n{stdout.strip()}")

    cpu_idle = None
    for line in stdout.splitlines():
        match = re.search(r"(\d+\.?\d*)\s*id", line)
        if match:
            try:
                cpu_idle = float(match.group(1))
            except ValueError:
                pass
            break

    if cpu_idle is not None:
        cpu_used = 100.0 - cpu_idle
        if cpu_used < 70:
            st, detail = STATUS_GOOD, f"{cpu_used:.1f}% CPU usado (<70%)"
        elif cpu_used <= 90:
            st, detail = STATUS_WARN, f"{cpu_used:.1f}% CPU usado (70-90%)"
        else:
            st, detail = STATUS_CRIT, f"{cpu_used:.1f}% CPU usado — CRÍTICO (>90%)"
        print_status("CPU Total", st, detail)
        record("1.3", "Carga - CPU Total", st, detail,
               "CPU alta. Investigar: ps aux --sort=-%cpu | head -10")

    # ── free — RAM / Swap ──────────────────────────────────────────────────
    stdout, _, _ = run_cmd("free -m")
    tee(f"\n{stdout.strip()}")

    for line in stdout.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            try:
                total = int(parts[1])
                used = int(parts[2])
                pct = (used / total) * 100 if total > 0 else 0
                if pct < 80:
                    st, detail = STATUS_GOOD, f"{pct:.1f}% RAM usado (<80%)"
                elif pct <= 90:
                    st, detail = STATUS_WARN, f"{pct:.1f}% RAM usado (80-90%)"
                else:
                    st, detail = STATUS_CRIT, f"{pct:.1f}% RAM usado — CRÍTICO (>90%)"
                print_status("RAM Usada", st, detail)
                record("1.3", "Carga - RAM Usada", st, detail,
                       "RAM alta. Verificar heap del Indexer y procesos con alto consumo")
            except (ValueError, IndexError):
                pass
            break

    for line in stdout.splitlines():
        if line.startswith("Swap:"):
            parts = line.split()
            try:
                swap_used = int(parts[2])
                if swap_used == 0:
                    st, detail = STATUS_GOOD, "0 MB swap usado"
                elif swap_used < 500:
                    st, detail = STATUS_WARN, f"{swap_used} MB swap usado (<500 MB)"
                else:
                    st, detail = STATUS_CRIT, f"{swap_used} MB swap usado — CRÍTICO (>500 MB)"
                print_status("Swap", st, detail)
                record("1.3", "Carga - Swap", st, detail,
                       "Uso de swap degrada rendimiento gravemente. Añadir RAM o reducir heap del Indexer")
            except (ValueError, IndexError):
                pass
            break

    # ── Wazuh processes ────────────────────────────────────────────────────
    tee("\n  Procesos Wazuh/ossec activos:")
    stdout, _, _ = run_cmd("ps aux | grep -E 'wazuh|ossec' | grep -v grep")
    tee(stdout.strip() if stdout.strip() else "  (ninguno encontrado)")


def fase1_daemons():
    print_header("FASE 1.4: Daemons Internos de Wazuh")

    stdout, stderr, rc = run_cmd("/var/ossec/bin/wazuh-control status 2>/dev/null")
    tee(stdout if stdout else f"  (sin output — rc={rc})")
    if stderr.strip():
        tee(f"  STDERR: {stderr.strip()}")

    critical_daemons = [
        "wazuh-analysisd",
        "wazuh-remoted",
        "wazuh-db",
        "wazuh-modulesd",
        "wazuh-logcollector",
        "wazuh-syscheckd",
        "wazuh-monitord",
        "wazuh-execd",
        "wazuh-apid",
    ]

    all_ok = True
    for daemon in critical_daemons:
        if f"{daemon} is running..." in stdout:
            pass  # running — good
        elif f"{daemon} not running..." in stdout:
            tee(f"  {SYM_CRIT} {RED}{daemon} NOT RUNNING{RESET}")
            record("1.4", f"Daemon {daemon}", STATUS_CRIT,
                   f"{daemon} no está corriendo",
                   f"Reiniciar Manager: systemctl restart wazuh-manager")
            all_ok = False

    if all_ok and stdout:
        print_status("Daemons Críticos", STATUS_GOOD,
                     "Todos los daemons críticos corriendo")
        record("1.4", "Daemons Internos", STATUS_GOOD,
               "Todos los daemons críticos OK")
    elif not stdout:
        print_status("Daemons Críticos", STATUS_WARN,
                     "No se pudo ejecutar wazuh-control status")
        record("1.4", "Daemons Internos", STATUS_WARN,
               "wazuh-control status no disponible",
               "Verificar que /var/ossec/bin/wazuh-control existe y es ejecutable")


# ─── FASE 2: Manager ──────────────────────────────────────────────────────────

def fase2_version():
    print_header("FASE 2.1: Versión y Configuración del Manager")

    stdout, _, _ = run_cmd("/var/ossec/bin/wazuh-control info 2>/dev/null")
    tee(stdout if stdout.strip() else "  (sin output)")

    # Check ossec.conf validity (first 50 lines)
    tee("\n  Primeras líneas de ossec.conf:")
    stdout2, _, _ = run_cmd("cat /var/ossec/etc/ossec.conf 2>/dev/null | head -50")
    tee(stdout2 if stdout2.strip() else "  (no se pudo leer ossec.conf)")

    # Attempt XML validation
    stdout3, stderr3, rc3 = run_cmd(
        "python3 -c \"import xml.etree.ElementTree as ET; "
        "ET.parse('/var/ossec/etc/ossec.conf'); print('XML OK')\" 2>&1"
    )
    if "XML OK" in stdout3:
        print_status("ossec.conf XML", STATUS_GOOD, "XML válido")
        record("2.1", "Manager - ossec.conf XML", STATUS_GOOD, "XML válido")
    else:
        print_status("ossec.conf XML", STATUS_CRIT, "Error de XML en ossec.conf")
        record("2.1", "Manager - ossec.conf XML", STATUS_CRIT,
               "ossec.conf tiene errores XML",
               "Verificar ossec.conf con: xmllint --noout /var/ossec/etc/ossec.conf")

    record("2.1", "Versión Manager", STATUS_GOOD,
           "Versión consultada (verificar que coincide con Indexer y Dashboard)")


def fase2_logs():
    print_header("FASE 2.2: Logs del Manager")

    # ── Recent errors ──────────────────────────────────────────────────────
    tee("  Últimos errores/warnings en ossec.log:")
    stdout, _, _ = run_cmd(
        "grep -iE 'error|critical|warning' /var/ossec/logs/ossec.log 2>/dev/null | tail -30"
    )
    tee(stdout.strip() if stdout.strip() else "  (sin errores recientes)")

    # Count errors + criticals
    stdout2, _, _ = run_cmd(
        "grep -icE 'error|critical' /var/ossec/logs/ossec.log 2>/dev/null || echo 0"
    )
    try:
        error_count = int(stdout2.strip())
    except ValueError:
        error_count = 0

    if error_count == 0:
        st, detail = STATUS_GOOD, "0 ERROR/CRITICAL en ossec.log"
    elif error_count < 20:
        st, detail = STATUS_WARN, f"{error_count} ERROR/CRITICAL en ossec.log"
    else:
        st, detail = STATUS_CRIT, f"{error_count} ERROR/CRITICAL — revisar urgente"
    print_status("Errores en ossec.log", st, detail)
    record("2.2", "Logs Manager - Errores", st, detail,
           "Revisar: grep -iE 'error|critical' /var/ossec/logs/ossec.log | tail -50")

    # ── Log file size ──────────────────────────────────────────────────────
    stdout3, _, _ = run_cmd("ls -lah /var/ossec/logs/ossec.log 2>/dev/null")
    tee(f"\n  Tamaño ossec.log: {stdout3.strip()}")

    stdout4, _, _ = run_cmd(
        "du -sb /var/ossec/logs/ossec.log 2>/dev/null | awk '{print $1}' || echo 0"
    )
    try:
        size_bytes = int(stdout4.strip())
        size_mb = size_bytes / (1024 * 1024)
        if size_mb < 500:
            st, detail = STATUS_GOOD, f"{size_mb:.0f} MB (<500 MB)"
        elif size_mb < 1024:
            st, detail = STATUS_WARN, f"{size_mb:.0f} MB (500 MB–1 GB)"
        else:
            st, detail = STATUS_CRIT, f"{size_mb:.0f} MB (>1 GB — rotación posiblemente rota)"
        print_status("Tamaño ossec.log", st, detail)
        record("2.2", "Logs Manager - Tamaño ossec.log", st, detail,
               "Verificar rotación de logs en /var/ossec/etc/ossec.conf")
    except ValueError:
        pass

    # ── Log directory size ──────────────────────────────────────────────────
    stdout5, _, _ = run_cmd("du -sh /var/ossec/logs/ 2>/dev/null | awk '{print $1}'")
    tee(f"\n  Tamaño directorio /var/ossec/logs/: {stdout5.strip()}")

    stdout6, _, _ = run_cmd(
        "du -sb /var/ossec/logs/ 2>/dev/null | awk '{print $1}' || echo 0"
    )
    try:
        dir_bytes = int(stdout6.strip())
        dir_gb = dir_bytes / (1024 ** 3)
        if dir_gb < 2:
            st, detail = STATUS_GOOD, f"{dir_gb:.1f} GB (<2 GB)"
        elif dir_gb < 5:
            st, detail = STATUS_WARN, f"{dir_gb:.1f} GB (2-5 GB)"
        else:
            st, detail = STATUS_CRIT, f"{dir_gb:.1f} GB (>5 GB)"
        print_status("Tamaño directorio logs", st, detail)
        record("2.2", "Logs Manager - Directorio", st, detail,
               "Limpiar logs antiguos o revisar política de retención")
    except ValueError:
        pass

    # ── Cluster log errors ─────────────────────────────────────────────────
    tee("\n  Errores en cluster.log (últimas 20 líneas):")
    stdout7, _, _ = run_cmd(
        "grep -iE 'error|critical' /var/ossec/logs/cluster.log 2>/dev/null | tail -20"
    )
    tee(stdout7.strip() if stdout7.strip() else "  (sin errores en cluster.log)")


def fase2_cluster():
    print_header("FASE 2.3: Estado del Cluster Wazuh")

    stdout, _, rc = run_cmd(
        "/var/ossec/bin/cluster_control -l 2>/dev/null"
    )
    tee(stdout.strip() if stdout.strip() else "  (sin output — ¿cluster no configurado?)")

    if "connected" in stdout and "disconnected" not in stdout.lower():
        st = STATUS_GOOD
        detail = "Todos los nodos conectados"
    elif "disconnected" in stdout.lower():
        st = STATUS_CRIT
        detail = "Nodo(s) desconectado(s) detectados"
    elif rc != 0 or not stdout.strip():
        st = STATUS_WARN
        detail = "Cluster no configurado o no se pudo consultar"
    else:
        st = STATUS_WARN
        detail = "Estado del cluster no determinado — verificar manualmente"

    print_status("Cluster Wazuh", st, detail)
    record("2.3", "Cluster Manager", st, detail,
           "Verificar conectividad y certificados entre nodos. "
           "Ver: /var/ossec/bin/cluster_control -l")

    stdout2, _, _ = run_cmd("/var/ossec/bin/cluster_control -i 2>/dev/null")
    if stdout2.strip():
        tee(f"\n  Cluster info:\n{stdout2.strip()}")


def fase2_agentes():
    print_header("FASE 2.4: Agentes Conectados")

    stdout, _, _ = run_cmd(
        "/var/ossec/bin/agent_control -l 2>/dev/null | head -30"
    )
    tee(stdout.strip() if stdout.strip() else "  (sin output)")

    stdout2, _, _ = run_cmd(
        "/var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'Active' || echo 0"
    )
    stdout3, _, _ = run_cmd(
        "/var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'Disconnected' || echo 0"
    )
    stdout4, _, _ = run_cmd(
        "/var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'Never connected' || echo 0"
    )

    try:
        active = int(stdout2.strip())
        disconnected = int(stdout3.strip())
        never = int(stdout4.strip())
        total = active + disconnected + never

        tee(f"\n  Agentes Activos:       {active}")
        tee(f"  Agentes Desconectados: {disconnected}")
        tee(f"  Nunca conectados:      {never}")
        tee(f"  Total:                 {total}")

        if total > 0:
            pct_active = (active / total) * 100
            pct_disc = (disconnected / total) * 100

            if pct_active > 95:
                st = STATUS_GOOD
                detail = f"{pct_active:.1f}% activos ({active}/{total})"
            elif pct_active >= 80:
                st = STATUS_WARN
                detail = f"{pct_active:.1f}% activos ({active}/{total}) — por debajo del 95%"
            else:
                st = STATUS_CRIT
                detail = f"{pct_active:.1f}% activos ({active}/{total}) — CRÍTICO (<80%)"
            print_status("Agentes Activos", st, detail)
            record("2.4", "Agentes - % Activos", st, detail,
                   "Investigar agentes desconectados: revisar red y certificados")

            if pct_disc == 0:
                st2, detail2 = STATUS_GOOD, "0 agentes desconectados"
            elif pct_disc < 5:
                st2, detail2 = STATUS_WARN, f"{disconnected} desconectados ({pct_disc:.1f}%)"
            else:
                st2, detail2 = STATUS_CRIT, f"{disconnected} desconectados ({pct_disc:.1f}%) — CRÍTICO"
            print_status("Agentes Desconectados", st2, detail2)
            record("2.4", "Agentes - Desconectados", st2, detail2,
                   "Revisar conectividad de agentes y estado del Manager")
        else:
            tee("  (sin agentes registrados o Manager sin acceso al agente DB)")
            record("2.4", "Agentes", STATUS_WARN,
                   "No se pudo obtener conteo de agentes",
                   "Verificar: /var/ossec/bin/agent_control -l")
    except ValueError:
        tee("  No se pudo contar agentes")
        record("2.4", "Agentes", STATUS_WARN, "No se pudo obtener conteo de agentes")


def fase2_queue():
    print_header("FASE 2.5: Cola de Eventos (Event Queue)")

    tee("  Mensajes de cola en ossec.log:")
    stdout, _, _ = run_cmd(
        "grep -i 'queue' /var/ossec/logs/ossec.log 2>/dev/null | tail -10"
    )
    tee(stdout.strip() if stdout.strip() else "  (sin mensajes de cola)")

    stdout2, _, _ = run_cmd(
        "grep -ic 'event queue is full' /var/ossec/logs/ossec.log 2>/dev/null || echo 0"
    )
    try:
        queue_full = int(stdout2.strip())
    except ValueError:
        queue_full = 0

    if queue_full == 0:
        st, detail = STATUS_GOOD, "0 mensajes 'event queue is full'"
    elif queue_full < 10:
        st, detail = STATUS_WARN, f"{queue_full} mensajes 'event queue is full' (esporádico)"
    else:
        st, detail = STATUS_CRIT, f"{queue_full} mensajes 'event queue is full' — CRÍTICO"

    print_status("Cola de Eventos", st, detail)
    record("2.5", "Cola de Eventos", st, detail,
           "Aumentar analysisd.event_queue_size en ossec.conf o añadir CPU al Manager")


# ─── FASE 3: Indexer ──────────────────────────────────────────────────────────

def fase3_cluster_health(idx_url, idx_user, idx_pass):
    print_header("FASE 3.1: Salud del Cluster del Indexer")

    cmd = (f'curl -sk -u "{idx_user}:{idx_pass}" '
           f'"{idx_url}/_cluster/health?pretty"')
    stdout, stderr, rc = run_cmd(cmd, timeout=20)
    tee(stdout.strip() if stdout.strip() else f"  ERROR: {stderr.strip()}")

    cluster_status = "unknown"
    unassigned = -1
    active_pct = -1.0

    try:
        data = json.loads(stdout)
        cluster_status = data.get("status", "unknown")
        unassigned = int(data.get("unassigned_shards", -1))
        active_pct = float(data.get("active_shards_percent_as_number", -1.0))
    except (json.JSONDecodeError, ValueError):
        pass

    # ── Cluster status ─────────────────────────────────────────────────────
    if cluster_status == "green":
        st, detail = STATUS_GOOD, "Cluster status: GREEN"
    elif cluster_status == "yellow":
        st, detail = STATUS_WARN, "Cluster status: YELLOW — réplicas sin asignar"
    elif cluster_status == "red":
        st, detail = STATUS_CRIT, "Cluster status: RED — POSIBLE PÉRDIDA DE DATOS"
    else:
        st, detail = STATUS_WARN, f"Estado no determinado: {cluster_status}"
    print_status("Cluster Indexer Status", st, detail)
    record("3.1", "Indexer - Cluster Status", st, detail,
           "RED: acción inmediata. YELLOW en AIO/single-node es normal (sin réplicas)")

    # ── Unassigned shards ──────────────────────────────────────────────────
    if unassigned >= 0:
        if unassigned == 0:
            st, detail = STATUS_GOOD, "0 shards sin asignar"
        elif unassigned <= 5:
            st, detail = STATUS_WARN, f"{unassigned} shards sin asignar"
        else:
            st, detail = STATUS_CRIT, f"{unassigned} shards sin asignar — CRÍTICO (>5)"
        print_status("Unassigned Shards", st, detail)
        record("3.1", "Indexer - Unassigned Shards", st, detail,
               "En AIO single-node, réplicas UNASSIGNED es normal. "
               "Verificar primarios si status=RED")

    # ── Active shards % ────────────────────────────────────────────────────
    if active_pct >= 0:
        if active_pct >= 100.0:
            st, detail = STATUS_GOOD, "100% shards activos"
        elif active_pct >= 90.0:
            st, detail = STATUS_WARN, f"{active_pct:.1f}% shards activos"
        else:
            st, detail = STATUS_CRIT, f"{active_pct:.1f}% shards activos — CRÍTICO (<90%)"
        print_status("Active Shards %", st, detail)
        record("3.1", "Indexer - Active Shards %", st, detail,
               "Investigar shards no asignados: _cat/shards?v")

    # ── Nodes list ─────────────────────────────────────────────────────────
    cmd2 = (f'curl -sk -u "{idx_user}:{idx_pass}" '
            f'"{idx_url}/_cat/nodes?v"')
    stdout2, _, _ = run_cmd(cmd2, timeout=20)
    tee(f"\n  Nodos del cluster:\n{stdout2.strip()}")


def fase3_jvm(idx_url, idx_user, idx_pass):
    print_header("FASE 3.2: JVM Heap Memory")

    cmd = (f'curl -sk -u "{idx_user}:{idx_pass}" '
           f'"{idx_url}/_cat/nodes?v&h=name,heap.percent,heap.current,heap.max,ram.percent,cpu"')
    stdout, stderr, rc = run_cmd(cmd, timeout=20)
    tee(stdout.strip() if stdout.strip() else f"  ERROR: {stderr.strip()}")

    lines = stdout.strip().splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 2:
            try:
                node_name = parts[0]
                heap_pct = float(parts[1])
                if heap_pct < 75:
                    st, detail = STATUS_GOOD, f"Heap {heap_pct:.0f}% (<75%)"
                elif heap_pct <= 85:
                    st, detail = STATUS_WARN, f"Heap {heap_pct:.0f}% (75-85%)"
                else:
                    st, detail = STATUS_CRIT, f"Heap {heap_pct:.0f}% — CRÍTICO (>85%)"
                print_status(f"JVM Heap ({node_name})", st, detail)
                record("3.2", f"Indexer - JVM Heap ({node_name})", st, detail,
                       "Ajustar Xmx/Xms en /etc/wazuh-indexer/jvm.options "
                       "(50% de RAM, máx 32 GB)")
            except (ValueError, IndexError):
                pass

    # Check heap.max via detailed stats
    cmd2 = (f'curl -sk -u "{idx_user}:{idx_pass}" '
            f'"{idx_url}/_nodes/stats/jvm?pretty" 2>/dev/null | grep -A5 "heap_max_in_bytes"')
    stdout2, _, _ = run_cmd(cmd2, timeout=20)
    if stdout2.strip():
        tee(f"\n  Detalles JVM heap_max:\n{stdout2.strip()}")


def fase3_disco(idx_url, idx_user, idx_pass):
    print_header("FASE 3.3: Disco y Watermarks")

    cmd = (f'curl -sk -u "{idx_user}:{idx_pass}" '
           f'"{idx_url}/_cat/allocation?v&s=node"')
    stdout, _, _ = run_cmd(cmd, timeout=20)
    tee(stdout.strip() if stdout.strip() else "  (sin output de _cat/allocation)")

    # Parse disk.percent from _cat/allocation
    for line in stdout.strip().splitlines()[1:]:
        parts = line.split()
        # allocation output columns: shards disk.indices disk.used disk.avail disk.total disk.percent host ip node
        if len(parts) >= 6:
            try:
                disk_pct_str = parts[5].replace("%", "")
                disk_pct = float(disk_pct_str)
                node = parts[-1] if len(parts) >= 8 else "?"
                if disk_pct < 75:
                    st, detail = STATUS_GOOD, f"{disk_pct:.0f}% disco usado (<75%)"
                elif disk_pct <= 85:
                    st, detail = STATUS_WARN, f"{disk_pct:.0f}% disco (watermark low: 85%)"
                else:
                    st, detail = STATUS_CRIT, f"{disk_pct:.0f}% disco — CRÍTICO (>85% watermark)"
                print_status(f"Disco Indexer ({node})", st, detail)
                record("3.3", f"Indexer - Disco ({node})", st, detail,
                       "Liberar espacio o ampliar disco. "
                       "Si >95%, índices pasan a read-only (flood stage)")
            except (ValueError, IndexError):
                pass

    # Watermarks
    cmd2 = (f'curl -sk -u "{idx_user}:{idx_pass}" '
            f'"{idx_url}/_cluster/settings?include_defaults=true&pretty" '
            f'2>/dev/null | grep -A3 "watermark" | head -20')
    stdout2, _, _ = run_cmd(cmd2, timeout=20)
    if stdout2.strip():
        tee(f"\n  Watermarks configurados:\n{stdout2.strip()}")

    # OS disk for Indexer data path
    stdout3, _, _ = run_cmd("df -h /var/lib/wazuh-indexer/ 2>/dev/null")
    tee(f"\n  Disco SO (/var/lib/wazuh-indexer/):\n{stdout3.strip()}")


def fase3_shards(idx_url, idx_user, idx_pass):
    print_header("FASE 3.4: Shards — Conteo y Estado")

    # Unassigned shards detail
    cmd = (f'curl -sk -u "{idx_user}:{idx_pass}" '
           f'"{idx_url}/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason" '
           f'2>/dev/null | grep UNASSIGNED | head -20')
    stdout, _, _ = run_cmd(cmd, timeout=20)
    tee(f"  Shards UNASSIGNED:\n{stdout.strip() if stdout.strip() else '  (ninguno)'}")

    # Total and unassigned counts
    cmd2 = (f'curl -sk -u "{idx_user}:{idx_pass}" '
            f'"{idx_url}/_cat/shards" 2>/dev/null | wc -l')
    stdout2, _, _ = run_cmd(cmd2, timeout=20)

    cmd3 = (f'curl -sk -u "{idx_user}:{idx_pass}" '
            f'"{idx_url}/_cat/shards" 2>/dev/null | grep -c UNASSIGNED || echo 0')
    stdout3, _, _ = run_cmd(cmd3, timeout=20)

    try:
        total_shards = int(stdout2.strip())
        unassigned = int(stdout3.strip())
        tee(f"\n  Total shards:  {total_shards}")
        tee(f"  Unassigned:    {unassigned}")

        # Estimate shards per node
        cmd4 = (f'curl -sk -u "{idx_user}:{idx_pass}" '
                f'"{idx_url}/_cat/nodes?v&h=name" 2>/dev/null | grep -v name | wc -l')
        stdout4, _, _ = run_cmd(cmd4, timeout=20)
        node_count = max(1, int(stdout4.strip()))
        shards_per_node = total_shards // node_count if node_count > 0 else total_shards

        if shards_per_node < 1000:
            st, detail = STATUS_GOOD, f"~{shards_per_node} shards/nodo (<1000)"
        elif shards_per_node <= 1500:
            st, detail = STATUS_WARN, f"~{shards_per_node} shards/nodo (1000-1500)"
        else:
            st, detail = STATUS_CRIT, f"~{shards_per_node} shards/nodo — CRÍTICO (>1500)"
        print_status("Shards por Nodo", st, detail)
        record("3.4", "Indexer - Shards por Nodo", st, detail,
               "Reducir shards cerrando índices antiguos o configurando ISM rollover")
    except (ValueError, ZeroDivisionError):
        tee("  No se pudo calcular shards por nodo")


def fase3_indices(idx_url, idx_user, idx_pass):
    print_header("FASE 3.5: Índices — Tamaño y Estado")

    cmd = (f'curl -sk -u "{idx_user}:{idx_pass}" '
           f'"{idx_url}/_cat/indices/wazuh-*?v&s=index" 2>/dev/null | head -30')
    stdout, _, _ = run_cmd(cmd, timeout=20)
    tee(stdout.strip() if stdout.strip() else "  (sin índices wazuh-*)")

    red_count = 0
    yellow_count = 0
    for line in stdout.strip().splitlines()[1:]:
        parts = line.split()
        if parts:
            state = parts[0]
            if state == "red":
                red_count += 1
            elif state == "yellow":
                yellow_count += 1

    if red_count > 0:
        st = STATUS_CRIT
        detail = f"{red_count} índice(s) en estado RED — CRÍTICO"
    elif yellow_count > 0:
        st = STATUS_WARN
        detail = f"{yellow_count} índice(s) en estado YELLOW"
    else:
        st = STATUS_GOOD
        detail = "Todos los índices open/green"

    print_status("Estado Índices", st, detail)
    record("3.5", "Indexer - Estado Índices", st, detail,
           "RED: verificar shards primarios no asignados. "
           "YELLOW en single-node es normal (sin réplicas)")


# ─── FASE 4: Filebeat ─────────────────────────────────────────────────────────

def fase4_filebeat():
    print_header("FASE 4.1: Filebeat — Estado y Conectividad")

    # Service active state
    stdout, _, _ = run_cmd("systemctl is-active filebeat 2>/dev/null")
    active = stdout.strip()
    tee(f"  Estado filebeat: {active}")

    stdout2, _, _ = run_cmd("systemctl status filebeat --no-pager 2>/dev/null | head -10")
    tee(stdout2.strip())

    if active == "active":
        st, detail = STATUS_GOOD, "active (running)"
    elif active == "activating":
        st, detail = STATUS_WARN, "activating — iniciando"
    else:
        st, detail = STATUS_CRIT, f"{active} — servicio no activo"
    print_status("Filebeat Service", st, detail)
    record("4.1", "Filebeat - Servicio", st, detail,
           "Revisar: systemctl status filebeat && journalctl -u filebeat -n 50")

    # filebeat test output
    tee("\n  filebeat test output:")
    stdout3, stderr3, rc3 = run_cmd("filebeat test output 2>&1", timeout=30)
    fb_out = (stdout3 + stderr3).strip()
    tee(fb_out if fb_out else "  (sin output)")

    if "OK" in fb_out and "refused" not in fb_out.lower() and "error" not in fb_out.lower():
        st2, detail2 = STATUS_GOOD, "Conexión al Indexer OK"
    elif "connection refused" in fb_out.lower() or "certificate" in fb_out.lower():
        st2, detail2 = STATUS_CRIT, "Conexión rechazada o error de certificado"
    elif rc3 != 0:
        st2, detail2 = STATUS_CRIT, "filebeat test output falló"
    else:
        st2, detail2 = STATUS_WARN, "Respuesta inesperada — verificar manualmente"
    print_status("filebeat test output", st2, detail2)
    record("4.1", "Filebeat - Test Output", st2, detail2,
           "Verificar certificados TLS y conectividad entre Filebeat e Indexer")

    # filebeat test config
    tee("\n  filebeat test config:")
    stdout4, stderr4, rc4 = run_cmd("filebeat test config 2>&1", timeout=15)
    cfg_out = (stdout4 + stderr4).strip()
    tee(cfg_out if cfg_out else "  (sin output)")

    if "Config OK" in cfg_out:
        st3, detail3 = STATUS_GOOD, "Config OK"
    elif rc4 != 0 or "error" in cfg_out.lower():
        st3, detail3 = STATUS_CRIT, "Error en configuración de Filebeat"
    else:
        st3, detail3 = STATUS_WARN, "Verificar manualmente la configuración"
    print_status("filebeat test config", st3, detail3)
    record("4.1", "Filebeat - Test Config", st3, detail3,
           "Verificar /etc/filebeat/filebeat.yml")


def fase4_filebeat_perf():
    print_header("FASE 4.2: Filebeat — Cola y Rendimiento")

    tee("  Últimos errores/warnings/dropping en filebeat log:")
    stdout, _, _ = run_cmd(
        "grep -iE 'error|warn|dropping' /var/log/filebeat/filebeat 2>/dev/null | tail -20"
    )
    tee(stdout.strip() if stdout.strip() else "  (sin errores en filebeat log)")

    stdout2, _, _ = run_cmd(
        "grep -ic 'dropping' /var/log/filebeat/filebeat 2>/dev/null || echo 0"
    )
    try:
        dropping = int(stdout2.strip())
        if dropping == 0:
            st, detail = STATUS_GOOD, "0 eventos descartados"
        elif dropping < 10:
            st, detail = STATUS_WARN, f"{dropping} eventos descartados (esporádico)"
        else:
            st, detail = STATUS_CRIT, f"{dropping} eventos descartados — CRÍTICO"
        print_status("Dropping Events", st, detail)
        record("4.2", "Filebeat - Dropping Events", st, detail,
               "Verificar capacidad del Indexer y aumentar queue.mem.events en filebeat.yml")
    except ValueError:
        pass

    tee("\n  Métricas de rendimiento (últimas líneas):")
    stdout3, _, _ = run_cmd(
        "grep -iE 'harvester|output|queue|pipeline' /var/log/filebeat/filebeat "
        "2>/dev/null | tail -10"
    )
    tee(stdout3.strip() if stdout3.strip() else "  (sin métricas disponibles)")


# ─── FASE 5: Certificados ─────────────────────────────────────────────────────

def fase5_certs(component):
    print_header("FASE 5.1: Certificados SSL/TLS")

    cert_map = {
        "indexer": [
            ("/etc/wazuh-indexer/certs/wazuh-indexer.pem", "Indexer"),
        ],
        "manager": [
            ("/var/ossec/etc/sslmanager.cert", "Manager SSL"),
        ],
        "dashboard": [
            ("/etc/wazuh-dashboard/certs/wazuh-dashboard.pem", "Dashboard"),
        ],
        "aio": [
            ("/etc/wazuh-indexer/certs/wazuh-indexer.pem", "Indexer"),
            ("/var/ossec/etc/sslmanager.cert", "Manager SSL"),
            ("/etc/wazuh-dashboard/certs/wazuh-dashboard.pem", "Dashboard"),
        ],
    }

    certs = cert_map.get(component, [])

    for cert_path, cert_name in certs:
        tee(f"\n  {BOLD}Certificado: {cert_name}{RESET}")
        tee(f"  Path: {cert_path}")

        if not os.path.exists(cert_path):
            tee(f"  {SYM_WARN} Archivo no encontrado: {cert_path}")
            record("5.1", f"Cert - {cert_name}", STATUS_WARN,
                   f"Archivo no encontrado: {cert_path}",
                   "Verificar path del certificado para el componente correspondiente")
            continue

        # Get expiry date
        cmd = f'openssl x509 -enddate -noout -in "{cert_path}" 2>&1'
        stdout, _, rc = run_cmd(cmd)
        tee(f"  {stdout.strip()}")

        match = re.search(r"notAfter=(.+)", stdout)
        if match:
            expiry_str = match.group(1).strip()
            expiry_date = None
            for fmt in [
                "%b %d %H:%M:%S %Y %Z",
                "%b  %d %H:%M:%S %Y %Z",
                "%b %d %H:%M:%S %Y",
            ]:
                try:
                    expiry_date = datetime.datetime.strptime(expiry_str, fmt)
                    break
                except ValueError:
                    continue

            if expiry_date:
                now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                days_left = (expiry_date - now).days

                if days_left < 0:
                    st = STATUS_CRIT
                    detail = f"EXPIRADO hace {abs(days_left)} días — URGENTE"
                elif days_left < 30:
                    st = STATUS_CRIT
                    detail = f"Expira en {days_left} días — CRÍTICO (<30 días)"
                elif days_left <= 90:
                    st = STATUS_WARN
                    detail = f"Expira en {days_left} días (30-90 días)"
                else:
                    st = STATUS_GOOD
                    detail = f"Expira en {days_left} días (>90 días)"

                print_status(f"Cert {cert_name}", st, detail)
                record("5.1", f"Cert - {cert_name}", st, detail,
                       "Renovar certificados antes de expiración para evitar interrupción del servicio")
            else:
                tee(f"  (No se pudo parsear fecha: {expiry_str})")
        elif rc != 0:
            tee(f"  {SYM_CRIT} Error al leer certificado")
            record("5.1", f"Cert - {cert_name}", STATUS_CRIT,
                   f"No se pudo leer el certificado: {cert_path}",
                   "Verificar permisos y validez del certificado")

        # Show subject and issuer
        cmd2 = f'openssl x509 -subject -issuer -noout -in "{cert_path}" 2>/dev/null'
        stdout2, _, _ = run_cmd(cmd2)
        if stdout2.strip():
            tee(f"  {stdout2.strip()}")


# ─── FASE 6: API ──────────────────────────────────────────────────────────────

def fase6_api(api_url, api_user, api_pass):
    print_header("FASE 6.1: Wazuh API — Conectividad y Respuesta")

    # Get token
    tee("  Obteniendo token de API...")
    t0 = time.monotonic()
    cmd = (f'curl -s -u "{api_user}:{api_pass}" -k '
           f'"{api_url}/security/user/authenticate?raw=true"')
    stdout, stderr, rc = run_cmd(cmd, timeout=15)
    elapsed = time.monotonic() - t0
    token = stdout.strip()

    if token and len(token) > 20 and "error" not in token.lower():
        tee(f"  Token: {token[:20]}...(truncado)")
        if elapsed < 2:
            st, detail = STATUS_GOOD, f"Token obtenido en {elapsed:.2f}s"
        elif elapsed < 5:
            st, detail = STATUS_WARN, f"Token obtenido en {elapsed:.2f}s (lento)"
        else:
            st, detail = STATUS_CRIT, f"Token obtenido en {elapsed:.2f}s — MUY LENTO"
        print_status("API Token", st, detail)
        record("6.1", "API - Token", st, detail,
               "API lenta: verificar carga del Manager y wazuh-apid")
    else:
        tee(f"  ERROR: {stderr.strip() or token}")
        st, detail = STATUS_CRIT, "No se obtuvo token de API"
        print_status("API Token", st, detail)
        record("6.1", "API - Token", st, detail,
               "Verificar: systemctl status wazuh-manager y credenciales wazuh-wui")
        tee(f"  {RED}No se puede continuar sin token de API.{RESET}")
        return

    # GET /
    tee(f"\n  GET {api_url}/ ...")
    t0 = time.monotonic()
    cmd2 = (f'curl -s -k -o /dev/null -w "%{{http_code}}" '
            f'-X GET "{api_url}/?pretty" '
            f'-H "Authorization: Bearer {token}"')
    stdout2, _, _ = run_cmd(cmd2, timeout=15)
    elapsed2 = time.monotonic() - t0
    http_code = stdout2.strip()
    tee(f"  HTTP Status: {http_code} ({elapsed2:.2f}s)")

    if http_code == "200":
        if elapsed2 < 2:
            st2, detail2 = STATUS_GOOD, f"HTTP 200 en {elapsed2:.2f}s"
        elif elapsed2 < 5:
            st2, detail2 = STATUS_WARN, f"HTTP 200 en {elapsed2:.2f}s (lento)"
        else:
            st2, detail2 = STATUS_CRIT, f"HTTP 200 en {elapsed2:.2f}s — MUY LENTO (>5s)"
    else:
        st2, detail2 = STATUS_CRIT, f"HTTP {http_code} — Error de conectividad"
    print_status("API GET /", st2, detail2)
    record("6.1", "API - GET /", st2, detail2,
           f"API responde HTTP {http_code}. Verificar Manager si no es HTTP 200")

    # GET /agents/summary/status
    tee(f"\n  GET {api_url}/agents/summary/status ...")
    cmd3 = (f'curl -s -k -X GET "{api_url}/agents/summary/status?pretty" '
            f'-H "Authorization: Bearer {token}"')
    stdout3, _, _ = run_cmd(cmd3, timeout=15)
    tee(stdout3.strip()[:600] if stdout3.strip() else "  (sin respuesta)")

    # GET /manager/info
    tee(f"\n  GET {api_url}/manager/info ...")
    cmd4 = (f'curl -s -k -X GET "{api_url}/manager/info?pretty" '
            f'-H "Authorization: Bearer {token}"')
    stdout4, _, _ = run_cmd(cmd4, timeout=15)
    tee(stdout4.strip()[:600] if stdout4.strip() else "  (sin respuesta)")


# ─── FASE 7: Dashboard ────────────────────────────────────────────────────────

def fase7_dashboard():
    print_header("FASE 7.1: Wazuh Dashboard — Verificar Servicio y Acceso")

    # Service active state
    stdout, _, _ = run_cmd("systemctl is-active wazuh-dashboard 2>/dev/null")
    active = stdout.strip()
    tee(f"  Estado wazuh-dashboard: {active}")

    stdout2, _, _ = run_cmd(
        "systemctl status wazuh-dashboard --no-pager 2>/dev/null | head -10"
    )
    tee(stdout2.strip())

    if active == "active":
        st, detail = STATUS_GOOD, "active (running)"
    elif active == "activating":
        st, detail = STATUS_WARN, "activating — iniciando"
    else:
        st, detail = STATUS_CRIT, f"{active} — no activo"
    print_status("Dashboard Service", st, detail)
    record("7.1", "Dashboard - Servicio", st, detail,
           "Revisar: systemctl status wazuh-dashboard && journalctl -u wazuh-dashboard -n 50")

    # Port 443
    tee("\n  Puerto 443 (ss -tlnp):")
    stdout3, _, _ = run_cmd("ss -tlnp 2>/dev/null | grep 443")
    tee(stdout3.strip() if stdout3.strip() else "  (no escucha en puerto 443)")

    if stdout3.strip():
        st2, detail2 = STATUS_GOOD, "Puerto 443 escuchando"
    else:
        st2, detail2 = STATUS_CRIT, "Puerto 443 NO escucha — Dashboard puede estar caído"
    print_status("Puerto 443", st2, detail2)
    record("7.1", "Dashboard - Puerto 443", st2, detail2,
           "Verificar configuración del Dashboard y si el servicio está activo")

    # HTTP status code
    tee("\n  Test HTTP https://localhost:443 ...")
    stdout4, _, _ = run_cmd(
        'curl -sk -o /dev/null -w "%{http_code}" "https://localhost:443"',
        timeout=15,
    )
    http_code = stdout4.strip()
    tee(f"  HTTP Status: {http_code}")

    if http_code == "302":
        st3, detail3 = STATUS_GOOD, "HTTP 302 (redirect a login) — OK"
    elif http_code == "200":
        st3, detail3 = STATUS_WARN, "HTTP 200 (sin redirect a login)"
    elif http_code in ("502", "503", "000", ""):
        st3, detail3 = STATUS_CRIT, f"HTTP {http_code} — Error de conectividad"
    else:
        st3, detail3 = STATUS_WARN, f"HTTP {http_code} — verificar manualmente"
    print_status("Dashboard HTTP", st3, detail3)
    record("7.1", "Dashboard - HTTP Status", st3, detail3,
           "502/503: Dashboard no puede conectar al Indexer. "
           "Verificar certificados y estado del Indexer")


# ─── FASE 8: End-to-End ───────────────────────────────────────────────────────

def fase8_e2e(idx_url, idx_user, idx_pass):
    print_header("FASE 8.1: Verificación End-to-End")

    # wazuh-logtest
    tee("  Ejecutando wazuh-logtest con mensaje de prueba...")
    t0 = time.monotonic()
    cmd = (r"""echo '{"message":"test health check alert"}' """
           r"""| timeout 15 /var/ossec/bin/wazuh-logtest 2>&1""")
    stdout, stderr, rc = run_cmd(cmd, timeout=20)
    elapsed = time.monotonic() - t0
    output = (stdout + stderr).strip()
    tee(output[:800] if output else "  (sin respuesta)")

    if output and any(kw in output for kw in
                      ["No rule", "Phase 1", "full_log", "**Phase", "Processing"]):
        if elapsed < 5:
            st, detail = STATUS_GOOD, f"wazuh-logtest responde en {elapsed:.2f}s"
        else:
            st, detail = STATUS_WARN, f"wazuh-logtest responde pero lento ({elapsed:.2f}s)"
    elif rc != 0 or not output:
        st, detail = STATUS_CRIT, "wazuh-logtest no responde o error"
    else:
        st, detail = STATUS_GOOD, f"wazuh-logtest responde en {elapsed:.2f}s"

    print_status("wazuh-logtest", st, detail)
    record("8.1", "E2E - wazuh-logtest", st, detail,
           "Si logtest falla, verificar wazuh-analysisd: "
           "/var/ossec/bin/wazuh-control status")

    # Check recent alerts in Indexer
    tee("\n  Verificando alertas recientes en el Indexer...")
    cmd2 = (f'curl -sk -u "{idx_user}:{idx_pass}" '
            f'"{idx_url}/wazuh-alerts-*/_search?pretty&size=1&sort=timestamp:desc" '
            f'2>/dev/null | head -30')
    stdout2, _, _ = run_cmd(cmd2, timeout=20)
    tee(stdout2.strip() if stdout2.strip() else "  (sin respuesta del Indexer)")

    if '"hits"' in stdout2 and '"total"' in stdout2:
        st2, detail2 = STATUS_GOOD, "Alertas presentes en el Indexer"
    else:
        st2, detail2 = STATUS_WARN, "No se pudieron verificar alertas en el Indexer"
    print_status("Alertas en Indexer", st2, detail2)
    record("8.1", "E2E - Alertas en Indexer", st2, detail2,
           "Si no hay alertas: verificar cadena Manager → Filebeat → Indexer")

    # Filebeat event count
    tee("\n  Verificando flujo de Filebeat...")
    stdout3, _, _ = run_cmd(
        "grep -c 'events' /var/log/filebeat/filebeat 2>/dev/null | tail -1 || echo 0"
    )
    tee(f"  Líneas con 'events' en filebeat log: {stdout3.strip()}")


# ─── Final Summary ────────────────────────────────────────────────────────────

def print_summary(deploy_type, report_path):
    width = 62
    border = "═" * width
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    tee(f"\n╔{border}╗")
    tee(f"║{'RESUMEN DIAGNÓSTICO WAZUH':^{width}}║")
    tee(f"╠{border}╣")

    deploy_label = {
        "aio": "AIO (All-In-One)",
        "manager": "Manager Only",
        "indexer": "Indexer Only",
        "dashboard": "Dashboard Only",
    }.get(deploy_type, deploy_type.upper())

    tee(f"║  Tipo de despliegue: {deploy_label:<{width - 22}}║")
    tee(f"║  Fecha: {now:<{width - 9}}║")
    tee(f"╠{border}╣")

    good_count = warn_count = crit_count = 0

    for section_id, section_name, status, message, hint in findings:
        sym = {STATUS_GOOD: SYM_GOOD, STATUS_WARN: SYM_WARN,
               STATUS_CRIT: SYM_CRIT}.get(status, "❓")
        color = {STATUS_GOOD: GREEN, STATUS_WARN: YELLOW,
                 STATUS_CRIT: RED}.get(status, RESET)
        status_label = {"BUENO": "OK  ", "REGULAR": "WARN", "MALO": "CRIT"}.get(
            status, status[:4])

        # Truncate name to fit in box
        name_trunc = section_name[:38]
        # Build the display line (emoji takes 2 chars in many terminals)
        inner = f"  {sym} {color}{name_trunc:<38}{RESET} {status_label}"
        tee(f"║{inner}║")

        if hint and status in (STATUS_WARN, STATUS_CRIT):
            hint_trunc = hint[:width - 6]
            tee(f"║    {YELLOW}→ {hint_trunc:<{width - 6}}{RESET}║")

        if status == STATUS_GOOD:
            good_count += 1
        elif status == STATUS_WARN:
            warn_count += 1
        elif status == STATUS_CRIT:
            crit_count += 1

    tee(f"╠{border}╣")
    totals = f"  Total: {SYM_GOOD} {good_count}  {SYM_WARN} {warn_count}  {SYM_CRIT} {crit_count}"
    tee(f"║{totals}")
    report_trunc = report_path[:width - 22]
    tee(f"║  Reporte guardado: {report_trunc}")
    tee(f"╚{border}╝")


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Wazuh Interactive Health Check Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  sudo python3 wazuh_health_check.py\n"
            "  sudo python3 wazuh_health_check.py -o /tmp/report.txt\n"
            "  sudo python3 wazuh_health_check.py --indexer-user admin --indexer-pass secreto\n"
        ),
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help="Ruta de salida del reporte (default: /var/ossec/logs/wazuh_health_check_TIMESTAMP.txt)",
    )
    parser.add_argument("--indexer-user", default="admin",
                        help="Usuario del Indexer (default: admin)")
    parser.add_argument("--indexer-pass", default="admin",
                        help="Contraseña del Indexer (default: admin)")
    parser.add_argument("--indexer-url", default="https://localhost:9200",
                        help="URL del Indexer (default: https://localhost:9200)")
    parser.add_argument("--api-user", default="wazuh-wui",
                        help="Usuario de la API (default: wazuh-wui)")
    parser.add_argument("--api-pass", default="wazuh-wui",
                        help="Contraseña de la API (default: wazuh-wui)")
    parser.add_argument("--api-url", default="https://localhost:55000",
                        help="URL de la API (default: https://localhost:55000)")
    return parser.parse_args()


def show_menu():
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║      === Wazuh Health Check ===      ║{RESET}")
    print(f"{BOLD}{CYAN}╠══════════════════════════════════════╣{RESET}")
    print(f"{BOLD}{CYAN}║  Seleccione el tipo de despliegue:   ║{RESET}")
    print(f"{BOLD}{CYAN}║                                      ║{RESET}")
    print(f"{BOLD}{CYAN}║  1) AIO (All-In-One) — TODOS         ║{RESET}")
    print(f"{BOLD}{CYAN}║  2) Dashboard only                   ║{RESET}")
    print(f"{BOLD}{CYAN}║  3) Manager only                     ║{RESET}")
    print(f"{BOLD}{CYAN}║  4) Indexer only                     ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════╝{RESET}")

    deploy_map = {"1": "aio", "2": "dashboard", "3": "manager", "4": "indexer"}
    while True:
        try:
            choice = input(f"\n  {BOLD}Ingrese su opción [1-4]: {RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}Saliendo...{RESET}")
            sys.exit(0)
        if choice in deploy_map:
            return deploy_map[choice]
        print(f"  {RED}Opción inválida. Por favor ingrese 1, 2, 3 o 4.{RESET}")


def main():
    args = parse_args()

    # Root check (after argparse so --help works without root)
    if os.geteuid() != 0:
        print(f"{RED}ERROR: Este script debe ejecutarse como root (sudo).{RESET}")
        print(f"  Ejecute: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    # Determine report path
    if args.output:
        report_path = args.output
        report_dir = os.path.dirname(report_path)
        if report_dir:
            os.makedirs(report_dir, exist_ok=True)
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = "/var/ossec/logs"
        try:
            os.makedirs(report_dir, exist_ok=True)
        except OSError:
            report_dir = "/tmp"
        report_path = os.path.join(report_dir, f"wazuh_health_check_{ts}.txt")

    # Interactive menu
    deploy_type = show_menu()

    tee(f"\n{BOLD}{'=' * 64}{RESET}")
    tee(f"{BOLD}  Wazuh Health Check — Inicio de Diagnóstico{RESET}")
    tee(f"{BOLD}{'=' * 64}{RESET}")
    tee(f"  Tipo de despliegue : {deploy_type.upper()}")
    tee(f"  Fecha              : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    tee(f"  Reporte            : {report_path}")
    tee(f"  Indexer URL        : {args.indexer_url}")
    tee(f"  API URL            : {args.api_url}")
    tee(f"{BOLD}{'=' * 64}{RESET}\n")

    # ── FASE 1: Server basics (ALL deployment types) ───────────────────────
    fase1_recursos(deploy_type)
    fase1_servicios(deploy_type)
    fase1_carga()

    if deploy_type in ("manager", "aio"):
        fase1_daemons()

    # ── FASE 2: Manager ────────────────────────────────────────────────────
    if deploy_type in ("manager", "aio"):
        fase2_version()
        fase2_logs()
        fase2_cluster()
        fase2_agentes()
        fase2_queue()

    # ── FASE 3: Indexer ────────────────────────────────────────────────────
    if deploy_type in ("indexer", "aio"):
        fase3_cluster_health(args.indexer_url, args.indexer_user, args.indexer_pass)
        fase3_jvm(args.indexer_url, args.indexer_user, args.indexer_pass)
        fase3_disco(args.indexer_url, args.indexer_user, args.indexer_pass)
        fase3_shards(args.indexer_url, args.indexer_user, args.indexer_pass)
        fase3_indices(args.indexer_url, args.indexer_user, args.indexer_pass)

    # ── FASE 4: Filebeat (Manager / AIO only) ─────────────────────────────
    if deploy_type in ("manager", "aio"):
        fase4_filebeat()
        fase4_filebeat_perf()

    # ── FASE 5: Certificates ───────────────────────────────────────────────
    fase5_certs(deploy_type)

    # ── FASE 6: API (Manager / AIO only) ──────────────────────────────────
    if deploy_type in ("manager", "aio"):
        fase6_api(args.api_url, args.api_user, args.api_pass)

    # ── FASE 7: Dashboard ──────────────────────────────────────────────────
    if deploy_type in ("dashboard", "aio"):
        fase7_dashboard()

    # ── FASE 8: End-to-End (AIO only) ─────────────────────────────────────
    if deploy_type == "aio":
        fase8_e2e(args.indexer_url, args.indexer_user, args.indexer_pass)

    # ── Final Summary ──────────────────────────────────────────────────────
    print_summary(deploy_type, report_path)

    # Write report to file
    try:
        with open(report_path, "w", encoding="utf-8") as fh:
            for line in output_lines:
                fh.write(line)
        print(f"\n{GREEN}{BOLD}✅ Reporte guardado en: {report_path}{RESET}")
    except OSError as exc:
        print(f"\n{RED}ERROR al guardar reporte: {exc}{RESET}")


if __name__ == "__main__":
    main()
