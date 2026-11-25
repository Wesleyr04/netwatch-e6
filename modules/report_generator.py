import json
import re
from datetime import datetime
from database import get_db_connection
from modules.network_discovery import get_network_info, get_local_interface_traffic
from modules.device_discovery import (
    sort_devices,
    enrich_device_runtime_fields,
    parse_iso_datetime,
    resolve_vendor_oui,
    infer_device_type,
    PORT_SERVICE_NAMES
)
from modules.soc_monitor import get_soc_overview

REMOTE_TRAFFIC_EXPLANATION = "Indisponível para hosts remotos (isolamento L2 sem root/acesso ao roteador)"

def format_duration_ptbr(seconds):
    """Formata segundos em string legível (ex.: '12m 30s', '1h 05m 10s', '45s')."""
    sec = max(0, int(seconds or 0))
    if sec < 60:
        return f"{sec}s"
    mins, s = divmod(sec, 60)
    if mins < 60:
        return f"{mins}m {s:02d}s"
    hrs, m = divmod(mins, 60)
    return f"{hrs}h {m:02d}m {s:02d}s"

def query_recent_discovery_changes(conn, net_info=None, limit=5):
    """
    Retorna os últimos 5 eventos de entrada/saída (`DISCOVERY`) da rede atual
    com `seconds_ago`, `ip`, `action` (`ENTERED`, `RETURNED`, `LEFT`) e `summary`.
    """
    if net_info is None:
        net_info = get_network_info()

    active_cidr = net_info.get("network_cidr") or ""
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, timestamp, event_type, severity, message
        FROM events
        WHERE event_type = 'DISCOVERY'
          AND (
              message LIKE 'DISPOSITIVO ENTROU:%'
              OR message LIKE 'ONLINE: Dispositivo%'
              OR message LIKE 'DISPOSITIVO SAIU%'
          )
        ORDER BY id DESC
        LIMIT 40;
    """)
    rows = cursor.fetchall()
    now_dt = datetime.now()
    changes = []

    for r in rows:
        msg = r["message"] or ""
        if active_cidr and active_cidr not in msg:
            continue

        m_ip = re.search(r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b", msg)
        ip = m_ip.group(1) if m_ip else ""

        if msg.startswith("DISPOSITIVO ENTROU"):
            action = "ENTERED"
            label = f"{ip} entrou na rede"
        elif msg.startswith("ONLINE:"):
            action = "RETURNED"
            label = f"{ip} voltou a ficar online"
        else:
            action = "LEFT"
            label = f"{ip} saiu da rede"

        ts_str = r["timestamp"] or ""
        ts_dt = parse_iso_datetime(ts_str)
        seconds_ago = max(0, int((now_dt - ts_dt).total_seconds())) if ts_dt else 0

        changes.append({
            "id": r["id"],
            "ip": ip,
            "action": action,
            "label": label,
            "message": msg,
            "timestamp": ts_str,
            "seconds_ago": seconds_ago,
            "time_ago_human": f"há {format_duration_ptbr(seconds_ago)}"
        })
        if len(changes) >= limit:
            break

    return changes

def build_device_report_dict(ip, net_info=None):
    """
    Constrói o relatório individual completo de um dispositivo (`GET /api/devices/<ip>`):
    - Dados cadastrais, OUI vendor, device_type, status, `is_trusted`, `custom_name`
    - `session_duration_seconds` calculado em tempo real, `total_online_seconds`,
      `uptime_percent`, `disconnections_count`
    - Estatísticas de latência `min/avg/max` e últimos pontos de `device_latency_history`
    - Lista de `services` com banners capturados
    - Lista de `soc_alerts` vinculados ao dispositivo (MITRE ATT&CK)
    - Últimas 15 entradas da tabela `events` relacionadas a esse IP
    - `traffic` com RX/TX real se for o Host Local ou explicação técnica de isolamento L2.
    """
    if net_info is None:
        net_info = get_network_info()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices WHERE ip = ?;", (ip,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    dev = dict(row)
    now_dt = datetime.now()
    enrich_device_runtime_fields(dev, now_dt)

    my_ip = net_info.get("ip")
    gw_ip = net_info.get("gateway")
    is_local_host = bool(my_ip and ip == my_ip)
    is_gateway = bool(gw_ip and ip == gw_ip)

    resolved_v = resolve_vendor_oui(
        dev.get("mac", "N/A"),
        is_local_host=is_local_host,
        service_details=dev.get("service_details")
    )
    if resolved_v != "Desconhecido":
        dev["vendor"] = resolved_v
    elif not dev.get("vendor"):
        dev["vendor"] = "Desconhecido"

    if not dev.get("device_type") or dev.get("device_type") == "Desconhecido":
        dev["device_type"] = infer_device_type(
            ip,
            dev.get("mac", "N/A"),
            dev["vendor"],
            dev.get("open_ports", ""),
            my_ip=my_ip,
            gateway_ip=gw_ip
        )

    session_sec = dev["session_duration_seconds"]
    total_online_sec = dev["total_online_seconds"]

    first_dt = parse_iso_datetime(dev.get("first_seen")) or parse_iso_datetime(dev.get("last_seen"))
    if first_dt:
        observed_window = max(1, int((now_dt - first_dt).total_seconds()))
    else:
        observed_window = max(1, total_online_sec)

    if dev.get("status") == "ONLINE" and int(dev.get("disconnections_count") or 0) == 0:
        uptime_percent = 100.0
        if total_online_sec < session_sec:
            total_online_sec = session_sec
    else:
        uptime_percent = round(min(100.0, (max(total_online_sec, session_sec) / float(observed_window)) * 100.0), 1)
        if dev.get("status") == "ONLINE" and uptime_percent <= 0.0:
            uptime_percent = 100.0

    # Histórico e estatísticas de latência (min / avg / max)
    cursor.execute("""
        SELECT timestamp, latency_ms, status
        FROM device_latency_history
        WHERE ip = ?
        ORDER BY id DESC
        LIMIT 50;
    """, (ip,))
    lat_rows = [dict(r) for r in cursor.fetchall()]

    valid_lats = [float(r["latency_ms"]) for r in lat_rows if r.get("latency_ms") is not None]
    if not valid_lats and dev.get("latency") is not None:
        valid_lats = [float(dev["latency"])]

    if valid_lats:
        lat_stats = {
            "min_ms": round(min(valid_lats), 2),
            "avg_ms": round(sum(valid_lats) / len(valid_lats), 2),
            "max_ms": round(max(valid_lats), 2),
            "samples_count": len(valid_lats)
        }
    else:
        lat_stats = {
            "min_ms": 0.0,
            "avg_ms": 0.0,
            "max_ms": 0.0,
            "samples_count": 0
        }

    # Serviços e banners
    services = dev.get("service_details_list") or []
    if not services and dev.get("open_ports"):
        for p_str in str(dev["open_ports"]).split(","):
            p_s = p_str.strip()
            if p_s.isdigit():
                p_int = int(p_s)
                sname = PORT_SERVICE_NAMES.get(p_int, f"TCP/{p_int}")
                services.append({
                    "port": p_int,
                    "service": sname,
                    "banner": "NetWatch E6 Web Dashboard (Flask)" if (is_local_host and p_int == 5000) else f"Porta {p_int} ({sname}) Aberta"
                })

    # Verifica se a baseline da sub-rede deste dispositivo está travada
    dev_cidr = dev.get("network_cidr") or net_info.get("network_cidr") or ""
    cursor.execute("SELECT baseline_locked FROM soc_network_baselines WHERE network_cidr = ?;", (dev_cidr,))
    b_row = cursor.fetchone()
    baseline_locked = bool(b_row and int(b_row["baseline_locked"] or 0) == 1)

    # Alertas SOC vinculados estritamente a este IP
    ip_regex = re.compile(rf"(?<![0-9.]){re.escape(ip)}(?![0-9.])")
    cursor.execute("SELECT * FROM soc_alerts WHERE target_ip LIKE ? ORDER BY id DESC LIMIT 40;", (f"%{ip}%",))
    host_soc_alerts = [
        dict(r) for r in cursor.fetchall()
        if ip_regex.search(r["target_ip"] or "") or ip_regex.search(r["title"] or "")
    ][:15]

    # Últimos 15 eventos relacionados estritamente a este IP
    cursor.execute("""
        SELECT id, timestamp, event_type, severity, message
        FROM events
        WHERE message LIKE ?
        ORDER BY id DESC
        LIMIT 80;
    """, (f"%{ip}%",))
    host_events = [dict(r) for r in cursor.fetchall() if ip_regex.search(r["message"] or "")][:15]

    conn.close()

    if is_local_host:
        traffic = get_local_interface_traffic(net_info.get("interface", "wlan0"))
    else:
        traffic = {
            "available": False,
            "rx_bytes": None,
            "tx_bytes": None,
            "rx_mb": None,
            "tx_mb": None,
            "rx_rate_kbps": None,
            "tx_rate_kbps": None,
            "note": REMOTE_TRAFFIC_EXPLANATION
        }

    return {
        "ip": dev["ip"],
        "mac": dev.get("mac") or "N/A",
        "hostname": dev.get("hostname") or "Dispositivo na LAN",
        "custom_name": dev.get("custom_name") or "",
        "is_trusted": int(dev.get("is_trusted") or 0),
        "baseline_locked": baseline_locked,
        "vendor": dev["vendor"],
        "device_type": dev["device_type"],
        "status": dev.get("status", "OFFLINE"),
        "network_cidr": dev_cidr,
        "open_ports": dev.get("open_ports") or "",
        "latency": dev.get("latency") or 0.0,
        "first_seen": dev.get("first_seen") or dev.get("last_seen"),
        "last_seen": dev.get("last_seen"),
        "connected_since": dev.get("connected_since"),
        "last_state_change": dev.get("last_state_change"),
        "last_event_type": dev.get("last_event_type") or "",
        "recently_changed": dev.get("recently_changed", False),
        "seconds_since_change": dev.get("seconds_since_change"),
        "is_local_host": is_local_host,
        "is_gateway": is_gateway,
        "session_duration_seconds": session_sec,
        "session_duration_human": format_duration_ptbr(session_sec) if dev.get("status") == "ONLINE" else "Offline",
        "total_online_seconds": total_online_sec,
        "total_online_human": format_duration_ptbr(total_online_sec),
        "uptime_percent": uptime_percent,
        "disconnections_count": int(dev.get("disconnections_count") or 0),
        "latency_stats": lat_stats,
        "latency_history": lat_rows[::-1],
        "services": services,
        "soc_alerts": host_soc_alerts,
        "events": host_events,
        "traffic": traffic
    }

def generate_device_markdown_report(ip, net_info=None):
    """Exporta o Relatório Individual completo de um dispositivo em formato Markdown (.md)."""
    rep = build_device_report_dict(ip, net_info=net_info)
    if not rep:
        return None

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lat = rep["latency_stats"]
    tr = rep["traffic"]
    trust_label = "AUTORIZADO (Baseline Confiável)" if rep["is_trusted"] == 1 else "Não Verificado"

    lines = [
        f"# Relatório Individual do Dispositivo — `{rep['ip']}`",
        f"**Gerado em:** `{now_str}` | **Sub-rede:** `{rep['network_cidr']}`",
        "\n---",
        "## 1. Identificação e Perfil",
        f"- **Endereço IPv4:** `{rep['ip']}`",
        f"- **Hostname:** `{rep['hostname']}`",
        f"- **Apelido Personalizado:** `{rep['custom_name'] or '-'}`",
        f"- **Confiança SOC:** **{trust_label}**",
        f"- **Endereço MAC:** `{rep['mac']}`",
        f"- **Fabricante (OUI):** `{rep['vendor']}`",
        f"- **Tipo de Dispositivo:** `{rep['device_type']}`",
        f"- **Status Atual:** **{rep['status']}**",
        "\n---",
        "## 2. Tempo de Sessão & Disponibilidade",
        f"- **Sessão Atual:** `{rep['session_duration_human']}` ({rep['session_duration_seconds']}s)",
        f"- **Conectado Desde:** `{rep['connected_since'] or 'Offline'}`",
        f"- **Tempo Total Acumulado:** `{rep['total_online_human']}` ({rep['total_online_seconds']}s)",
        f"- **Disponibilidade (Uptime):** `{rep['uptime_percent']}%`",
        f"- **Primeira Detecção:** `{rep['first_seen'] or '-'}`",
        f"- **Última Detecção:** `{rep['last_seen'] or '-'}`",
        f"- **Quedas / Desconexões:** `{rep['disconnections_count']}`",
        "\n---",
        "## 3. Desempenho de Latência & Tráfego",
        f"- **Latência Atual:** `{rep['latency']} ms`",
        f"- **Latência Mín / Méd / Máx:** `{lat['min_ms']} ms` / `{lat['avg_ms']} ms` / `{lat['max_ms']} ms` ({lat['samples_count']} amostras)"
    ]

    if tr.get("available"):
        lines.extend([
            f"- **Tráfego Recebido (RX):** `{tr['rx_mb']} MB` ({tr['rx_bytes']} bytes) • Taxa: `{tr['rx_rate_kbps']} KB/s`",
            f"- **Tráfego Enviado (TX):** `{tr['tx_mb']} MB` ({tr['tx_bytes']} bytes) • Taxa: `{tr['tx_rate_kbps']} KB/s`",
            f"- **Fonte de Medição:** `{tr.get('note', '/proc/net/dev')}`"
        ])
    else:
        lines.append(f"- **Tráfego de Rede (RX/TX):** *{tr.get('note', REMOTE_TRAFFIC_EXPLANATION)}*")

    lines.extend([
        "\n---",
        "## 4. Serviços & Portas Detectadas",
        "| Porta | Serviço | Banner / Identificação |",
        "| :--- | :--- | :--- |"
    ])

    if not rep["services"]:
        lines.append("| - | *Nenhuma porta TCP aberta detectada* | - |")
    else:
        for s in rep["services"]:
            lines.append(f"| `{s['port']}/TCP` | **{s['service']}** | `{s.get('banner', '-')}` |")

    lines.extend([
        "\n---",
        "## 5. Postura SOC & Alertas Automáticos (MITRE ATT&CK)",
        "| Horário | Severidade | MITRE | Categoria | Título | Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ])

    if not rep["soc_alerts"]:
        lines.append("| - | - | - | - | *Nenhum alerta SOC registrado para este dispositivo* | - |")
    else:
        for a in rep["soc_alerts"]:
            lines.append(
                f"| `{a['timestamp']}` | **{a['severity']}** | `{a['mitre_id']}` | `{a['category']}` | {a['title']} | `{a['status']}` |"
            )

    lines.extend([
        "\n---",
        "## 6. Histórico de Eventos deste Host",
        "| Data/Hora | Tipo | Severidade | Evento |",
        "| :--- | :--- | :--- | :--- |"
    ])

    if not rep["events"]:
        lines.append("| - | - | - | *Nenhum evento registrado para este IP* |")
    else:
        for e in rep["events"]:
            lines.append(f"| `{e['timestamp']}` | `{e['event_type']}` | **{e['severity']}** | {e['message']} |")

    return "\n".join(lines)

def generate_report_data():
    """Consolida todas as informações do banco filtradas pela sub-rede ativa atual, incluindo SOC."""
    conn = get_db_connection()
    cursor = conn.cursor()

    net_info = get_network_info()
    active_cidr = net_info.get("network_cidr", "")

    if net_info.get("is_connected") and active_cidr:
        cursor.execute("SELECT * FROM devices WHERE network_cidr = ?;", (active_cidr,))
    else:
        cursor.execute("SELECT * FROM devices;")

    now_dt = datetime.now()
    devices = [enrich_device_runtime_fields(dict(row), now_dt) for row in cursor.fetchall()]
    devices = sort_devices(devices, my_ip=net_info.get("ip"), gateway_ip=net_info.get("gateway"))

    cursor.execute("SELECT name, host, port, service_type, status, latency, last_check, details FROM monitored_services;")
    services = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT timestamp, gateway_ip, gateway_latency, external_latency, dns_latency, classification, details
        FROM connectivity_logs ORDER BY id DESC LIMIT 20;
    """)
    conn_logs = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT timestamp, event_type, severity, message FROM events ORDER BY id DESC LIMIT 30;")
    events = [dict(row) for row in cursor.fetchall()]

    conn.close()

    soc_overview = get_soc_overview(net_info=net_info)

    return {
        "metadata": {
            "title": "Relatório Técnico NetWatch E6",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device": "Motorola Moto E6 Play (XT2029-3 / bali)",
            "soc": "MediaTek MT6739WW (ARMv7 32-bit)",
            "os": "Android 9 Pie (API 28)",
            "environment": "Termux Linux Userspace (Non-Root)"
        },
        "network": net_info,
        "soc": soc_overview,
        "summary": {
            "total_devices": len(devices),
            "online_devices": len([d for d in devices if d.get("status") == "ONLINE"]),
            "total_services": len(services),
            "online_services": len([s for s in services if s.get("status") == "ONLINE"]),
            "total_events": len(events),
            "soc_posture": soc_overview.get("posture", "SEGURO"),
            "soc_open_alerts": soc_overview.get("counts", {}).get("total_open", 0)
        },
        "devices": devices,
        "services": services,
        "recent_connectivity_logs": conn_logs,
        "recent_events": events
    }

def generate_markdown_report():
    """Gera um relatório técnico estruturado em formato Markdown incluindo Postura SOC."""
    data = generate_report_data()
    meta = data["metadata"]
    net = data["network"]
    summ = data["summary"]
    soc = data.get("soc", {})

    lines = [
        f"# {meta['title']}",
        f"**Data de Geração:** `{meta['generated_at']}` | **Ambiente:** `{meta['environment']}`",
        f"**Hardware:** `{meta['device']}` | **SoC:** `{meta['soc']}` | **SO:** `{meta['os']}`",
        "\n---",
        "## 1. Visão Geral da Rede Local",
        f"- **Interface Ativa:** `{net.get('interface', 'N/A')}`",
        f"- **Endereço IPv4 Local:** `{net.get('ip', 'N/A')}` / `{net.get('cidr', 24)}`",
        f"- **Máscara de Sub-rede:** `{net.get('netmask', 'N/A')}`",
        f"- **Bloco CIDR de Varredura:** `{net.get('network_cidr', 'N/A')}`",
        f"- **Gateway Padrão:** `{net.get('gateway', 'N/A')}` (MAC Travado: `{soc.get('gateway_mac_locked', 'N/A')}`)",
        f"- **Servidores DNS Primário/Secundário:** `{', '.join(net.get('dns', []))}`",
        "\n---",
        "## 2. Resumo de Métricas e Disponibilidade",
        f"- **Postura SOC da Rede:** **`{soc.get('posture', 'SEGURO')}`** (Alertas Abertos: `{summ.get('soc_open_alerts', 0)}`)",
        f"- **Baseline de Dispositivos:** `{'TRAVADA' if soc.get('baseline_locked') else 'DESTRAVADA'}`",
        f"- **Dispositivos na Rede Atual:** Total: `{summ['total_devices']}` | Online: `{summ['online_devices']}`",
        f"- **Serviços Monitorados:** Total: `{summ['total_services']}` | Online: `{summ['online_services']}`",
        "\n---",
        "## 3. Postura SOC & Alertas Automáticos (MITRE ATT&CK)",
        "| Horário | Severidade | MITRE | Categoria | Alvo | Título | Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ]

    soc_alerts = soc.get("alerts") or []
    if not soc_alerts:
        lines.append("| - | - | - | - | - | *Nenhum alerta SOC registrado na sub-rede atual* | - |")
    else:
        for a in soc_alerts[:25]:
            lines.append(
                f"| `{a['timestamp']}` | **{a['severity']}** | `{a['mitre_id']}` | `{a['category']}` | `{a.get('target_ip') or '-'}` | {a['title']} | `{a['status']}` |"
            )

    lines.extend([
        "\n---",
        "## 4. Dispositivos Descobertos na LAN (/24)",
        "| IP | Hostname | Fabricante (OUI) | Tipo | MAC | Portas Abertas | Confiança | Latência | Última Detecção | Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ])

    if not data["devices"]:
        lines.append("| - | *Nenhum dispositivo varrido ainda* | - | - | - | - | - | - | - | - |")
    else:
        for d in data["devices"]:
            host = d.get("custom_name") or d.get("hostname") or "-"
            vendor = d.get("vendor") or "Desconhecido"
            dtype = d.get("device_type") or "Dispositivo na LAN"
            mac = d.get("mac") or "N/A"
            ports = d.get("open_ports") or "Nenhuma"
            trust = "Autorizado" if int(d.get("is_trusted") or 0) == 1 else "Padrão"
            lat = f"{d.get('latency', 0.0)} ms"
            last_seen = d.get("last_seen") or "-"
            lines.append(f"| `{d['ip']}` | {host} | {vendor} | {dtype} | `{mac}` | `{ports}` | {trust} | {lat} | `{last_seen}` | **{d['status']}** |")

    lines.extend([
        "\n---",
        "## 5. Auditoria de Serviços de Rede",
        "| Serviço | Destino | Tipo | Status | Latência | Detalhes |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ])

    for s in data["services"]:
        lines.append(f"| {s['name']} | `{s['host']}:{s['port']}` | `{s['service_type']}` | **{s['status']}** | {s['latency']} ms | {s['details'] or '-'} |")

    lines.extend([
        "\n---",
        "## 6. Histórico Recente de Conectividade Externa",
        "| Horário | Gateway | Lat. Gateway | Lat. WAN (1.1.1.1) | Lat. DNS | Diagnóstico |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ])

    if not data["recent_connectivity_logs"]:
        lines.append("| - | - | - | - | - | *Sem registros* |")
    else:
        for l in data["recent_connectivity_logs"][:10]:
            gw_lat = f"{l['gateway_latency']} ms" if l['gateway_latency'] is not None else "FALHA"
            wan_lat = f"{l['external_latency']} ms" if l['external_latency'] is not None else "FALHA"
            dns_lat = f"{l['dns_latency']} ms" if l['dns_latency'] is not None else "FALHA"
            lines.append(f"| {l['timestamp']} | `{l['gateway_ip']}` | {gw_lat} | {wan_lat} | {dns_lat} | `{l['classification']}` |")

    lines.extend([
        "\n---",
        "## 7. Registro de Alertas e Eventos",
        "| Horário | Tipo | Severidade | Mensagem |",
        "| :--- | :--- | :--- | :--- |"
    ])

    if not data["recent_events"]:
        lines.append("| - | - | - | *Nenhum evento registrado* |")
    else:
        for e in data["recent_events"][:15]:
            lines.append(f"| {e['timestamp']} | `{e['event_type']}` | **{e['severity']}** | {e['message']} |")

    return "\n".join(lines)

def generate_json_report():
    """Gera um relatório completo em formato JSON formatado."""
    return json.dumps(generate_report_data(), indent=2, ensure_ascii=False)

if __name__ == "__main__":
    print(generate_markdown_report())
