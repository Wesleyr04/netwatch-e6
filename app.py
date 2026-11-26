from flask import Flask, render_template, jsonify, request, Response, send_from_directory
import threading
import time
import os
from database import init_db, get_db_connection, log_event, ack_soc_alert, get_open_soc_alert_counts
from modules.network_discovery import get_network_info
from modules.device_discovery import (
    quick_presence_scan,
    query_filtered_devices,
    clear_offline_devices,
    calculate_device_counts
)
from modules.connectivity_monitor import run_connectivity_check
from modules.service_monitor import verify_all_services, probe_service
from modules.soc_monitor import (
    run_fast_soc_cycle,
    run_wan_soc_cycle,
    get_soc_overview,
    lock_current_network_baseline,
    set_device_trust
)
from modules.report_generator import (
    generate_markdown_report,
    generate_json_report,
    build_device_report_dict,
    generate_device_markdown_report,
    query_recent_discovery_changes
)

BASE_APP_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, root_path=BASE_APP_DIR)

# Controle de estado de varredura
is_scanning = False
last_scan_time = None
scan_lock = threading.Lock()

@app.after_request
def apply_no_cache_headers(response):
    """Garante que nenhuma resposta de /api/* ou Service Worker seja cacheada pelo WebView/Chrome."""
    if request.path.startswith("/api/") or request.path in ("/sw.js", "/manifest.json", "/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

def run_discovery_cycle(force_deep=False):
    """
    Executa `get_network_info()` ANTES de `quick_presence_scan()` e em seguida
    roda os 3 detectores SOC rápidos de LAN (`check_arp_integrity`, `check_ports_and_drift`,
    `check_rogue_devices`), garantindo liberação de `is_scanning = False` no finally.
    """
    global is_scanning, last_scan_time
    with scan_lock:
        if is_scanning:
            return False
        is_scanning = True

    try:
        current_net = get_network_info()
        if not current_net.get("is_connected"):
            return False
        cidr = current_net.get("network_cidr") or f"{current_net.get('ip', '127.0.0.1')}/24"
        quick_presence_scan(
            network_cidr=cidr,
            my_ip=current_net.get("ip", "127.0.0.1"),
            gateway_ip=current_net.get("gateway"),
            interface=current_net.get("interface", "wlan0"),
            force_deep=force_deep
        )
        run_fast_soc_cycle(net_info=current_net)
        last_scan_time = time.strftime("%H:%M:%S")
        return True
    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        log_event("SCAN", "ERROR", f"Falha na varredura: {e}")
        return False
    finally:
        is_scanning = False

def presence_monitor_worker():
    """
    Thread daemon rápida: executa `quick_presence_scan()` + sensores SOC de LAN
    a cada 15 segundos sem bloquear requisições HTTP.
    """
    time.sleep(1.0)
    while True:
        try:
            if not is_scanning:
                run_discovery_cycle(force_deep=False)
        except Exception as e:
            print(f"[PRESENCE WORKER] Erro: {e}")
        time.sleep(15)

def connectivity_and_services_worker():
    """
    Thread daemon de conectividade externa, serviços e sensores SOC WAN (DoH DNS + TLS)
    a cada 30 segundos.
    """
    time.sleep(2.5)
    while True:
        try:
            net_info = get_network_info()
            if net_info.get("is_connected"):
                gw = net_info.get("gateway") or "127.0.0.1"
                run_connectivity_check(gw)
                verify_all_services()
                run_wan_soc_cycle(net_info=net_info)
        except Exception as e:
            print(f"[CONNECTIVITY WORKER] Erro: {e}")
        time.sleep(30)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/apresentacao")
def apresentacao_banca():
    """Serve a apresentação interativa de 9 slides para a banca do SENAC SP."""
    return send_from_directory(BASE_APP_DIR, "apresentacao_banca_senac.html", mimetype="text/html")

@app.route("/manifest.json")
def pwa_manifest():
    return send_from_directory(app.static_folder, "manifest.json", mimetype="application/manifest+json")

@app.route("/sw.js")
def pwa_sw():
    resp = send_from_directory(app.static_folder, "sw.js", mimetype="application/javascript")
    resp.headers["Service-Worker-Allowed"] = "/"
    return resp

@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    """Retorna dados consolidados para os cards de status, gráficos e contador SOC."""
    conn = get_db_connection()
    cursor = conn.cursor()

    scope = request.args.get("scope", "current")
    net_info = get_network_info()

    active_devices = query_filtered_devices(conn, net_info, scope=scope)
    dev_counts = calculate_device_counts(
        active_devices,
        my_ip=net_info.get("ip") if net_info.get("is_connected") else None,
        gateway_ip=net_info.get("gateway") if net_info.get("is_connected") else None
    )
    total_devices = dev_counts["total_count"]
    online_devices = dev_counts["online_count"]

    cursor.execute("""
        SELECT gateway_ip, gateway_latency, external_latency, dns_latency, classification, details, timestamp
        FROM connectivity_logs ORDER BY id DESC LIMIT 1;
    """)
    last_conn_row = cursor.fetchone()
    last_conn = dict(last_conn_row) if last_conn_row else {
        "classification": "AGUARDANDO",
        "gateway_latency": 0.0,
        "external_latency": 0.0,
        "dns_latency": 0.0,
        "details": "Nenhum teste executado ainda"
    }

    cursor.execute("SELECT COUNT(*) FROM monitored_services;")
    total_services = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM monitored_services WHERE status = 'ONLINE';")
    online_services = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events;")
    total_events = cursor.fetchone()[0]

    cursor.execute("""
        SELECT timestamp, gateway_latency, external_latency, dns_latency, classification
        FROM connectivity_logs ORDER BY id DESC LIMIT 15;
    """)
    recent_logs = [dict(r) for r in cursor.fetchall()][::-1]

    soc_counts = get_open_soc_alert_counts(conn, network_cidr=net_info.get("network_cidr"))
    conn.close()

    if soc_counts["CRITICAL"] > 0:
        soc_posture = "CRITICO"
    elif soc_counts["HIGH"] > 0 or soc_counts["MEDIUM"] > 0:
        soc_posture = "ATENCAO"
    else:
        soc_posture = "SEGURO"

    return jsonify({
        "network": net_info,
        "connectivity": last_conn,
        "metrics": {
            "total_devices": total_devices,
            "online_devices": online_devices,
            "offline_devices": dev_counts["offline_count"],
            "online_clients": dev_counts["online_clients_count"],
            "online_infra": dev_counts["online_infra_count"],
            "total_services": total_services,
            "online_services": online_services,
            "total_events": total_events,
            "soc_open_alerts": soc_counts["total_open"],
            "soc_posture": soc_posture,
            "is_scanning": is_scanning,
            "last_scan_time": last_scan_time
        },
        "history": recent_logs
    })

@app.route("/api/devices", methods=["GET"])
def api_devices():
    """
    Retorna lista de dispositivos da sub-rede ativa (ou todos com `?scope=all`),
    ordenados por: (1) `recently_changed` mais recente primeiro, (2) `ONLINE` antes
    de `OFFLINE`, (3) Host Local e Gateway, (4) IP numérico, além de `recent_changes`
    e `baseline_locked`.
    """
    scope = request.args.get("scope", "current")
    net_info = get_network_info()
    active_cidr = net_info.get("network_cidr") or ""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT baseline_locked FROM soc_network_baselines WHERE network_cidr = ?;", (active_cidr,))
    b_row = cursor.fetchone()
    baseline_locked = bool(b_row and int(b_row["baseline_locked"] or 0) == 1)

    devices = query_filtered_devices(conn, net_info, scope=scope)
    dev_counts = calculate_device_counts(
        devices,
        my_ip=net_info.get("ip") if net_info.get("is_connected") else None,
        gateway_ip=net_info.get("gateway") if net_info.get("is_connected") else None
    )
    recent_changes = query_recent_discovery_changes(conn, net_info=net_info, limit=5)
    conn.close()
    return jsonify({
        "devices": devices,
        "count": dev_counts["total_count"],
        "online_count": dev_counts["online_count"],
        "offline_count": dev_counts["offline_count"],
        "online_clients_count": dev_counts["online_clients_count"],
        "online_infra_count": dev_counts["online_infra_count"],
        "network_cidr": active_cidr,
        "baseline_locked": baseline_locked,
        "scope": scope,
        "is_scanning": is_scanning,
        "last_scan_time": last_scan_time,
        "recent_changes": recent_changes
    })

@app.route("/api/devices/<ip>", methods=["GET"])
def api_device_individual_report(ip):
    """Retorna o Relatório Individual completo do dispositivo especificado por `<ip>`."""
    net_info = get_network_info()
    report = build_device_report_dict(ip, net_info=net_info)
    if not report:
        return jsonify({"status": "NOT_FOUND", "message": f"Dispositivo {ip} não encontrado."}), 404
    return jsonify(report)

@app.route("/api/devices/<ip>/trust", methods=["POST"])
def api_toggle_device_trust(ip):
    """Alterna `is_trusted` (e opcionalmente atualiza `custom_name`) direto do modal do dispositivo."""
    data = request.get_json(silent=True) or {}
    is_trusted = data.get("is_trusted") if "is_trusted" in data else None
    custom_name = data.get("custom_name") if "custom_name" in data else None

    net_info = get_network_info()
    res = set_device_trust(ip, is_trusted=is_trusted, custom_name=custom_name, net_info=net_info)
    if not res:
        return jsonify({"status": "NOT_FOUND", "message": f"Dispositivo {ip} não encontrado."}), 404

    label = "CONFIÁVEL (Autorizado)" if res["is_trusted"] == 1 else "NÃO VERIFICADO"
    log_event("SOC_TRUST", "INFO", f"Dispositivo {ip} marcado como {label}.")
    return jsonify({
        "status": "SUCCESS",
        "ip": res["ip"],
        "is_trusted": res["is_trusted"],
        "custom_name": res["custom_name"],
        "message": f"Dispositivo {ip} atualizado para {label}."
    })

@app.route("/api/soc/overview", methods=["GET"])
def api_soc_overview():
    """
    Retorna postura geral SOC (`SEGURO`, `ATENCAO`, `CRITICO`), contagem de alertas
    por severidade, status dos 4 sensores automáticos, `gateway_mac_locked`,
    `baseline_locked` e lista de alertas da rede atual.
    """
    net_info = get_network_info()
    overview = get_soc_overview(net_info=net_info)
    return jsonify(overview)

@app.route("/api/soc/baseline/lock", methods=["POST"])
def api_soc_baseline_lock():
    """Marca todos os dispositivos ONLINE da sub-rede como `is_trusted = 1` e trava a baseline."""
    net_info = get_network_info()
    res = lock_current_network_baseline(net_info=net_info, lock_state=True)
    return jsonify(res)

@app.route("/api/soc/baseline/unlock", methods=["POST"])
def api_soc_baseline_unlock():
    """Destrava a baseline da sub-rede atual (`baseline_locked = 0`)."""
    net_info = get_network_info()
    res = lock_current_network_baseline(net_info=net_info, lock_state=False)
    return jsonify(res)

@app.route("/api/soc/alerts/<int:alert_id>/ack", methods=["POST"])
def api_soc_alert_ack(alert_id):
    """Marca um alerta SOC como reconhecido (`ACK`)."""
    conn = get_db_connection()
    ok = ack_soc_alert(conn, alert_id)
    conn.close()
    if not ok:
        return jsonify({"status": "NOT_FOUND", "message": f"Alerta #{alert_id} não encontrado."}), 404
    return jsonify({"status": "SUCCESS", "alert_id": alert_id, "new_status": "ACK"})

@app.route("/api/report/device/<ip>/markdown", methods=["GET"])
def api_download_device_report_md(ip):
    """Exporta o Relatório Individual do dispositivo `<ip>` em formato Markdown (.md)."""
    net_info = get_network_info()
    md_content = generate_device_markdown_report(ip, net_info=net_info)
    if not md_content:
        return jsonify({"status": "NOT_FOUND", "message": f"Dispositivo {ip} não encontrado."}), 404
    safe_ip = ip.replace(".", "_")
    filename = f"netwatch_device_{safe_ip}_{time.strftime('%Y%m%d_%H%M%S')}.md"
    return Response(
        md_content,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route("/api/devices/offline", methods=["DELETE"])
def api_clear_offline_devices():
    """Remove dispositivos OFFLINE e registros órfãos de outras sub-redes."""
    net_info = get_network_info()
    conn = get_db_connection()
    removed = clear_offline_devices(conn, net_info)
    conn.close()

    log_event("CLEANUP", "INFO", f"Histórico limpo: {removed} dispositivo(s) offline/de redes antigas removido(s).")
    return jsonify({
        "status": "SUCCESS",
        "removed": removed,
        "message": f"{removed} dispositivo(s) antigo(s)/offline removido(s)."
    })

@app.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    """
    Executa `get_network_info()` antes de disparar `quick_presence_scan` em background,
    retornando status claro se iniciou (`STARTED`) ou se já estava em execução (`ALREADY_RUNNING`).
    """
    net_info = get_network_info()
    if not net_info.get("is_connected"):
        return jsonify({
            "status": "WIFI_REQUIRED",
            "is_scanning": False,
            "message": net_info.get("status_reason", "Conecte o aparelho a uma rede Wi-Fi para iniciar o monitoramento")
        }), 400

    if is_scanning:
        return jsonify({
            "status": "ALREADY_RUNNING",
            "is_scanning": True,
            "network_cidr": net_info.get("network_cidr"),
            "message": "Varredura já está em andamento."
        }), 200

    t = threading.Thread(target=run_discovery_cycle, kwargs={"force_deep": False}, daemon=True)
    t.start()

    return jsonify({
        "status": "STARTED",
        "is_scanning": True,
        "network_cidr": net_info.get("network_cidr"),
        "message": f"Varredura rápida de presença iniciada em {net_info.get('network_cidr')}."
    })

@app.route("/api/services", methods=["GET", "POST", "DELETE"])
def api_services():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "GET":
        cursor.execute("SELECT * FROM monitored_services ORDER BY id ASC;")
        services = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return jsonify({"services": services})

    elif request.method == "POST":
        data = request.json or {}
        name = data.get("name", "").strip()
        host = data.get("host", "").strip()
        port = int(data.get("port", 80))
        stype = data.get("service_type", "HTTP").upper().strip()

        if not name or not host:
            conn.close()
            return jsonify({"status": "ERROR", "message": "Nome e Host são obrigatórios."}), 400

        status, latency, details = probe_service(stype, host, port)
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")

        cursor.execute("""
            INSERT INTO monitored_services (name, host, port, service_type, status, latency, last_check, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (name, host, port, stype, status, latency, now_iso, details))
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()

        log_event("SERVICE", "INFO", f"Novo serviço adicionado: '{name}' ({host}:{port} - {stype})")
        return jsonify({"status": "SUCCESS", "id": new_id, "initial_status": status, "latency": latency})

    elif request.method == "DELETE":
        s_id = request.args.get("id")
        if not s_id:
            conn.close()
            return jsonify({"status": "ERROR", "message": "ID não informado."}), 400

        cursor.execute("DELETE FROM monitored_services WHERE id = ?;", (s_id,))
        conn.commit()
        conn.close()
        log_event("SERVICE", "INFO", f"Serviço ID {s_id} removido do monitoramento.")
        return jsonify({"status": "SUCCESS", "message": f"Serviço {s_id} removido."})

@app.route("/api/services/verify", methods=["POST"])
def api_services_verify():
    """Força verificação imediata de todos os serviços monitorados."""
    res = verify_all_services()
    return jsonify({"status": "SUCCESS", "services": res})

@app.route("/api/events", methods=["GET"])
def api_events():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50;")
    events = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"events": events})

@app.route("/api/report/markdown", methods=["GET"])
def api_download_report_md():
    md_content = generate_markdown_report()
    filename = f"netwatch_report_{time.strftime('%Y%m%d_%H%M%S')}.md"
    return Response(
        md_content,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route("/api/report/json", methods=["GET"])
def api_download_report_json():
    json_content = generate_json_report()
    filename = f"netwatch_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        json_content,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

if __name__ == "__main__":
    init_db()
    net_init = get_network_info()
    if net_init.get("is_connected"):
        run_connectivity_check(net_init.get("gateway") or "127.0.0.1")
        verify_all_services()

    # Inicia os 2 workers assíncronos independentes (15s presença+SOC LAN / 30s conectividade+serviços+SOC WAN)
    t_presence = threading.Thread(target=presence_monitor_worker, daemon=True)
    t_presence.start()

    t_conn = threading.Thread(target=connectivity_and_services_worker, daemon=True)
    t_conn.start()

    bind_host = os.environ.get("NETWATCH_HOST", "127.0.0.1")
    bind_port = int(os.environ.get("NETWATCH_PORT", "5000"))

    print("==================================================================")
    print("  NetWatch E6 — Servidor Web & Motor SOC Automático (Android 9)")
    print(f"  Bind Local Seguro: http://{bind_host}:{bind_port}")
    print("==================================================================")
    app.run(host=bind_host, port=bind_port, debug=False, threaded=True)
