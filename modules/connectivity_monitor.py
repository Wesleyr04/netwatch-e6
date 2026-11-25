import socket
import time
import subprocess
import os
from datetime import datetime
from database import get_db_connection, log_event

def test_socket_connection(host, port, timeout=1.5):
    """Testa conectividade TCP com medição de latência em milissegundos."""
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        latency = (time.perf_counter() - t0) * 1000.0
        s.close()
        return True, round(latency, 2)
    except Exception:
        return False, None

def ping_target(host, timeout_sec=1):
    """Fallback via comando ping do sistema operacional."""
    ping_bin = "/system/bin/ping" if os.path.exists("/system/bin/ping") else "ping"
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_sec * 1000), host]
    else:
        cmd = [ping_bin, "-c", "1", "-W", str(timeout_sec), host]

    t0 = time.perf_counter()
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_sec + 0.5)
        dt = (time.perf_counter() - t0) * 1000.0
        if res.returncode == 0:
            return True, round(dt, 2)
    except Exception:
        pass
    return False, None

def test_gateway(gateway_ip):
    """Verifica se o Gateway local responde via TCP ou ping."""
    if not gateway_ip:
        return False, None
    # Testa portas comuns de roteador/gateway (80, 53, 443)
    for p in [80, 53, 443]:
        ok, lat = test_socket_connection(gateway_ip, p, timeout=0.8)
        if ok:
            return True, lat
    # Fallback ping
    return ping_target(gateway_ip, timeout_sec=1)

def test_external_wan(target_ip="1.1.1.1"):
    """Verifica acesso direto à Internet via IP externo (porta 53 ou ping)."""
    ok, lat = test_socket_connection(target_ip, 53, timeout=1.5)
    if ok:
        return True, lat
    return ping_target(target_ip, timeout_sec=1)

def test_dns_resolution(target_host="www.google.com"):
    """Verifica capacidade de resolução de nomes de domínio."""
    t0 = time.perf_counter()
    try:
        socket.getaddrinfo(target_host, None, socket.AF_INET, socket.SOCK_STREAM)
        dt = (time.perf_counter() - t0) * 1000.0
        return True, round(dt, 2)
    except Exception:
        return False, None

def classify_connectivity(gw_ok, wan_ok, dns_ok):
    """
    Classifica a causa raiz do estado da conexão com regras estritas:
    - OPERACIONAL: Gateway OK, WAN OK, DNS OK
    - FALHA_LOCAL_GATEWAY: Gateway inalcançável
    - FALHA_WAN_EXTERNA: Gateway OK, mas IP externo inalcançável
    - FALHA_RESOLUCAO_DNS: Gateway OK e WAN OK, mas resolução de nomes falhou
    """
    if not gw_ok:
        return "FALHA_LOCAL_GATEWAY"
    if not wan_ok:
        return "FALHA_WAN_EXTERNA"
    if not dns_ok:
        return "FALHA_RESOLUCAO_DNS"
    return "OPERACIONAL"

def run_connectivity_check(gateway_ip="192.168.1.1"):
    """Executa a bateria de testes de conectividade e persiste histórico no SQLite."""
    gw_ok, gw_lat = test_gateway(gateway_ip)
    wan_ok, wan_lat = test_external_wan("1.1.1.1")
    dns_ok, dns_lat = test_dns_resolution("www.google.com")

    classification = classify_connectivity(gw_ok, wan_ok, dns_ok)

    details_parts = []
    if not gw_ok:
        details_parts.append(f"Gateway {gateway_ip} inalcançável")
    if not wan_ok:
        details_parts.append("Acesso direto a 1.1.1.1 falhou")
    if not dns_ok:
        details_parts.append("Resolução de www.google.com falhou")
    if not details_parts:
        details_parts.append("Todos os testes responderam normalmente")

    details = "; ".join(details_parts)
    now_iso = datetime.now().isoformat()

    # Gravar no banco SQLite
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO connectivity_logs (timestamp, gateway_ip, gateway_latency, external_latency, dns_latency, classification, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (now_iso, gateway_ip, gw_lat, wan_lat, dns_lat, classification, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERRO DB] Falha ao persistir log de conectividade: {e}")

    # Emitir evento em caso de falha
    if classification != "OPERACIONAL":
        log_event("CONNECTIVITY", "WARNING", f"Problema detectado: {classification} ({details})")

    return {
        "timestamp": now_iso,
        "gateway_ip": gateway_ip,
        "gateway_ok": gw_ok,
        "gateway_latency": gw_lat,
        "wan_ok": wan_ok,
        "wan_latency": wan_lat,
        "dns_ok": dns_ok,
        "dns_latency": dns_lat,
        "classification": classification,
        "details": details
    }

if __name__ == "__main__":
    res = run_connectivity_check("127.0.0.1")
    print("=== Resultado da Análise de Conectividade ===")
    for k, v in res.items():
        print(f"{k}: {v}")
