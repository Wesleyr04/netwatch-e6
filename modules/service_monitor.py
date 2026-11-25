import socket
import ssl
import time
import urllib.request
from datetime import datetime
from database import get_db_connection, log_event

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

def check_ssh_banner(host, port=22, timeout=2.5):
    """
    Conecta na porta 22 e lê o banner protocolar do servidor SSH
    (Ex: 'SSH-2.0-OpenSSH_8.2p1...').
    """
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # Lê banner enviado pelo servidor SSH
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        latency = (time.perf_counter() - t0) * 1000.0
        s.close()
        if "SSH" in banner:
            return "ONLINE", round(latency, 2), f"Banner: {banner}"
        return "ONLINE", round(latency, 2), f"Porta aberta (Banner não padrão: {banner[:30]})"
    except Exception as e:
        return "OFFLINE", 0.0, f"Falha de conexão: {str(e)}"

def check_dns_service(host, port=53, timeout=2.0):
    """
    Executa uma consulta real de registro tipo 'A' contra o servidor DNS alvo.
    Utiliza dnspython se instalado, com fallback socket.
    """
    t0 = time.perf_counter()
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [host]
            resolver.port = port
            resolver.timeout = timeout
            resolver.lifetime = timeout
            ans = resolver.resolve("google.com", "A")
            latency = (time.perf_counter() - t0) * 1000.0
            ips = [str(r) for r in ans]
            return "ONLINE", round(latency, 2), f"Resolvido 'google.com' -> {', '.join(ips[:2])}"
        except Exception as e:
            return "OFFLINE", 0.0, f"Falha na consulta DNS: {str(e)}"
    else:
        # Fallback TCP port check
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            latency = (time.perf_counter() - t0) * 1000.0
            s.close()
            return "ONLINE", round(latency, 2), "Porta DNS 53 acessível (TCP)"
        except Exception as e:
            return "OFFLINE", 0.0, f"Porta 53 inacessível: {str(e)}"

def check_http_service(host, port=80, timeout=3.0):
    """Envia requisição HTTP real e captura código de status e latência."""
    t0 = time.perf_counter()
    url = f"http://{host}:{port}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetWatch-E6/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            latency = (time.perf_counter() - t0) * 1000.0
            status = "ONLINE" if 200 <= code < 400 else "DEGRADADO"
            return status, round(latency, 2), f"Status HTTP {code}"
    except urllib.error.HTTPError as e:
        latency = (time.perf_counter() - t0) * 1000.0
        return "ONLINE", round(latency, 2), f"Status HTTP {e.code}"
    except Exception as e:
        return "OFFLINE", 0.0, f"Falha de requisição: {str(e)}"

def check_https_service(host, port=443, timeout=3.5):
    """
    Testa handshake TLS seguro e captura versão do protocolo TLS e status code.
    """
    t0 = time.perf_counter()
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Permite validar mesmo certificados autoassinados na LAN

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                cipher = ssock.cipher()
                latency = (time.perf_counter() - t0) * 1000.0
                cipher_name = cipher[0] if cipher else "N/A"
                return "ONLINE", round(latency, 2), f"TLS {tls_version} ({cipher_name})"
    except Exception as e:
        return "OFFLINE", 0.0, f"Falha TLS/HTTPS: {str(e)}"

def check_generic_tcp(host, port, timeout=2.0):
    """Testa abertura de socket TCP para portas genéricas."""
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ret = s.connect_ex((host, port))
        latency = (time.perf_counter() - t0) * 1000.0
        s.close()
        if ret == 0:
            return "ONLINE", round(latency, 2), f"Porta TCP {port} aberta"
        return "OFFLINE", 0.0, f"Porta TCP {port} fechada (código {ret})"
    except Exception as e:
        return "OFFLINE", 0.0, f"Erro de conexão: {str(e)}"

def probe_service(service_type, host, port):
    """Roteia a sondagem conforme o tipo de protocolo configurado."""
    st = service_type.upper()
    if st == "SSH" or port == 22:
        return check_ssh_banner(host, port)
    elif st == "DNS" or port == 53:
        return check_dns_service(host, port)
    elif st == "HTTPS" or port == 443:
        return check_https_service(host, port)
    elif st == "HTTP" or port == 80:
        return check_http_service(host, port)
    else:
        return check_generic_tcp(host, port)

def verify_all_services():
    """
    Itera por todos os serviços cadastrados na tabela `monitored_services`,
    atualiza status, latência e detalhes, e emite eventos de indisponibilidade.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, host, port, service_type, status FROM monitored_services;")
    services = cursor.fetchall()

    results = []
    now_iso = datetime.now().isoformat()

    for s in services:
        s_id = s["id"]
        s_name = s["name"]
        host = s["host"]
        port = s["port"]
        stype = s["service_type"]
        prev_status = s["status"]

        status, latency, details = probe_service(stype, host, port)

        cursor.execute("""
            UPDATE monitored_services
            SET status = ?, latency = ?, last_check = ?, details = ?
            WHERE id = ?;
        """, (status, latency, now_iso, details, s_id))

        if prev_status == "ONLINE" and status == "OFFLINE":
            log_event("SERVICE", "CRITICAL", f"Serviço '{s_name}' ({host}:{port}) ficou OFFLINE! {details}")
        elif prev_status == "OFFLINE" and status == "ONLINE":
            log_event("SERVICE", "INFO", f"Serviço '{s_name}' ({host}:{port}) restabelecido.")

        results.append({
            "id": s_id,
            "name": s_name,
            "host": host,
            "port": port,
            "service_type": stype,
            "status": status,
            "latency": latency,
            "details": details
        })

    conn.commit()
    conn.close()
    return results

if __name__ == "__main__":
    print("Testando monitoramento de serviços cadastrados...")
    res = verify_all_services()
    for item in res:
        print(f"[{item['status']}] {item['name']} ({item['host']}:{item['port']}) - Latência: {item['latency']}ms - {item['details']}")
