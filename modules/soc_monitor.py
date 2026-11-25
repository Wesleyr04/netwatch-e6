import socket
import ssl
import urllib.request
import json
import time
import re
import subprocess
import ipaddress
from datetime import datetime
try:
    import dns.resolver
except ImportError:
    dns = None

from database import (
    get_db_connection,
    create_soc_alert_dedup,
    get_soc_alerts,
    get_open_soc_alert_counts,
    log_event
)
from modules.network_discovery import get_network_info
from modules.device_discovery import is_valid_mac, PORT_SERVICE_NAMES

# Estado em memória do sensor de Integridade DNS (com cooldown de 60s para DoH)
_DNS_SENSOR_STATE = {
    "status": "AGUARDANDO",
    "last_check_ts": 0.0,
    "last_check_iso": None,
    "details": "Aguardando primeira verificação automática DNS vs DoH"
}

# Estado em memória do sensor TLS
_TLS_SENSOR_STATE = {
    "last_check_ts": 0.0,
    "checked_count": 0
}

# Portas de Alto Risco (MITRE T1021) e recomendações de mitigação
RISKY_PORTS_MITIGATION = {
    21: (
        "FTP (Transferência em Texto Claro)",
        "Serviço FTP exposto na porta 21/TCP transmite credenciais sem criptografia. Mitigação: desative o FTP ou substitua por SFTP/SCP (SSH)."
    ),
    23: (
        "Telnet (Administração em Texto Claro)",
        "Serviço Telnet exposto na porta 23/TCP permite interceptação total de sessão na LAN. Mitigação: desative o Telnet imediatamente e utilize SSH."
    ),
    445: (
        "SMB / Compartilhamento Windows",
        "Porta 445/TCP (SMB) exposta na LAN aumenta superfície para movimentação lateral e ransomware. Mitigação: restrinja o SMB no firewall local apenas a IPs estritamente necessários."
    ),
    3389: (
        "RDP (Área de Trabalho Remota Windows)",
        "Porta 3389/TCP (RDP) aberta na rede local permite tentativas de força bruta e exploração remota. Mitigação: habilite NLA e restrinja o acesso por firewall."
    ),
    5555: (
        "Android ADB sobre TCP/Wi-Fi",
        "Daemon Android Debug Bridge (5555/TCP) aberto permite execução remota de comandos sem autenticação física. Mitigação: execute `adb usb` ou desative a depuração Wi-Fi."
    )
}

def parse_ports_set(ports_str):
    """Converte string '53,80,443' em conjunto de inteiros {53, 80, 443}."""
    res = set()
    if not ports_str:
        return res
    for part in str(ports_str).split(","):
        p = part.strip()
        if p.isdigit():
            res.add(int(p))
    return res

def read_active_arp_neighbors(interface="wlan0"):
    """
    Lê `ip neigh show dev <interface>` filtrando apenas entradas com MAC válido
    nos estados `REACHABLE`, `STALE` ou `DELAY`.
    Retorna lista de dicts `[{'ip': ip, 'mac': mac, 'state': state}]`.
    """
    entries = []
    valid_states = {"REACHABLE", "STALE", "DELAY", "PERMANENT"}

    for ip_bin in ["ip", "/data/data/com.termux/files/usr/bin/ip", "/system/bin/ip"]:
        try:
            cmd = [ip_bin, "neigh", "show"]
            if interface and interface != "desconectado":
                cmd.extend(["dev", interface])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=1.5)
            lines = (res.stdout or "").splitlines()
            if lines:
                for line in lines:
                    line_s = line.strip()
                    m_ip = re.match(r"^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", line_s)
                    m_mac = re.search(r"\blladdr\s+([0-9a-fA-F:]{17})\b", line_s)
                    if not m_ip or not m_mac:
                        continue
                    ip = m_ip.group(1)
                    mac = m_mac.group(1).upper()
                    tokens = line_s.split()
                    state = tokens[-1].upper() if tokens else ""
                    if is_valid_mac(mac) and mac != "00:00:00:00:00:00" and state in valid_states:
                        entries.append({"ip": ip, "mac": mac, "state": state})
                break
        except Exception:
            pass

    return entries

# ==============================================================================
# DETECTOR 1 — GUARDIÃO ANTI-MITM / ARP (MITRE T1557.002)
# ==============================================================================

def check_arp_integrity(net_info=None, neighbor_entries=None):
    """
    Detector 1 — Guardião Anti-MITM / ARP (`T1557.002`):
    - Regra A (Troca de MAC do Gateway): grava `gateway_mac` na primeira vez na
      `soc_network_baselines`. Se o MAC do Gateway mudar, abre alerta `CRITICAL` (`ARP_MITM`).
    - Regra B (MAC Duplicado na LAN): se dois IPs distintos compartilharem o mesmo MAC
      na tabela de vizinhos/dispositivos ativos da sub-rede, abre alerta `CRITICAL` (`ARP_MITM`).
    """
    if net_info is None:
        net_info = get_network_info()

    if not net_info.get("is_connected") or not net_info.get("network_cidr"):
        return {"status": "INATIVO", "alerts_triggered": 0}

    network_cidr = net_info["network_cidr"]
    gateway_ip = net_info.get("gateway") or ""
    interface = net_info.get("interface", "wlan0")

    if neighbor_entries is None:
        neighbor_entries = read_active_arp_neighbors(interface)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Complementa vizinhos com dispositivos atualmente ONLINE na sub-rede no SQLite
    ip_to_mac = {}
    cursor.execute(
        "SELECT ip, mac FROM devices WHERE network_cidr = ? AND status = 'ONLINE';",
        (network_cidr,)
    )
    for row in cursor.fetchall():
        r_ip = row["ip"]
        r_mac = (row["mac"] or "").strip().upper()
        if is_valid_mac(r_mac) and r_mac != "00:00:00:00:00:00" and r_mac != "02:00:00:00:00:00":
            ip_to_mac[r_ip] = r_mac

    # Sobrescreve/atualiza com a leitura ao vivo da tabela ARP/neigh
    try:
        net_obj = ipaddress.IPv4Network(network_cidr, strict=False)
    except Exception:
        net_obj = None

    for item in neighbor_entries:
        n_ip = item.get("ip", "")
        n_mac = (item.get("mac") or "").strip().upper()
        if not is_valid_mac(n_mac) or n_mac in ("00:00:00:00:00:00", "02:00:00:00:00:00"):
            continue
        if net_obj:
            try:
                if ipaddress.IPv4Address(n_ip) not in net_obj:
                    continue
            except Exception:
                continue
        ip_to_mac[n_ip] = n_mac

    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    alerts_triggered = 0

    # Regra A — Verificar integridade do MAC do Gateway na soc_network_baselines
    current_gw_mac = ip_to_mac.get(gateway_ip, "")
    cursor.execute("SELECT * FROM soc_network_baselines WHERE network_cidr = ?;", (network_cidr,))
    base_row = cursor.fetchone()

    if base_row is None:
        cursor.execute("""
            INSERT INTO soc_network_baselines (network_cidr, gateway_ip, gateway_mac, baseline_locked, updated_at)
            VALUES (?, ?, ?, 0, ?);
        """, (network_cidr, gateway_ip, current_gw_mac, now_iso))
    else:
        locked_gw_mac = (base_row["gateway_mac"] or "").strip().upper()
        if not is_valid_mac(locked_gw_mac) and is_valid_mac(current_gw_mac):
            cursor.execute("""
                UPDATE soc_network_baselines
                SET gateway_ip = ?, gateway_mac = ?, updated_at = ?
                WHERE network_cidr = ?;
            """, (gateway_ip, current_gw_mac, now_iso, network_cidr))
        elif is_valid_mac(locked_gw_mac) and is_valid_mac(current_gw_mac) and current_gw_mac != locked_gw_mac:
            title = f"Alteração do MAC do Gateway Detectada ({gateway_ip})"
            details = (
                f"Possível ataque ARP Spoofing / MITM: o Gateway {gateway_ip} tinha o MAC original "
                f"{locked_gw_mac} travado na baseline, mas agora responde com o MAC {current_gw_mac}."
            )
            create_soc_alert_dedup(
                network_cidr=network_cidr,
                severity="CRITICAL",
                category="ARP_MITM",
                mitre_id="T1557.002",
                title=title,
                details=details,
                target_ip=gateway_ip,
                target_mac=current_gw_mac,
                conn=conn
            )
            alerts_triggered += 1

    # Regra B — Detectar MAC duplicado entre IPs distintos na LAN
    mac_to_ips = {}
    for ip_addr, mac_addr in ip_to_mac.items():
        mac_to_ips.setdefault(mac_addr, set()).add(ip_addr)

    for mac_addr, ip_set in mac_to_ips.items():
        if len(ip_set) >= 2:
            sorted_ips = sorted(ip_set, key=lambda x: int(ipaddress.IPv4Address(x)))
            ips_joined = ", ".join(sorted_ips)
            title = f"Conflito ARP: MAC Duplicado na Rede ({mac_addr})"
            details = (
                f"O endereço físico {mac_addr} está sendo anunciado simultaneamente pelos IPs "
                f"[{ips_joined}] na sub-rede {network_cidr} (indicativo de ARP Spoofing / MITM)."
            )
            create_soc_alert_dedup(
                network_cidr=network_cidr,
                severity="CRITICAL",
                category="ARP_MITM",
                mitre_id="T1557.002",
                title=title,
                details=details,
                target_ip=ips_joined,
                target_mac=mac_addr,
                conn=conn
            )
            alerts_triggered += 1

    conn.commit()
    conn.close()
    return {
        "status": "ALERTA" if alerts_triggered > 0 else "ATIVO",
        "alerts_triggered": alerts_triggered,
        "gateway_mac": current_gw_mac
    }

# ==============================================================================
# DETECTOR 2 — INTEGRIDADE DNS / ANTI-HIJACKING (MITRE T1557)
# ==============================================================================

def resolve_domain_local_dns(domain, dns_servers=None, gateway_ip=None, timeout=3.0):
    """
    Resolve registros A de `domain` usando `dns.resolver.Resolver(configure=False)`
    (evitando erro de `/etc/resolv.conf` ausente no Android 9) e consultando
    prioritariamente o DNS do Gateway local (porta 53) e os servidores DNS ativos.
    """
    if dns is not None and hasattr(dns, "resolver"):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = timeout
        resolver.lifetime = timeout
        servers = []
        if gateway_ip and gateway_ip not in ("127.0.0.1", "0.0.0.0"):
            servers.append(gateway_ip)
        if dns_servers:
            for s in dns_servers:
                if s and s not in servers:
                    servers.append(s)
        if not servers:
            servers = ["1.1.1.1", "8.8.8.8"]
        resolver.nameservers = servers
        answers = resolver.resolve(domain, "A")
        return [str(rdata.address) for rdata in answers]
    infos = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
    return list({item[4][0] for item in infos if item and len(item) >= 5})

def resolve_domain_doh(domain, timeout=3.0):
    """Consulta DNS-over-HTTPS da Cloudflare (`application/dns-json`) para comparação."""
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
    req = urllib.request.Request(url, headers={
        "Accept": "application/dns-json",
        "User-Agent": "NetWatch-E6-SOC/2.0"
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    ips = []
    for ans in payload.get("Answer", []):
        if ans.get("type") == 1 and ans.get("data"):
            ips.append(str(ans["data"]))
    return ips

def is_bogon_or_private_ip(ip_str):
    """Retorna True se o IP for privado (RFC1918), loopback, link-local, 0.0.0.0 ou reservado."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_unspecified
            or addr.is_multicast
            or addr.is_reserved
        )
    except Exception:
        return True

def verify_tls_certificate_for_domain(ip_str, domain, port=443, timeout=3.0):
    """
    Valida se o IP devolvido pelo DNS local apresenta um certificado TLS autêntico
    e confiável para `server_hostname=domain` na porta 443.
    Retorna `(is_valid, error_reason)`.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip_str, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return False, "Certificado TLS vazio"
                return True, "Certificado TLS autêntico"
    except ssl.SSLCertVerificationError as e:
        return False, f"Certificado TLS inválido para {domain}: {e}"
    except ssl.SSLError as e:
        return False, f"Erro SSL/TLS para {domain}: {e}"
    except Exception as e:
        # Se a porta 443 estiver inacessível por queda de WAN, não classifica como certificado falso
        return True, f"Conexão 443 indisponível ({e})"

def check_dns_hijacking(net_info=None, force=False, test_domains=("google.com", "cloudflare.com")):
    """
    Detector 2 — Integridade DNS / Anti-Hijacking (`T1557`):
    Compara respostas do DNS local com DNS-over-HTTPS e valida autenticidade TLS sem
    falsos positivos de CDN. Dispara alerta `CRITICAL` (`DNS_HIJACK`) apenas se:
      a) O DNS local devolver IP privado, loopback, link-local ou 0.0.0.0 para domínio público; OU
      b) O IP devolvido pelo DNS local falhar na verificação de certificado TLS na porta 443.
    """
    global _DNS_SENSOR_STATE
    now_t = time.time()

    if not force and (now_t - _DNS_SENSOR_STATE["last_check_ts"] < 60.0) and _DNS_SENSOR_STATE["status"] != "AGUARDANDO":
        return _DNS_SENSOR_STATE

    if net_info is None:
        net_info = get_network_info()

    if not net_info.get("is_connected") or not net_info.get("network_cidr"):
        _DNS_SENSOR_STATE = {
            "status": "SEM_WAN",
            "last_check_ts": now_t,
            "last_check_iso": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "details": "Aparelho desconectado do Wi-Fi"
        }
        return _DNS_SENSOR_STATE

    network_cidr = net_info["network_cidr"]
    dns_servers = net_info.get("dns") or []
    gateway_ip = net_info.get("gateway") or ""
    conn = get_db_connection()

    hijack_detected = False
    any_resolved = False
    summary_notes = []

    for domain in test_domains:
        try:
            local_ips = resolve_domain_local_dns(
                domain,
                dns_servers=dns_servers,
                gateway_ip=gateway_ip,
                timeout=3.0
            )
        except Exception as e:
            summary_notes.append(f"{domain}: falha de resolução local ({e})")
            continue

        if not local_ips:
            continue

        any_resolved = True
        try:
            doh_ips = resolve_domain_doh(domain, timeout=3.0)
        except Exception:
            doh_ips = []

        first_ip = local_ips[0]

        # Condição (a): IP privado, loopback, link-local ou 0.0.0.0 para domínio público
        if any(is_bogon_or_private_ip(ip) for ip in local_ips):
            bad_ip = next(ip for ip in local_ips if is_bogon_or_private_ip(ip))
            hijack_detected = True
            title = f"DNS Hijacking Detectado para {domain} ({bad_ip})"
            details = (
                f"O servidor DNS local respondeu o domínio público '{domain}' com o endereço "
                f"privado/reservado {bad_ip} (DoH referência: {', '.join(doh_ips) or 'N/A'})."
            )
            create_soc_alert_dedup(
                network_cidr=network_cidr,
                severity="CRITICAL",
                category="DNS_HIJACK",
                mitre_id="T1557",
                title=title,
                details=details,
                target_ip=bad_ip,
                conn=conn
            )
            summary_notes.append(f"{domain} -> {bad_ip} (IP PRIVADO/FALSO)")
            continue

        # Condição (b): valida se o IP público apresenta certificado TLS válido para o domínio
        tls_ok, tls_msg = verify_tls_certificate_for_domain(first_ip, domain, port=443, timeout=3.0)
        if not tls_ok:
            hijack_detected = True
            title = f"Interceptação TLS/DNS Detectada em {domain} ({first_ip})"
            details = (
                f"O IP {first_ip} retornado pelo DNS local para '{domain}' apresentou certificado TLS "
                f"inválido na porta 443 ({tls_msg}). DoH referência: {', '.join(doh_ips) or 'N/A'}."
            )
            create_soc_alert_dedup(
                network_cidr=network_cidr,
                severity="CRITICAL",
                category="DNS_HIJACK",
                mitre_id="T1557",
                title=title,
                details=details,
                target_ip=first_ip,
                conn=conn
            )
            summary_notes.append(f"{domain} -> {first_ip} (FALHA TLS)")
        else:
            summary_notes.append(f"{domain} -> {first_ip} (TLS OK)")

    conn.commit()
    conn.close()

    if hijack_detected:
        dns_status = "SUSPEITO"
    elif any_resolved:
        dns_status = "INTEGRO"
    else:
        dns_status = "SEM_WAN"

    _DNS_SENSOR_STATE = {
        "status": dns_status,
        "last_check_ts": now_t,
        "last_check_iso": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "details": " | ".join(summary_notes) if summary_notes else "Sem resposta DNS externa"
    }
    return _DNS_SENSOR_STATE

# ==============================================================================
# DETECTOR 3 — AUDITORIA DE PORTAS CRÍTICAS E DRIFT (MITRE T1021 / T1046)
# ==============================================================================

def check_ports_and_drift(net_info=None):
    """
    Detector 3 — Auditoria de Portas Críticas e Drift:
    - Portas de Alto Risco (`T1021`): se qualquer host `ONLINE` da sub-rede atual expor
      21 (FTP), 23 (Telnet), 445 (SMB), 3389 (RDP) ou 5555 (ADB), abre alerta `HIGH` (`RISKY_PORT`).
    - Drift de Portas (`T1046`): se um host já conhecido abrir uma porta nova que não
      estava em `previous_ports`, abre alerta `MEDIUM` (`PORT_DRIFT`) indicando qual porta apareceu.
    """
    if net_info is None:
        net_info = get_network_info()

    if not net_info.get("is_connected") or not net_info.get("network_cidr"):
        return {"risky_alerts": 0, "drift_alerts": 0}

    network_cidr = net_info["network_cidr"]
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, ip, mac, hostname, open_ports, previous_ports, status
        FROM devices
        WHERE network_cidr = ? AND status = 'ONLINE';
    """, (network_cidr,))
    rows = cursor.fetchall()

    risky_alerts = 0
    drift_alerts = 0

    for row in rows:
        dev_id = row["id"]
        ip = row["ip"]
        mac = row["mac"] or "N/A"
        hostname = row["hostname"] or "Dispositivo na LAN"
        open_ports_str = row["open_ports"] or ""
        prev_ports_str = row["previous_ports"] if row["previous_ports"] is not None else ""

        curr_set = parse_ports_set(open_ports_str)
        prev_set = parse_ports_set(prev_ports_str)

        # 1. Verifica Portas de Alto Risco (21, 23, 445, 3389, 5555)
        for port in sorted(curr_set):
            if port in RISKY_PORTS_MITIGATION:
                srv_label, mitigation = RISKY_PORTS_MITIGATION[port]
                title = f"Porta de Alto Risco Exposta: {port}/TCP ({srv_label}) em {ip}"
                details = f"Host {ip} ({hostname}) [MAC: {mac}] expõe a porta crítica {port}/TCP. {mitigation}"
                create_soc_alert_dedup(
                    network_cidr=network_cidr,
                    severity="HIGH",
                    category="RISKY_PORT",
                    mitre_id="T1021",
                    title=title,
                    details=details,
                    target_ip=ip,
                    target_mac=mac,
                    conn=conn
                )
                risky_alerts += 1

        # 2. Verifica Drift de Portas (abertura de porta nova em host já conhecido)
        if prev_ports_str != "":
            new_ports = sorted(curr_set - prev_set)
            for np in new_ports:
                sname = PORT_SERVICE_NAMES.get(np, f"TCP/{np}")
                title = f"Drift de Porta: Nova Porta {np}/TCP ({sname}) Aberta em {ip}"
                details = (
                    f"O dispositivo {ip} ({hostname}) abriu uma nova porta de serviço {np}/TCP ({sname}) "
                    f"que não estava ativa anteriormente (portas anteriores: {prev_ports_str or 'nenhuma'})."
                )
                create_soc_alert_dedup(
                    network_cidr=network_cidr,
                    severity="MEDIUM",
                    category="PORT_DRIFT",
                    mitre_id="T1046",
                    title=title,
                    details=details,
                    target_ip=ip,
                    target_mac=mac,
                    conn=conn
                )
                drift_alerts += 1

        # Atualiza previous_ports para refletir o estado auditado atual
        if open_ports_str != prev_ports_str:
            cursor.execute("UPDATE devices SET previous_ports = ? WHERE id = ?;", (open_ports_str, dev_id))

    conn.commit()
    conn.close()
    return {"risky_alerts": risky_alerts, "drift_alerts": drift_alerts}

# ==============================================================================
# DETECTOR 4 — BASELINE DE DISPOSITIVOS AUTORIZADOS (MITRE T1200)
# ==============================================================================

def check_rogue_devices(net_info=None):
    """
    Detector 4 — Baseline de Dispositivos Autorizados (`T1200`):
    Se `baseline_locked == 1` para a `network_cidr` atual, qualquer host `ONLINE`
    com `is_trusted == 0` gera alerta `HIGH` (`ROGUE_DEVICE`) com IP, MAC e fabricante.
    """
    if net_info is None:
        net_info = get_network_info()

    if not net_info.get("is_connected") or not net_info.get("network_cidr"):
        return {"baseline_locked": False, "rogue_count": 0}

    network_cidr = net_info["network_cidr"]
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT baseline_locked FROM soc_network_baselines WHERE network_cidr = ?;",
        (network_cidr,)
    )
    base_row = cursor.fetchone()
    if not base_row or int(base_row["baseline_locked"] or 0) != 1:
        conn.close()
        return {"baseline_locked": False, "rogue_count": 0}

    cursor.execute("""
        SELECT ip, mac, hostname, vendor, device_type
        FROM devices
        WHERE network_cidr = ?
          AND status = 'ONLINE'
          AND COALESCE(is_trusted, 0) = 0;
    """, (network_cidr,))
    rogues = cursor.fetchall()

    for r in rogues:
        ip = r["ip"]
        mac = r["mac"] or "N/A"
        vendor = r["vendor"] or "Desconhecido"
        hostname = r["hostname"] or "Dispositivo na LAN"
        title = f"Dispositivo Não Autorizado na Rede: {ip}"
        details = (
            f"Novo host não autorizado conectado enquanto a Baseline está travada: "
            f"IP {ip}, MAC {mac}, Fabricante: {vendor}, Hostname: {hostname}."
        )
        create_soc_alert_dedup(
            network_cidr=network_cidr,
            severity="HIGH",
            category="ROGUE_DEVICE",
            mitre_id="T1200",
            title=title,
            details=details,
            target_ip=ip,
            target_mac=mac,
            conn=conn
        )

    conn.commit()
    conn.close()
    return {"baseline_locked": True, "rogue_count": len(rogues)}

# ==============================================================================
# BÔNUS AUTOMÁTICO — AUDITORIA TLS NOS SERVIÇOS MONITORADOS (MITRE T1557)
# ==============================================================================

def check_tls_certificates(net_info=None, force=False):
    """
    Para serviços HTTPS (443) cadastrados em `monitored_services`, verifica via `ssl`
    a data de expiração do certificado (`notAfter`); se expirado ou com menos de 15 dias
    restantes, abre alerta `MEDIUM` (`TLS_AUDIT`, `T1557`).
    """
    global _TLS_SENSOR_STATE
    now_t = time.time()
    if not force and (now_t - _TLS_SENSOR_STATE["last_check_ts"] < 60.0):
        return _TLS_SENSOR_STATE

    if net_info is None:
        net_info = get_network_info()

    network_cidr = net_info.get("network_cidr") or "127.0.0.0/24"
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT name, host, port, service_type
        FROM monitored_services
        WHERE UPPER(service_type) = 'HTTPS' OR port = 443;
    """)
    services = cursor.fetchall()
    checked = 0

    for srv in services:
        host = srv["host"]
        port = int(srv["port"] or 443)
        name = srv["name"]
        checked += 1
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after_str = cert.get("notAfter") if cert else None
                    if not_after_str:
                        exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_dt - datetime.utcnow()).days
                        if days_left < 15:
                            title = f"Certificado TLS Expirando em {host}:{port} ({days_left} dias)"
                            details = (
                                f"O certificado TLS do serviço '{name}' ({host}:{port}) expira em "
                                f"{days_left} dia(s) ({not_after_str})."
                            )
                            create_soc_alert_dedup(
                                network_cidr=network_cidr,
                                severity="MEDIUM",
                                category="TLS_AUDIT",
                                mitre_id="T1557",
                                title=title,
                                details=details,
                                target_ip=host,
                                conn=conn
                            )
        except ssl.SSLCertVerificationError as e:
            title = f"Certificado TLS Inválido em {host}:{port}"
            details = f"Falha na verificação do certificado TLS do serviço '{name}' ({host}:{port}): {e}"
            create_soc_alert_dedup(
                network_cidr=network_cidr,
                severity="MEDIUM",
                category="TLS_AUDIT",
                mitre_id="T1557",
                title=title,
                details=details,
                target_ip=host,
                conn=conn
            )
        except Exception:
            pass

    conn.commit()
    conn.close()
    _TLS_SENSOR_STATE = {"last_check_ts": now_t, "checked_count": checked}
    return _TLS_SENSOR_STATE

# ==============================================================================
# GERENCIAMENTO DE BASELINE E VISÃO GERAL SOC
# ==============================================================================

def lock_current_network_baseline(net_info=None, lock_state=True):
    """
    Quando `lock_state=True`: marca todos os dispositivos atualmente `ONLINE` da sub-rede
    ativa como `is_trusted = 1` e ativa `baseline_locked = 1` em `soc_network_baselines`.
    Quando `lock_state=False`: desativa `baseline_locked = 0` e reconhece alertas `ROGUE_DEVICE` abertos.
    """
    if net_info is None:
        net_info = get_network_info()

    network_cidr = net_info.get("network_cidr") or "127.0.0.0/24"
    gateway_ip = net_info.get("gateway") or ""
    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Descobre MAC atual do Gateway se presente em devices
    gw_mac = ""
    if gateway_ip:
        cursor.execute("SELECT mac FROM devices WHERE ip = ?;", (gateway_ip,))
        gw_row = cursor.fetchone()
        if gw_row and is_valid_mac(gw_row["mac"]):
            gw_mac = gw_row["mac"].upper()

    trusted_count = 0
    if lock_state:
        cursor.execute("""
            UPDATE devices
            SET is_trusted = 1
            WHERE network_cidr = ? AND status = 'ONLINE';
        """, (network_cidr,))
        trusted_count = cursor.rowcount

        # Reconhece alertas ROGUE_DEVICE anteriores dos hosts que acabaram de ser autorizados
        cursor.execute("""
            UPDATE soc_alerts
            SET status = 'ACK'
            WHERE network_cidr = ? AND category = 'ROGUE_DEVICE' AND status = 'OPEN';
        """, (network_cidr,))

    cursor.execute("""
        INSERT INTO soc_network_baselines (network_cidr, gateway_ip, gateway_mac, baseline_locked, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(network_cidr) DO UPDATE SET
            gateway_ip = CASE WHEN excluded.gateway_ip != '' THEN excluded.gateway_ip ELSE soc_network_baselines.gateway_ip END,
            gateway_mac = CASE WHEN excluded.gateway_mac != '' THEN excluded.gateway_mac ELSE soc_network_baselines.gateway_mac END,
            baseline_locked = excluded.baseline_locked,
            updated_at = excluded.updated_at;
    """, (network_cidr, gateway_ip, gw_mac, 1 if lock_state else 0, now_iso))

    if not lock_state:
        cursor.execute("""
            UPDATE soc_alerts
            SET status = 'ACK'
            WHERE network_cidr = ? AND category = 'ROGUE_DEVICE' AND status = 'OPEN';
        """, (network_cidr,))

    conn.commit()
    conn.close()

    action_msg = (
        f"Baseline da rede {network_cidr} TRAVADA ({trusted_count} dispositivos autorizados)."
        if lock_state
        else f"Baseline da rede {network_cidr} DESTRAVADA."
    )
    log_event("SOC_BASELINE", "INFO", action_msg)
    return {
        "status": "SUCCESS",
        "network_cidr": network_cidr,
        "baseline_locked": bool(lock_state),
        "trusted_devices": trusted_count,
        "message": action_msg
    }

def set_device_trust(ip, is_trusted=None, custom_name=None, net_info=None):
    """
    Alterna ou define `is_trusted` (0 ou 1) e opcionalmente `custom_name` para um dispositivo.
    Se o dispositivo passar a `is_trusted = 1`, reconhece automaticamente alertas `ROGUE_DEVICE` desse IP.
    """
    if net_info is None:
        net_info = get_network_info()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, ip, hostname, is_trusted, custom_name, network_cidr FROM devices WHERE ip = ?;", (ip,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    curr_trust = int(row["is_trusted"] or 0)
    new_trust = (0 if curr_trust == 1 else 1) if is_trusted is None else (1 if bool(is_trusted) else 0)
    new_name = row["custom_name"] or ""
    if custom_name is not None:
        new_name = str(custom_name).strip()[:45]

    cursor.execute("""
        UPDATE devices
        SET is_trusted = ?, custom_name = ?
        WHERE ip = ?;
    """, (new_trust, new_name, ip))

    if new_trust == 1:
        cursor.execute("""
            UPDATE soc_alerts
            SET status = 'ACK'
            WHERE target_ip = ? AND category = 'ROGUE_DEVICE' AND status = 'OPEN';
        """, (ip,))
    else:
        # Se a baseline da rede estiver travada e o usuário removeu a confiança, reavalia rogue devices
        conn.commit()
        conn.close()
        check_rogue_devices(net_info=net_info)
        return {
            "ip": ip,
            "is_trusted": new_trust,
            "custom_name": new_name
        }

    conn.commit()
    conn.close()
    return {
        "ip": ip,
        "is_trusted": new_trust,
        "custom_name": new_name
    }

def run_fast_soc_cycle(net_info=None):
    """Executa os 3 sensores rápidos de LAN logo após `quick_presence_scan()` (15s)."""
    if net_info is None:
        net_info = get_network_info()
    if not net_info.get("is_connected"):
        return
    check_arp_integrity(net_info=net_info)
    check_ports_and_drift(net_info=net_info)
    check_rogue_devices(net_info=net_info)

def run_wan_soc_cycle(net_info=None):
    """Executa os sensores de integridade DNS (DoH + TLS) e certificados TLS (30s/60s)."""
    if net_info is None:
        net_info = get_network_info()
    if not net_info.get("is_connected"):
        return
    check_dns_hijacking(net_info=net_info, force=False)
    check_tls_certificates(net_info=net_info, force=False)

def get_soc_overview(net_info=None):
    """
    Consolida todos os dados de postura SOC (`SEGURO`, `ATENCAO`, `CRITICO`),
    contagem de alertas por severidade, status dos 4 sensores automáticos,
    `gateway_mac_locked`, `baseline_locked` e lista de alertas da sub-rede atual.
    """
    if net_info is None:
        net_info = get_network_info()

    network_cidr = net_info.get("network_cidr") or "127.0.0.0/24"
    gateway_ip = net_info.get("gateway") or ""

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM soc_network_baselines WHERE network_cidr = ?;", (network_cidr,))
    base_row = cursor.fetchone()

    gateway_mac_locked = ""
    baseline_locked = False
    if base_row:
        gateway_mac_locked = base_row["gateway_mac"] or ""
        baseline_locked = bool(int(base_row["baseline_locked"] or 0) == 1)

    if not gateway_mac_locked and gateway_ip:
        cursor.execute("SELECT mac FROM devices WHERE ip = ?;", (gateway_ip,))
        gw_dev = cursor.fetchone()
        if gw_dev and is_valid_mac(gw_dev["mac"]):
            gateway_mac_locked = gw_dev["mac"].upper()

    cursor.execute("""
        SELECT
            SUM(CASE WHEN COALESCE(is_trusted, 0) = 1 THEN 1 ELSE 0 END) as trusted_cnt,
            SUM(CASE WHEN status = 'ONLINE' AND COALESCE(is_trusted, 0) = 0 THEN 1 ELSE 0 END) as untrusted_online_cnt
        FROM devices
        WHERE network_cidr = ?;
    """, (network_cidr,))
    trust_row = cursor.fetchone()
    trusted_cnt = int(trust_row["trusted_cnt"] or 0) if trust_row else 0
    untrusted_online_cnt = int(trust_row["untrusted_online_cnt"] or 0) if trust_row else 0

    counts = get_open_soc_alert_counts(conn, network_cidr=network_cidr)
    alerts = get_soc_alerts(conn, network_cidr=network_cidr, limit=80)
    conn.close()

    if counts["CRITICAL"] > 0:
        posture = "CRITICO"
    elif counts["HIGH"] > 0 or counts["MEDIUM"] > 0:
        posture = "ATENCAO"
    else:
        posture = "SEGURO"

    open_categories = {a["category"] for a in alerts if a.get("status") == "OPEN"}

    dns_state = _DNS_SENSOR_STATE.get("status", "INTEGRO")
    if "DNS_HIJACK" in open_categories:
        dns_state = "SUSPEITO"
    elif dns_state == "AGUARDANDO" and net_info.get("is_connected"):
        dns_state = "INTEGRO"

    sensors = [
        {
            "id": "arp_guard",
            "name": "ARP Guard (Anti-MITM)",
            "mitre": "T1557.002",
            "status": "ALERTA" if "ARP_MITM" in open_categories else "ATIVO",
            "detail": f"GW MAC: {gateway_mac_locked or 'Aprendendo...'}"
        },
        {
            "id": "dns_integrity",
            "name": "DNS Integrity (DoH + TLS)",
            "mitre": "T1557",
            "status": dns_state,
            "detail": _DNS_SENSOR_STATE.get("details", "Validação contínua google.com / cloudflare.com")
        },
        {
            "id": "ports_drift",
            "name": "Portas & Drift",
            "mitre": "T1021 / T1046",
            "status": "ALERTA" if ("RISKY_PORT" in open_categories or "PORT_DRIFT" in open_categories) else "ATIVO",
            "detail": "Monitorando 16 portas TCP + desvios de baseline"
        },
        {
            "id": "baseline_lock",
            "name": "Baseline Lock",
            "mitre": "T1200",
            "status": "ALERTA" if "ROGUE_DEVICE" in open_categories else ("TRAVADA" if baseline_locked else "DESTRAVADA"),
            "detail": f"{trusted_cnt} autorizados • {untrusted_online_cnt} não verificados online"
        }
    ]

    return {
        "posture": posture,
        "network_cidr": network_cidr,
        "gateway_ip": gateway_ip,
        "gateway_mac_locked": gateway_mac_locked or "N/A",
        "baseline_locked": baseline_locked,
        "trusted_devices_count": trusted_cnt,
        "untrusted_online_count": untrusted_online_cnt,
        "dns_integrity_status": dns_state,
        "counts": counts,
        "sensors": sensors,
        "alerts": alerts
    }
