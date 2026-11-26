import socket
import subprocess
import time
import os
import re
import json
import errno
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from database import get_db_connection, log_event, record_device_latency
from modules.network_discovery import get_network_info, get_interface_mac

# Fase A: portas de sondagem rápida de presença (TCP SYN -> Open ou RST)
PHASE_A_PRESENCE_PORTS = (80, 443, 62078, 445)

# Fase B: 16 portas de auditoria de serviços apenas nos hosts confirmados ONLINE (inclui 21, 23, 3389)
COMMON_PROBE_PORTS = (21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 5000, 5555, 8008, 8022, 8080, 9100)

# Mapeamento de portas para nomes legíveis de serviço
PORT_SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    135: "RPC/Windows",
    139: "NetBIOS/SMB",
    443: "HTTPS",
    445: "SMB/Windows",
    3389: "RDP/Windows",
    5000: "HTTP/NetWatch",
    5555: "Android ADB",
    8008: "Chromecast/Media",
    8022: "Termux SSH",
    8080: "HTTP-Alt",
    9100: "Impressora RAW"
}

# Códigos de erro que indicam recepção de pacote TCP RST (prova ativa de host ONLINE)
ECONNREFUSED_CODES = {errno.ECONNREFUSED, 111, 10061}

LOCAL_HOST_LABEL = "Moto E6 Play (Host Local)"
GATEWAY_LABEL = "Gateway / Roteador"
PRIVATE_MAC_LABEL = "Dispositivo Móvel (MAC Privado)"
GENERIC_LAN_LABEL = "Dispositivo na LAN"

# Janela de destaque visual (segundos) para entradas/saídas recentes
RECENT_CHANGE_WINDOW_SECONDS = 180

# Histerese anti-flapping: número de ciclos consecutivos sem resposta (2 x 10s = 20s) para marcar OFFLINE
HYSTERESIS_MAX_MISSED_SCANS = 2

# Estados ativos da tabela de vizinhos (`ip neigh`) que comprovam presença recente em camada 2
ACTIVE_NEIGHBOR_STATES = {"REACHABLE", "DELAY", "PROBE"}

# Intervalo mínimo (segundos) para reexecutar deep_fingerprint_host em um mesmo IP já ONLINE
DEEP_FINGERPRINT_INTERVAL_SECONDS = 180
_LAST_DEEP_FINGERPRINT = {}

# Tabela OUI Offline (~90 prefixos MAC 3-octetos mais comuns no Brasil)
OUI_VENDOR_MAP = {
    # Motorola
    "F8:1F:32": "Motorola Mobility",
    "14:AB:C5": "Motorola Mobility",
    "E8:91:20": "Motorola Mobility",
    "CC:61:E5": "Motorola Mobility",
    "80:58:F8": "Motorola Mobility",
    "40:78:6A": "Motorola Mobility",
    "90:68:C3": "Motorola Mobility",
    "F8:CF:C5": "Motorola Mobility",
    # Huawei / FiberHome / ZTE / Nokia
    "14:09:B4": "ZTE Corporation",
    "98:B3:EF": "Huawei Technologies",
    "48:46:FB": "Huawei Technologies",
    "84:A8:E4": "Huawei Technologies",
    "D4:6E:0E": "Huawei Technologies",
    "74:A5:28": "Huawei Technologies",
    "E0:19:54": "ZTE Corporation",
    "F4:28:53": "ZTE Corporation",
    "34:6B:46": "FiberHome Telecom",
    "BC:9C:31": "Huawei Technologies",
    "A0:F4:79": "Nokia / Alcatel",
    "68:9E:29": "Nokia / Alcatel",
    # Apple
    "00:1C:B3": "Apple Inc.",
    "28:CF:E9": "Apple Inc.",
    "3C:15:C2": "Apple Inc.",
    "40:A6:D9": "Apple Inc.",
    "58:55:CA": "Apple Inc.",
    "60:F8:1D": "Apple Inc.",
    "70:56:81": "Apple Inc.",
    "88:66:5A": "Apple Inc.",
    "A4:83:E7": "Apple Inc.",
    "BC:52:B7": "Apple Inc.",
    "D0:03:4B": "Apple Inc.",
    "F0:18:98": "Apple Inc.",
    # Samsung
    "00:16:32": "Samsung Electronics",
    "08:D4:2B": "Samsung Electronics",
    "10:D5:42": "Samsung Electronics",
    "24:4B:03": "Samsung Electronics",
    "38:01:97": "Samsung Electronics",
    "50:B7:C3": "Samsung Electronics",
    "64:B3:10": "Samsung Electronics",
    "78:47:1D": "Samsung Electronics",
    "8C:77:12": "Samsung Electronics",
    "A8:7C:01": "Samsung Electronics",
    "C4:73:1E": "Samsung Electronics",
    "E4:7C:F9": "Samsung Electronics",
    # Xiaomi
    "00:9E:C8": "Xiaomi Communications",
    "14:F6:5A": "Xiaomi Communications",
    "28:6C:07": "Xiaomi Communications",
    "34:CE:00": "Xiaomi Communications",
    "50:64:2B": "Xiaomi Communications",
    "64:09:80": "Xiaomi Communications",
    "78:11:DC": "Xiaomi Communications",
    "8C:BE:BE": "Xiaomi Communications",
    "AC:C1:EE": "Xiaomi Communications",
    "F8:A4:5F": "Xiaomi Communications",
    # TP-Link / Intelbras / D-Link / Asus
    "00:31:92": "TP-Link Systems",
    "14:CC:20": "TP-Link Systems",
    "18:D6:C7": "TP-Link Systems",
    "30:B5:C2": "TP-Link Systems",
    "50:C7:BF": "TP-Link Systems",
    "60:E3:27": "TP-Link Systems",
    "78:8C:B5": "TP-Link Systems",
    "84:16:F9": "TP-Link Systems",
    "98:DA:C4": "TP-Link Systems",
    "B0:95:75": "TP-Link Systems",
    "C0:25:E9": "TP-Link Systems",
    "D8:0D:17": "TP-Link Systems",
    "00:1A:3F": "Intelbras",
    "38:21:87": "Intelbras",
    "5C:F9:6A": "D-Link International",
    "78:32:1B": "D-Link International",
    "04:D4:C4": "ASUSTek Computer",
    "2C:FD:A1": "ASUSTek Computer",
    # Espressif (IoT ESP8266 / ESP32)
    "18:FE:34": "Espressif IoT",
    "24:0A:C4": "Espressif IoT",
    "24:6F:28": "Espressif IoT",
    "30:AE:A4": "Espressif IoT",
    "3C:71:BF": "Espressif IoT",
    "5C:CF:7F": "Espressif IoT",
    "84:CC:A8": "Espressif IoT",
    "84:F3:EB": "Espressif IoT",
    "A4:CF:12": "Espressif IoT",
    "BC:DD:C2": "Espressif IoT",
    "CC:50:E3": "Espressif IoT",
    "EC:FA:BC": "Espressif IoT",
    # Dell / Lenovo / HP / Intel / Realtek / Positivo
    "00:14:22": "Dell Inc.",
    "18:03:73": "Dell Inc.",
    "24:B6:FD": "Dell Inc.",
    "F8:B1:56": "Dell Inc.",
    "00:21:CC": "Lenovo",
    "54:EE:75": "Lenovo",
    "98:FA:9B": "Lenovo",
    "00:1B:78": "Hewlett Packard",
    "3C:D9:2B": "Hewlett Packard",
    "A0:D3:C1": "Hewlett Packard",
    "00:1B:21": "Intel Corporate",
    "34:13:E8": "Intel Corporate",
    "7C:B2:7D": "Intel Corporate",
    "8C:8D:28": "Intel Corporate",
    "00:E0:4C": "Realtek Semiconductor",
    "52:54:00": "Positivo / QEMU",
    # Google / Amazon / LG / Sony
    "3C:5A:B4": "Google Inc.",
    "54:60:09": "Google Inc.",
    "F4:F5:D8": "Google Inc.",
    "44:65:0D": "Amazon Technologies",
    "68:37:E9": "Amazon Technologies",
    "F0:27:2D": "Amazon Technologies",
    "00:1E:75": "LG Electronics",
    "38:8C:50": "LG Electronics",
    "A8:23:FE": "LG Electronics",
    "00:13:A9": "Sony Corporation",
    "58:48:22": "Sony Corporation"
}

def is_valid_mac(mac):
    """Verifica se a string representa um endereço MAC hexadecimal válido."""
    if not mac or not isinstance(mac, str):
        return False
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac.strip()))

def is_locally_administered_mac(mac):
    """
    Verifica se o MAC é localmente administrado / randomizado (MAC Privado),
    identificado pelo segundo dígito hexadecimal em {'2', '6', 'A', 'E'}.
    """
    if not is_valid_mac(mac):
        return False
    second_char = mac.strip()[1].upper()
    return second_char in {"2", "6", "A", "E"}

BANNER_VENDOR_KEYWORDS = (
    ("ZTE", "ZTE Corporation"),
    ("HUAWEI", "Huawei Technologies"),
    ("TP-LINK", "TP-Link Systems"),
    ("INTELBRAS", "Intelbras"),
    ("MIKROTIK", "MikroTik"),
    ("UBIQUITI", "Ubiquiti Inc."),
    ("D-LINK", "D-Link International"),
    ("FIBERHOME", "FiberHome Telecom"),
    ("NOKIA", "Nokia / Alcatel"),
    ("ALCATEL", "Nokia / Alcatel"),
    ("CISCO", "Cisco Systems"),
    ("ASUSTEK", "ASUSTek Computer"),
    ("ASUS", "ASUSTek Computer"),
)

def extract_vendor_from_banners(service_details):
    """
    Inspeciona os banners HTTP/SSH capturados em `service_details` (str JSON ou list)
    e retorna o fabricante caso identificado explicitamente no banner.
    """
    if not service_details:
        return None
    text = service_details if isinstance(service_details, str) else json.dumps(service_details, ensure_ascii=False)
    text_up = text.upper()
    for kw, vendor_name in BANNER_VENDOR_KEYWORDS:
        if re.search(rf"\b{re.escape(kw)}\b", text_up):
            return vendor_name
    return None

def resolve_vendor_oui(mac, is_local_host=False, service_details=None):
    """
    Identifica o fabricante priorizando:
    1. Fabricante explícito detectado no banner HTTP/serviço quando presente;
    2. Os 3 primeiros octetos do MAC na tabela OUI Offline (`OUI_VENDOR_MAP`);
    3. Se o MAC for randomizado (`mac[1]` em {'2','6','A','E'}), retorna "MAC Privado (Android/iOS)".
    """
    banner_vendor = extract_vendor_from_banners(service_details)
    if banner_vendor:
        return banner_vendor

    if is_local_host and (not is_valid_mac(mac) or mac == "02:00:00:00:00:00"):
        return "Motorola Mobility"

    if not is_valid_mac(mac):
        return "Desconhecido"

    mac_norm = mac.strip().upper()
    prefix = mac_norm[:8]
    if prefix in OUI_VENDOR_MAP:
        return OUI_VENDOR_MAP[prefix]

    if is_locally_administered_mac(mac_norm):
        return "MAC Privado (Android/iOS)"

    return "Dispositivo Padrão IEEE"

def infer_device_type(ip, mac="N/A", vendor="Desconhecido", open_ports_str="", my_ip=None, gateway_ip=None):
    """
    Infere o tipo de dispositivo com base em gateway, host local, portas abertas e vendor OUI.
    """
    if my_ip and ip == my_ip:
        return "Smartphone Android (Host Local)"
    if gateway_ip and ip == gateway_ip:
        return "Roteador / Gateway"

    ports = set()
    if open_ports_str:
        for p in str(open_ports_str).split(","):
            p_s = p.strip()
            if p_s.isdigit():
                ports.add(int(p_s))

    if 9100 in ports:
        return "Impressora de Rede"
    if 8008 in ports:
        return "Smart TV / Chromecast"
    if {135, 139, 445, 3389} & ports:
        return "PC / Servidor Windows"
    if 62078 in ports:
        return "iPhone / iPad (iOS)"
    if 5555 in ports:
        return "Smartphone Android (ADB)"
    if {22, 8022} & ports:
        return "Servidor Linux / SSH"

    v_up = (vendor or "").upper()
    if "MAC PRIVADO" in v_up or any(k in v_up for k in ("APPLE", "SAMSUNG", "MOTOROLA", "XIAOMI")):
        return "Smartphone / Mobile"
    if "ESPRESSIF" in v_up:
        return "Dispositivo IoT / Smart Home"
    if any(k in v_up for k in ("TP-LINK", "INTELBRAS", "HUAWEI", "ZTE", "D-LINK", "FIBERHOME", "NOKIA")):
        return "Roteador / Equipamento CPE"
    if any(k in v_up for k in ("DELL", "LENOVO", "HEWLETT", "INTEL", "REALTEK", "ASUS", "POSITIVO")):
        return "PC / Workstation"
    if any(k in v_up for k in ("LG", "SONY", "GOOGLE", "AMAZON")):
        return "Smart TV / Mídia"

    return "Dispositivo na LAN"

def parse_iso_datetime(iso_str):
    """Converte string ISO (%Y-%m-%dT%H:%M:%S) em objeto datetime."""
    if not iso_str or not isinstance(iso_str, str):
        return None
    clean = iso_str.strip().split(".")[0]
    try:
        return datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None

def ip_to_int(ip_str):
    """Converte um IPv4 em inteiro para ordenação estritamente numérica."""
    try:
        return int(ipaddress.IPv4Address(ip_str))
    except Exception:
        return 0xFFFFFFFF

def enrich_device_runtime_fields(d, now_dt=None):
    """
    Calcula em tempo real para cada registro de dispositivo:
    - `recently_changed`: True se `last_state_change` ocorreu nos últimos 180 segundos
    - `seconds_since_change`: segundos decorridos desde `last_state_change`
    - `session_duration_seconds`: duração da sessão online atual desde `connected_since`
    - `service_details_list`: lista JSON decodificada de `service_details`
    """
    if now_dt is None:
        now_dt = datetime.now()

    change_dt = parse_iso_datetime(d.get("last_state_change"))
    seconds_since_change = None
    recently_changed = False
    if change_dt:
        diff = int((now_dt - change_dt).total_seconds())
        if diff >= 0:
            seconds_since_change = diff
            if diff <= RECENT_CHANGE_WINDOW_SECONDS and d.get("last_event_type") in ("ENTERED", "RETURNED", "LEFT"):
                recently_changed = True

    session_duration_seconds = 0
    if d.get("status") == "ONLINE":
        conn_dt = parse_iso_datetime(d.get("connected_since")) or parse_iso_datetime(d.get("last_seen"))
        if conn_dt:
            session_duration_seconds = max(0, int((now_dt - conn_dt).total_seconds()))

    base_total = int(d.get("total_online_seconds") or 0)
    if d.get("status") == "ONLINE" and session_duration_seconds > base_total:
        effective_total = session_duration_seconds
    else:
        effective_total = base_total

    raw_srv = d.get("service_details")
    if isinstance(raw_srv, str):
        try:
            srv_list = json.loads(raw_srv) if raw_srv.strip() else []
        except Exception:
            srv_list = []
    elif isinstance(raw_srv, list):
        srv_list = raw_srv
    else:
        srv_list = []

    d["recently_changed"] = recently_changed
    d["seconds_since_change"] = seconds_since_change
    d["session_duration_seconds"] = session_duration_seconds
    d["total_online_seconds"] = effective_total
    d["service_details_list"] = srv_list
    d["is_trusted"] = int(d.get("is_trusted") or 0)
    d["custom_name"] = d.get("custom_name") or ""
    d["missed_scans"] = int(d.get("missed_scans") or 0)
    return d

def calculate_device_counts(devices, my_ip=None, gateway_ip=None):
    """
    Calcula métricas separadas de contagem de dispositivos para evitar inflar o contador
    da interface com registros OFFLINE do histórico ou infraestrutura (Gateway / Host Local):
      - online_count: total de dispositivos com status == 'ONLINE'
      - offline_count: total de dispositivos com status != 'ONLINE'
      - total_count: total geral no banco para a sub-rede
      - online_clients_count: clientes reais ONLINE (excluindo Host Local e Gateway)
      - online_infra_count: dispositivos de infraestrutura ONLINE (Host Local e Gateway)
    """
    online_count = 0
    offline_count = 0
    online_clients_count = 0
    online_infra_count = 0

    for d in (devices or []):
        ip = d.get("ip", "")
        is_online = (d.get("status") == "ONLINE")
        is_infra = bool((my_ip and ip == my_ip) or (gateway_ip and ip == gateway_ip))
        if is_online:
            online_count += 1
            if is_infra:
                online_infra_count += 1
            else:
                online_clients_count += 1
        else:
            offline_count += 1

    return {
        "online_count": online_count,
        "offline_count": offline_count,
        "total_count": len(devices or []),
        "online_clients_count": online_clients_count,
        "online_infra_count": online_infra_count
    }

def sort_devices(devices, my_ip=None, gateway_ip=None):
    """
    Ordena os dispositivos priorizando:
    1. `recently_changed` mais recente primeiro
    2. `ONLINE` antes de `OFFLINE`
    3. Host Local (0) e Gateway (1) no topo (2 para demais)
    4. IP numérico crescente
    """
    now_dt = datetime.now()
    for d in devices:
        if "recently_changed" not in d:
            enrich_device_runtime_fields(d, now_dt)

    def sort_key(d):
        ip = d.get("ip", "")
        is_recent = 0 if d.get("recently_changed") else 1
        recency_age = d.get("seconds_since_change") if d.get("recently_changed") and d.get("seconds_since_change") is not None else 999999
        status_online = 0 if d.get("status") == "ONLINE" else 1
        if my_ip and ip == my_ip and status_online == 0:
            role_rank = 0
        elif gateway_ip and ip == gateway_ip:
            role_rank = 1
        else:
            role_rank = 2
        return (is_recent, recency_age, status_online, role_rank, ip_to_int(ip))

    return sorted(devices, key=sort_key)

def query_filtered_devices(conn, net_info, scope="current"):
    """
    Consulta dispositivos filtrando por padrão apenas os pertencentes à sub-rede
    ativa atual (`net_info["network_cidr"]`), ou todos se `scope == "all"`.
    Enriquece com `recently_changed` e ordena conforme especificação.
    """
    cursor = conn.cursor()
    scope_norm = (scope or "current").strip().lower()

    if scope_norm == "all":
        cursor.execute("SELECT * FROM devices;")
        rows = [dict(r) for r in cursor.fetchall()]
    else:
        if not net_info.get("is_connected") or not net_info.get("network_cidr"):
            rows = []
        else:
            active_cidr = net_info["network_cidr"]
            cursor.execute("SELECT * FROM devices WHERE network_cidr = ?;", (active_cidr,))
            rows = [dict(r) for r in cursor.fetchall()]

    now_dt = datetime.now()
    for r in rows:
        enrich_device_runtime_fields(r, now_dt)

    my_ip = net_info.get("ip") if net_info.get("is_connected") else None
    gw_ip = net_info.get("gateway") if net_info.get("is_connected") else None
    return sort_devices(rows, my_ip=my_ip, gateway_ip=gw_ip)

def clear_offline_devices(conn, net_info):
    """Remove dispositivos OFFLINE e registros órfãos de outras sub-redes."""
    active_cidr = net_info.get("network_cidr", "")
    cursor = conn.cursor()

    if net_info.get("is_connected") and active_cidr:
        cursor.execute(
            "DELETE FROM devices WHERE status != 'ONLINE' OR network_cidr != ?;",
            (active_cidr,)
        )
    else:
        cursor.execute("DELETE FROM devices WHERE status != 'ONLINE';")

    removed = cursor.rowcount
    conn.commit()
    return removed

def parse_ip_neigh_output(stdout_text):
    """
    Faz o parsing da saída de `ip neigh show`:
    Retorna:
      - mac_table: dict {ip: mac} para todos os vizinhos com endereço MAC válido
      - active_ips: set de IPs cujo estado em `ip neigh` é `REACHABLE`, `DELAY` ou `PROBE`
      - stale_ips: set de IPs cujo estado é `STALE` e possuem MAC válido (candidatos a re-sondagem)
      - state_map: dict {ip: state} com o estado bruto em maiúsculas
    """
    mac_table = {}
    active_ips = set()
    stale_ips = set()
    state_map = {}

    for line in (stdout_text or "").splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        m_ip = re.match(r"^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", line_s)
        if not m_ip:
            continue
        ip = m_ip.group(1)
        tokens = line_s.split()
        state = tokens[-1].upper() if tokens else ""
        state_map[ip] = state

        m_mac = re.search(r"\blladdr\s+([0-9a-fA-F:]{17})\b", line_s)
        has_valid_mac = False
        if m_mac:
            mac = m_mac.group(1).upper()
            if is_valid_mac(mac) and mac != "00:00:00:00:00:00":
                mac_table[ip] = mac
                has_valid_mac = True

        if state in ACTIVE_NEIGHBOR_STATES:
            active_ips.add(ip)
        elif state == "STALE" and has_valid_mac:
            stale_ips.add(ip)

    return mac_table, active_ips, stale_ips, state_map

def inspect_neighbor_table(interface="wlan0", include_details=False):
    """
    Executa `ip neigh show dev <interface>` e complementa MACs com `/proc/net/arp`.
    Considera ativos os estados `REACHABLE`, `DELAY` e `PROBE`.
    Quando `include_details=False` (padrão retrocompatível):
      Retorna `(mac_table, active_ips)`.
    Quando `include_details=True`:
      Retorna `(mac_table, active_ips, stale_ips, state_map)`.
    """
    mac_table = {}
    active_ips = set()
    stale_ips = set()
    state_map = {}

    for ip_bin in ["ip", "/data/data/com.termux/files/usr/bin/ip", "/system/bin/ip"]:
        try:
            cmd = [ip_bin, "neigh", "show"]
            if interface and interface != "desconectado":
                cmd.extend(["dev", interface])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=1.5)
            out = res.stdout or ""
            if out.strip():
                mac_table, active_ips, stale_ips, state_map = parse_ip_neigh_output(out)
                break
        except Exception:
            pass

    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        flags = parts[2].upper()
                        mac = parts[3].upper()
                        if is_valid_mac(mac) and mac != "00:00:00:00:00:00" and flags != "0X0":
                            if ip not in mac_table:
                                mac_table[ip] = mac
                            if ip not in state_map:
                                state_map[ip] = "STALE"
                                stale_ips.add(ip)
    except Exception:
        pass

    if include_details:
        return mac_table, active_ips, stale_ips, state_map
    return mac_table, active_ips

def parse_arp_table():
    """Wrapper de compatibilidade que retorna o dicionário {ip: mac}."""
    mac_table, _ = inspect_neighbor_table("wlan0")
    return mac_table

def resolve_smart_hostname(ip, mac="N/A", my_ip=None, gateway_ip=None, reverse_dns_name=None):
    """
    Resolução inteligente de hostname:
    1. Se ip == my_ip -> "Moto E6 Play (Host Local)"
    2. Se reverse_dns_name válido e diferente do próprio IP, utiliza-o.
    3. Caso contrário:
       - Se ip == gateway_ip -> "Gateway / Roteador"
       - Se MAC válido e mac[1].upper() em {'2', '6', 'A', 'E'} -> "Dispositivo Móvel (MAC Privado)"
       - Caso contrário -> "Dispositivo na LAN"
    """
    if my_ip and ip == my_ip:
        return LOCAL_HOST_LABEL

    resolved = (reverse_dns_name or "").strip()
    if resolved and resolved != ip and not resolved.startswith(ip):
        return resolved

    if gateway_ip and ip == gateway_ip:
        return GATEWAY_LABEL

    if is_locally_administered_mac(mac):
        return PRIVATE_MAC_LABEL

    return GENERIC_LAN_LABEL

def grab_port_banner(ip, port, timeout=0.35):
    """
    Captura banner leve em portas abertas:
    - SSH (22 / 8022): lê banner `SSH-*`
    - HTTP (80 / 8080 / 5000 / 8008): lê cabeçalho `Server` e/ou tag `<title>`
    - Demais portas: descrição padrão do protocolo.
    """
    service_name = PORT_SERVICE_NAMES.get(port, f"TCP/{port}")
    if port == 5000 and ip in ("127.0.0.1",):
        return "NetWatch E6 Web Dashboard (Flask)"

    try:
        if port in (21, 22, 23, 8022):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            raw = s.recv(128).decode("utf-8", errors="ignore").strip()
            s.close()
            if raw:
                first_line = raw.splitlines()[0][:80]
                return first_line
            return f"Servidor {service_name} Ativo"

        elif port in (80, 8080, 5000, 8008):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetWatch-E6/2.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii", errors="ignore"))
            data = s.recv(2048).decode("utf-8", errors="ignore")
            s.close()

            if data:
                status_line = data.splitlines()[0].strip() if data.splitlines() else ""
                m_title = re.search(r"<title[^>]*>(.*?)</title>", data, re.IGNORECASE | re.DOTALL)
                m_server = re.search(r"^Server:\s*(.+)$", data, re.IGNORECASE | re.MULTILINE)
                parts = []
                if m_title:
                    title_clean = re.sub(r"\s+", " ", m_title.group(1)).strip()[:55]
                    if title_clean:
                        parts.append(f"Título: {title_clean}")
                if m_server:
                    srv_clean = m_server.group(1).strip()[:40]
                    if srv_clean:
                        parts.append(f"Server: {srv_clean}")
                if parts:
                    return " | ".join(parts)
                if status_line.startswith("HTTP/"):
                    return status_line[:50]
            return f"Serviço {service_name} Ativo"

        elif port == 443:
            return "HTTPS / TLS Ativo"
        elif port == 53:
            return "Servidor DNS Ativo"
        elif port in (135, 139, 445):
            return "Compartilhamento Windows SMB/RPC"
        elif port == 3389:
            return "Área de Trabalho Remota Windows (RDP)"
        elif port == 9100:
            return "Serviço de Impressão JetDirect/RAW"
        elif port == 5555:
            return "Daemon ADB sobre TCP"
    except Exception:
        pass

    return f"Porta {port} ({service_name}) Aberta"

def detect_local_listening_ports(my_ip="127.0.0.1", timeout=0.08):
    """
    Detecta portas locais em escuta no próprio aparelho (incluindo 5000 e 8022 se ativas),
    testando em 127.0.0.1 para resposta instantânea.
    """
    open_ports = set()
    for port in COMMON_PROBE_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ret = s.connect_ex(("127.0.0.1", port))
            s.close()
            if ret == 0:
                open_ports.add(port)
        except Exception:
            pass

    netwatch_port = int(os.environ.get("NETWATCH_PORT", "5000"))
    if netwatch_port in COMMON_PROBE_PORTS:
        open_ports.add(netwatch_port)

    return sorted(open_ports)

def probe_tcp_socket(ip, port, timeout=0.12):
    """
    Tenta conectar via TCP em (ip, port) com timeout curto.
    Retorna:
      - ("OPEN", latency_ms) se a conexão for aceita (SYN-ACK / ret == 0)
      - ("REFUSED", latency_ms) se receber TCP RST (ConnectionRefusedError / ECONNREFUSED)
      - ("CLOSED", None) se expirar por timeout ou host inalcançável
    """
    start_t = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        ret = s.connect_ex((ip, port))
        latency = (time.perf_counter() - start_t) * 1000.0
        if ret == 0:
            return "OPEN", latency
        if ret in ECONNREFUSED_CODES:
            return "REFUSED", latency
    except ConnectionRefusedError:
        latency = (time.perf_counter() - start_t) * 1000.0
        return "REFUSED", latency
    except OSError as e:
        if getattr(e, "errno", None) in ECONNREFUSED_CODES:
            latency = (time.perf_counter() - start_t) * 1000.0
            return "REFUSED", latency
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return "CLOSED", None

def send_udp_arp_nudge(ip):
    """
    Envia datagrama UDP leve para as portas 5353 (mDNS), 137 (NetBIOS) e 1900 (SSDP)
    para forçar o kernel Linux/Android a disparar requisição ARP em camada 2 na wlan0,
    mesmo que o host alvo bloqueie ICMP/Ping ou descarte o pacote em camada superior.
    """
    for port in (5353, 137, 1900):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            s.sendto(b"\x00", (ip, port))
            s.close()
        except Exception:
            pass

def reverify_stale_neighbor(ip, timeout=0.30):
    """
    Executa sondagem direcionada em um vizinho que apareceu como `STALE` na tabela ARP:
    1. Envia datagramas UDP (5353, 137, 1900) para forçar o kernel a revalidar o ARP (STALE -> DELAY/PROBE -> REACHABLE).
    2. Tenta conexão TCP rápida com timeout de 0.30s nas portas de presença (80, 443, 62078, 445).
    3. Executa fallback de ping rápido.
    Retorna dict de presença caso responda em camada 3/4, ou None para depender da atualização do kernel em `ip neigh`.
    """
    send_udp_arp_nudge(ip)
    for idx, port in enumerate(PHASE_A_PRESENCE_PORTS):
        p_to = timeout if idx == 0 else min(timeout, 0.12)
        state, lat = probe_tcp_socket(ip, port, timeout=p_to)
        if state == "OPEN":
            return {"ip": ip, "online": True, "open_ports": [port], "latency": round(lat or 2.0, 2), "method": "STALE_TCP_OPEN"}
        if state == "REFUSED":
            return {"ip": ip, "online": True, "open_ports": [], "latency": round(lat or 2.0, 2), "method": "STALE_TCP_RST"}
    ok, lat = ping_host(ip, max_wait=0.55)
    if ok:
        return {"ip": ip, "online": True, "open_ports": [], "latency": round(lat or 3.5, 2), "method": "STALE_ICMP"}
    return None

def ping_host(ip, max_wait=1.0):
    """Executa `/system/bin/ping -c 1 -W 1 <ip>` retornando (True, latency_ms) se código 0."""
    ping_bin = "/system/bin/ping" if os.path.exists("/system/bin/ping") else "ping"

    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", "400", ip]
    else:
        cmd = [ping_bin, "-c", "1", "-W", "1", ip]

    try:
        t0 = time.perf_counter()
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=max_wait)
        dt = (time.perf_counter() - t0) * 1000.0
        if res.returncode == 0:
            return True, round(dt, 2)
    except Exception:
        pass
    return False, None

def phase_a_check_presence(ip, timeout=0.12, my_ip=None, gateway_ip=None, allow_icmp=False):
    """
    Fase A — Descoberta Ativa de Presença para um IP:
    a) Sonda UDP vazia (5353 / 137) para forçar requisição ARP no kernel.
    b) Sonda TCP rápida em (80, 443, 62078, 445) com timeout=0.12s:
       - "OPEN" -> host ONLINE e porta aberta.
       - "REFUSED" (TCP RST / ECONNREFUSED) -> host ONLINE (pilha TCP/IP respondeu).
    c) Se allow_icmp=True, executa `/system/bin/ping -c 1 -W 1 <ip>`.
    """
    if my_ip and ip == my_ip:
        return {
            "ip": ip,
            "online": True,
            "open_ports": [],
            "latency": 0.1,
            "method": "LOCAL"
        }

    send_udp_arp_nudge(ip)

    open_ports = []
    latencies = []
    is_online = False
    method = None

    for idx, port in enumerate(PHASE_A_PRESENCE_PORTS):
        p_timeout = timeout if idx == 0 else min(timeout, 0.05)
        state, lat = probe_tcp_socket(ip, port, timeout=p_timeout)
        if state == "OPEN":
            is_online = True
            open_ports.append(port)
            latencies.append(lat)
            method = "TCP_OPEN"
            break
        elif state == "REFUSED":
            is_online = True
            latencies.append(lat)
            method = "TCP_RST"
            break

    if not is_online and allow_icmp:
        ping_ok, ping_lat = ping_host(ip, max_wait=0.85)
        if ping_ok:
            is_online = True
            latencies.append(ping_lat)
            method = "ICMP"

    if not is_online:
        return None

    best_lat = round(min(latencies), 2) if latencies else 1.0
    return {
        "ip": ip,
        "online": True,
        "open_ports": open_ports,
        "latency": best_lat,
        "method": method
    }

def deep_fingerprint_host(ip, initial_open_ports=None, initial_latency=None, timeout=0.20, is_local_host=False):
    """
    Scan Profundo (`deep_fingerprint_host`):
    - Executado apenas para hosts novos, hosts que acabaram de voltar a ONLINE, ou a cada 180s.
    - Sonda as 13 portas (22, 53, 80, 135, 139, 443, 445, 5000, 5555, 8008, 8022, 8080, 9100)
      com timeout=0.20s em paralelo.
    - Traduz para nomes legíveis e captura banner leve nas portas abertas.
    """
    if is_local_host:
        local_ports = detect_local_listening_ports(ip, timeout=0.08)
        srv_details = []
        for p in local_ports:
            sname = PORT_SERVICE_NAMES.get(p, f"TCP/{p}")
            if p == 5000:
                banner = "NetWatch E6 Web Dashboard (Flask)"
            elif p in (22, 8022):
                banner = grab_port_banner("127.0.0.1", p, timeout=0.25)
            else:
                banner = f"Serviço Local {sname}"
            srv_details.append({"port": p, "service": sname, "banner": banner})
        _LAST_DEEP_FINGERPRINT[ip] = time.time()
        return {
            "ip": ip,
            "reverse_dns": "",
            "open_ports": ",".join(map(str, local_ports)),
            "service_details": json.dumps(srv_details, ensure_ascii=False),
            "service_details_list": srv_details,
            "latency": 0.1,
            "latency_ms": 0.1,
            "status": "ONLINE"
        }

    open_ports = set(initial_open_ports or [])
    latencies = [initial_latency] if initial_latency else []

    ports_to_check = [p for p in COMMON_PROBE_PORTS if p not in open_ports]
    if ports_to_check:
        with ThreadPoolExecutor(max_workers=len(ports_to_check)) as p_exec:
            f_map = {p_exec.submit(probe_tcp_socket, ip, port, timeout): port for port in ports_to_check}
            for fut in as_completed(f_map):
                port = f_map[fut]
                try:
                    state, lat = fut.result()
                    if state == "OPEN":
                        open_ports.add(port)
                        if lat is not None:
                            latencies.append(lat)
                    elif state == "REFUSED" and lat is not None:
                        latencies.append(lat)
                except Exception:
                    pass

    sorted_ports = sorted(open_ports)
    srv_details = []
    for p in sorted_ports:
        sname = PORT_SERVICE_NAMES.get(p, f"TCP/{p}")
        banner = grab_port_banner(ip, p, timeout=0.35)
        srv_details.append({"port": p, "service": sname, "banner": banner})

    final_latency = round(min(latencies), 2) if latencies else 1.0
    _LAST_DEEP_FINGERPRINT[ip] = time.time()

    return {
        "ip": ip,
        "reverse_dns": "",
        "open_ports": ",".join(map(str, sorted_ports)),
        "service_details": json.dumps(srv_details, ensure_ascii=False),
        "service_details_list": srv_details,
        "latency": final_latency,
        "latency_ms": final_latency,
        "status": "ONLINE"
    }

def phase_b_scan_ports(ip, initial_open_ports=None, initial_latency=None, timeout=0.20):
    """Wrapper de compatibilidade para deep_fingerprint_host."""
    return deep_fingerprint_host(
        ip,
        initial_open_ports=initial_open_ports,
        initial_latency=initial_latency,
        timeout=timeout,
        is_local_host=False
    )

def probe_host(ip, timeout=0.20, my_ip=None, gateway_ip=None, interface="wlan0"):
    """
    Função de sondagem completa de um único host (combina presença + deep fingerprint),
    compatível com chamadas unitárias diretas.
    """
    if my_ip and ip == my_ip:
        fp = deep_fingerprint_host(ip, is_local_host=True)
        local_mac = get_interface_mac(interface)
        vendor = resolve_vendor_oui(local_mac, is_local_host=True)
        dtype = infer_device_type(ip, local_mac, vendor, fp["open_ports"], my_ip=my_ip, gateway_ip=gateway_ip)
        fp["mac"] = local_mac
        fp["hostname"] = LOCAL_HOST_LABEL
        fp["vendor"] = vendor
        fp["device_type"] = dtype
        return fp

    presence = phase_a_check_presence(
        ip,
        timeout=min(timeout, 0.12),
        my_ip=my_ip,
        gateway_ip=gateway_ip,
        allow_icmp=True
    )
    if not presence:
        return None

    details = deep_fingerprint_host(
        ip,
        initial_open_ports=presence.get("open_ports"),
        initial_latency=presence.get("latency"),
        timeout=timeout,
        is_local_host=False
    )
    details["mac"] = "N/A"
    details["vendor"] = resolve_vendor_oui("N/A")
    details["hostname"] = resolve_smart_hostname(
        ip=ip,
        mac="N/A",
        my_ip=my_ip,
        gateway_ip=gateway_ip,
        reverse_dns_name=details.get("reverse_dns", "")
    )
    details["device_type"] = infer_device_type(
        ip,
        "N/A",
        details["vendor"],
        details["open_ports"],
        my_ip=my_ip,
        gateway_ip=gateway_ip
    )
    return details

def quick_presence_scan(network_cidr=None, my_ip=None, gateway_ip=None, interface=None, force_deep=False):
    """
    Loop Rápido de Presença com Prioridade + Deep Fingerprint Condicional:
    - Passo 1 (Prioridade ~0.5–1.2s): Verifica imediatamente os IPs já conhecidos na `network_cidr`
      atual para detectar saída ou retorno quase em tempo real.
    - Passo 2 (Varredura rápida /24): `ThreadPoolExecutor(max_workers=64)` com sondas TCP rápidas
      (80, 443, 62078, 445) (timeout=0.12s, aceitando Open ou ConnectionRefusedError), UDP 5353/137
      + leitura de `ip neigh show dev <interface>` (somente REACHABLE) e fallback ping nos candidatos L2.
    - Passo 3: Executa `deep_fingerprint_host(ip)` APENAS para hosts novos, hosts que acabaram de
      voltar a ONLINE, ou a cada 180 segundos (reaproveitando portas/banners nos ciclos intermediários).
    - Passo 4: Calcula `connected_since`, `total_online_seconds`, `disconnections_count`, `last_state_change`
      e grava histórico de latência (últimos 100 pontos por IP).
    """
    t_start = time.perf_counter()
    net_info = get_network_info()

    if network_cidr is None:
        if not net_info.get("is_connected"):
            log_event("DISCOVERY", "WARNING", "Varredura cancelada: aparelho não está conectado a uma rede Wi-Fi.")
            return []
        network_cidr = net_info.get("network_cidr")

    if my_ip is None:
        my_ip = net_info.get("ip", "127.0.0.1")
    if gateway_ip is None:
        gateway_ip = net_info.get("gateway")
    if interface is None:
        interface = net_info.get("interface", "wlan0")
        if interface == "desconectado":
            interface = "wlan0"

    normalized_cidr = network_cidr or "127.0.0.0/24"
    try:
        net_obj = ipaddress.IPv4Network(normalized_cidr, strict=False)
        normalized_cidr = str(net_obj)
    except Exception:
        net_obj = None

    if not network_cidr or network_cidr.startswith("127."):
        targets = [my_ip]
    else:
        try:
            targets = [str(host) for host in net_obj.hosts()][:254]
            if my_ip and my_ip not in targets and not my_ip.startswith("127."):
                targets.append(my_ip)
        except Exception:
            targets = [my_ip]

    target_set = set(targets)

    # Lê os dispositivos já conhecidos na sub-rede atual
    conn_init = get_db_connection()
    cur_init = conn_init.cursor()
    cur_init.execute("SELECT * FROM devices WHERE network_cidr = ?;", (normalized_cidr,))
    previous_devices = {row["ip"]: dict(row) for row in cur_init.fetchall()}
    conn_init.close()

    confirmed_online = {}

    # ==========================================================================
    # PASSO 0 — Varredura UDP Leve em toda a sub-rede /24 para acordar ARP L2
    # ==========================================================================
    for t_ip in targets:
        if t_ip != my_ip:
            send_udp_arp_nudge(t_ip)

    # ==========================================================================
    # PASSO 1 (Prioridade ~1s) — Verificação Imediata dos Hosts Já Conhecidos
    # ==========================================================================
    priority_ips = [ip for ip in previous_devices.keys() if ip in target_set and ip != my_ip]
    if gateway_ip and gateway_ip in target_set and gateway_ip not in priority_ips and gateway_ip != my_ip:
        priority_ips.insert(0, gateway_ip)

    if priority_ips:
        with ThreadPoolExecutor(max_workers=min(32, len(priority_ips))) as p_exec:
            f_prio = {
                p_exec.submit(phase_a_check_presence, ip, 0.25, my_ip, gateway_ip, True): ip
                for ip in priority_ips
            }
            for fut in as_completed(f_prio):
                try:
                    res = fut.result()
                    if res and res.get("online"):
                        confirmed_online[res["ip"]] = res
                except Exception:
                    pass

    # ==========================================================================
    # PASSO 2 — Varredura Rápida /24 nos Demais IPs (64 threads, timeout=0.15s)
    # ==========================================================================
    remaining_ips = [ip for ip in targets if ip not in confirmed_online and ip not in priority_ips]
    if remaining_ips:
        with ThreadPoolExecutor(max_workers=64) as executor:
            future_to_ip = {
                executor.submit(phase_a_check_presence, ip, 0.15, my_ip, gateway_ip, False): ip
                for ip in remaining_ips
            }
            for future in as_completed(future_to_ip):
                try:
                    res = future.result()
                    if res and res.get("online"):
                        confirmed_online[res["ip"]] = res
                except Exception:
                    pass

    # Inspeciona `ip neigh show dev <interface>` considerando ativos REACHABLE, DELAY e PROBE
    neigh_res = inspect_neighbor_table(interface)
    if isinstance(neigh_res, tuple) and len(neigh_res) == 4:
        mac_table, active_neigh_ips, stale_neigh_ips, _ = neigh_res
    else:
        mac_table, active_neigh_ips = neigh_res
        stale_neigh_ips = set()

    for r_ip in active_neigh_ips:
        if r_ip in target_set and r_ip not in confirmed_online:
            confirmed_online[r_ip] = {
                "ip": r_ip,
                "online": True,
                "open_ports": [],
                "latency": 2.5,
                "method": "ARP_ACTIVE"
            }

    # Para hosts em STALE (ou presentes na mac_table mas ainda não confirmados), faz nova sondagem direcionada
    stale_candidates = [
        ip for ip in (set(stale_neigh_ips) | set(mac_table.keys()))
        if ip in target_set and ip not in confirmed_online and ip != my_ip
    ]
    if stale_candidates:
        with ThreadPoolExecutor(max_workers=min(32, len(stale_candidates))) as p_exec:
            f_stale = {p_exec.submit(reverify_stale_neighbor, ip, 0.30): ip for ip in stale_candidates}
            for fut in as_completed(f_stale):
                ip = f_stale[fut]
                try:
                    res = fut.result()
                    if res and res.get("online"):
                        confirmed_online[ip] = res
                except Exception:
                    pass

        neigh_after = inspect_neighbor_table(interface)
        if isinstance(neigh_after, tuple) and len(neigh_after) == 4:
            mac_table_after, active_after, _, _ = neigh_after
        else:
            mac_table_after, active_after = neigh_after
        mac_table.update(mac_table_after)
        for r_ip in active_after:
            if r_ip in target_set and r_ip not in confirmed_online:
                confirmed_online[r_ip] = {
                    "ip": r_ip,
                    "online": True,
                    "open_ports": [],
                    "latency": 3.0,
                    "method": "ARP_ACTIVE"
                }

    # Garante presença do Host Local
    if my_ip and my_ip in target_set:
        confirmed_online[my_ip] = {
            "ip": my_ip,
            "online": True,
            "open_ports": [],
            "latency": 0.1,
            "method": "LOCAL"
        }

    # ==========================================================================
    # PASSO 3 — Deep Fingerprint Condicional (Novos, Retornos ou a cada 180s)
    # ==========================================================================
    now_ts = time.time()
    discovered_devices = []
    hosts_needing_deep = []

    for ip, entry in confirmed_online.items():
        prev = previous_devices.get(ip)
        is_new = prev is None
        just_returned = (prev is not None and prev.get("status") != "ONLINE")
        last_deep = _LAST_DEEP_FINGERPRINT.get(ip, 0)
        missing_services = (prev is not None and (not prev.get("service_details") or prev.get("service_details") == "[]") and bool(prev.get("open_ports")))
        needs_deep = force_deep or is_new or just_returned or missing_services or ((now_ts - last_deep) >= DEEP_FINGERPRINT_INTERVAL_SECONDS)

        if ip == my_ip:
            if needs_deep or not prev:
                fp = deep_fingerprint_host(my_ip, is_local_host=True)
            else:
                fp = {
                    "ip": my_ip,
                    "open_ports": prev.get("open_ports") or "5000",
                    "service_details": prev.get("service_details") or '[{"port": 5000, "service": "HTTP/NetWatch", "banner": "NetWatch E6 Web Dashboard (Flask)"}]',
                    "latency": 0.1,
                    "status": "ONLINE"
                }
            local_mac = get_interface_mac(interface)
            vendor = resolve_vendor_oui(local_mac, is_local_host=True)
            dtype = infer_device_type(my_ip, local_mac, vendor, fp["open_ports"], my_ip=my_ip, gateway_ip=gateway_ip)
            discovered_devices.append({
                "ip": my_ip,
                "mac": local_mac,
                "hostname": LOCAL_HOST_LABEL,
                "vendor": vendor,
                "device_type": dtype,
                "open_ports": fp["open_ports"],
                "service_details": fp["service_details"],
                "latency": 0.1,
                "latency_ms": 0.1,
                "status": "ONLINE",
                "network_cidr": normalized_cidr
            })
        elif needs_deep:
            hosts_needing_deep.append(entry)
        else:
            # Reaproveita portas e service_details do banco para manter o ciclo rápido (~1.5-2.5s)
            mac = mac_table.get(ip) or prev.get("mac") or "N/A"
            open_ports_cached = prev.get("open_ports") or ",".join(map(str, entry.get("open_ports") or []))
            srv_cached = prev.get("service_details") or "[]"
            vendor = resolve_vendor_oui(mac, is_local_host=False, service_details=srv_cached)
            hostname = resolve_smart_hostname(ip=ip, mac=mac, my_ip=my_ip, gateway_ip=gateway_ip)
            dtype = infer_device_type(ip, mac, vendor, open_ports_cached, my_ip=my_ip, gateway_ip=gateway_ip)
            lat = entry.get("latency") or prev.get("latency") or 2.0
            discovered_devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": dtype,
                "open_ports": open_ports_cached,
                "service_details": srv_cached,
                "latency": round(float(lat), 2),
                "latency_ms": round(float(lat), 2),
                "status": "ONLINE",
                "network_cidr": normalized_cidr
            })

    if hosts_needing_deep:
        workers_b = min(16, max(1, len(hosts_needing_deep)))
        with ThreadPoolExecutor(max_workers=workers_b) as executor:
            future_to_ip = {
                executor.submit(
                    deep_fingerprint_host,
                    entry["ip"],
                    entry.get("open_ports"),
                    entry.get("latency"),
                    0.20,
                    False
                ): entry["ip"]
                for entry in hosts_needing_deep
            }
            for future in as_completed(future_to_ip):
                try:
                    dev = future.result()
                    if dev:
                        ip = dev["ip"]
                        prev = previous_devices.get(ip)
                        mac = mac_table.get(ip) or (prev.get("mac") if prev else None) or "N/A"
                        vendor = resolve_vendor_oui(
                            mac,
                            is_local_host=False,
                            service_details=dev.get("service_details")
                        )
                        hostname = resolve_smart_hostname(
                            ip=ip,
                            mac=mac,
                            my_ip=my_ip,
                            gateway_ip=gateway_ip,
                            reverse_dns_name=dev.get("reverse_dns", "")
                        )
                        dtype = infer_device_type(
                            ip,
                            mac,
                            vendor,
                            dev["open_ports"],
                            my_ip=my_ip,
                            gateway_ip=gateway_ip
                        )
                        dev["mac"] = mac
                        dev["vendor"] = vendor
                        dev["hostname"] = hostname
                        dev["device_type"] = dtype
                        dev["network_cidr"] = normalized_cidr
                        discovered_devices.append(dev)
                except Exception:
                    pass

    found_ips = {d["ip"] for d in discovered_devices}

    # ==========================================================================
    # PASSO 4 — Persistência SQLite, Cálculo de Tempo Conectado e Transições
    # ==========================================================================
    now_dt = datetime.now()
    now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%S")
    conn = get_db_connection()
    cursor = conn.cursor()

    transition_events = []

    for dev in discovered_devices:
        ip = dev["ip"]
        dev["last_seen"] = now_iso
        prev = previous_devices.get(ip)

        if prev is None:
            # Dispositivo novo na sub-rede
            first_seen = now_iso
            connected_since = now_iso
            total_online_seconds = 0
            last_state_change = now_iso
            last_event_type = "ENTERED"
            disconnections_count = 0
            transition_events.append((
                "DISCOVERY",
                "INFO",
                f"DISPOSITIVO ENTROU: {ip} ({dev['hostname']}) [MAC: {dev.get('mac', 'N/A')}] detectado ONLINE em {normalized_cidr}."
            ))
        elif prev.get("status") != "ONLINE":
            # Dispositivo retornou (OFFLINE -> ONLINE)
            first_seen = prev.get("first_seen") or prev.get("last_seen") or now_iso
            connected_since = now_iso
            total_online_seconds = int(prev.get("total_online_seconds") or 0)
            last_state_change = now_iso
            last_event_type = "RETURNED"
            disconnections_count = int(prev.get("disconnections_count") or 0)
            transition_events.append((
                "DISCOVERY",
                "INFO",
                f"ONLINE: Dispositivo {ip} ({dev['hostname']}) voltou a responder em {normalized_cidr}."
            ))
        else:
            # Dispositivo permaneceu ONLINE -> acumula delta real desde o último ciclo
            first_seen = prev.get("first_seen") or prev.get("last_seen") or now_iso
            connected_since = prev.get("connected_since") or prev.get("last_seen") or now_iso
            last_state_change = prev.get("last_state_change") or connected_since
            last_event_type = prev.get("last_event_type") or "ENTERED"
            disconnections_count = int(prev.get("disconnections_count") or 0)

            prev_seen_dt = parse_iso_datetime(prev.get("last_seen"))
            delta_sec = 0
            if prev_seen_dt:
                raw_delta = int((now_dt - prev_seen_dt).total_seconds())
                if 0 < raw_delta <= 300:
                    delta_sec = raw_delta
            total_online_seconds = int(prev.get("total_online_seconds") or 0) + delta_sec

        dev["first_seen"] = first_seen
        dev["connected_since"] = connected_since
        dev["total_online_seconds"] = total_online_seconds
        dev["last_state_change"] = last_state_change
        dev["last_event_type"] = last_event_type
        dev["disconnections_count"] = disconnections_count
        dev["missed_scans"] = 0

        cursor.execute("""
            INSERT INTO devices (
                ip, mac, hostname, vendor, status, open_ports, latency, last_seen,
                network_cidr, first_seen, connected_since, total_online_seconds,
                last_state_change, last_event_type, disconnections_count, device_type,
                service_details, previous_ports, missed_scans
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            ON CONFLICT(ip) DO UPDATE SET
                mac = CASE WHEN excluded.mac != 'N/A' THEN excluded.mac ELSE devices.mac END,
                hostname = excluded.hostname,
                vendor = CASE WHEN excluded.vendor != 'Desconhecido' THEN excluded.vendor ELSE devices.vendor END,
                status = 'ONLINE',
                open_ports = excluded.open_ports,
                latency = excluded.latency,
                last_seen = excluded.last_seen,
                network_cidr = excluded.network_cidr,
                first_seen = COALESCE(devices.first_seen, excluded.first_seen),
                connected_since = excluded.connected_since,
                total_online_seconds = excluded.total_online_seconds,
                last_state_change = excluded.last_state_change,
                last_event_type = excluded.last_event_type,
                disconnections_count = excluded.disconnections_count,
                device_type = excluded.device_type,
                service_details = excluded.service_details,
                missed_scans = 0;
        """, (
            ip,
            dev.get("mac", "N/A"),
            dev["hostname"],
            dev.get("vendor", "Desconhecido"),
            "ONLINE",
            dev["open_ports"],
            dev["latency"],
            now_iso,
            normalized_cidr,
            first_seen,
            connected_since,
            total_online_seconds,
            last_state_change,
            last_event_type,
            disconnections_count,
            dev.get("device_type", "Dispositivo na LAN"),
            dev.get("service_details", "[]"),
            dev["open_ports"]
        ))

        record_device_latency(conn, ip, normalized_cidr, now_iso, dev["latency"], "ONLINE")

    # Histerese anti-flapping: dispositivos ausentes só mudam para OFFLINE quando missed_scans >= 2 (20s)
    for prev_ip, prev_row in previous_devices.items():
        if prev_ip not in found_ips:
            if prev_row.get("status") == "ONLINE":
                new_missed = int(prev_row.get("missed_scans") or 0) + 1
                if new_missed < HYSTERESIS_MAX_MISSED_SCANS:
                    # Mantém o host ONLINE durante falha transitória (1ª falha consecutiva)
                    cursor.execute("""
                        UPDATE devices
                        SET missed_scans = ?
                        WHERE ip = ? AND network_cidr = ?;
                    """, (new_missed, prev_ip, normalized_cidr))
                    retained_dev = dict(prev_row)
                    retained_dev["missed_scans"] = new_missed
                    retained_dev["status"] = "ONLINE"
                    discovered_devices.append(retained_dev)
                else:
                    # Atingiu 2 falhas consecutivas (20s sem resposta) -> transiciona para OFFLINE
                    prev_seen_dt = parse_iso_datetime(prev_row.get("last_seen"))
                    delta_sec = 0
                    if prev_seen_dt:
                        raw_delta = int((now_dt - prev_seen_dt).total_seconds())
                        if 0 < raw_delta <= 300:
                            delta_sec = raw_delta
                    new_total_online = int(prev_row.get("total_online_seconds") or 0) + delta_sec
                    new_disc_count = int(prev_row.get("disconnections_count") or 0) + 1

                    cursor.execute("""
                        UPDATE devices
                        SET status = 'OFFLINE',
                            connected_since = NULL,
                            total_online_seconds = ?,
                            disconnections_count = ?,
                            last_state_change = ?,
                            last_event_type = 'LEFT',
                            missed_scans = ?
                        WHERE ip = ? AND network_cidr = ?;
                    """, (new_total_online, new_disc_count, now_iso, new_missed, prev_ip, normalized_cidr))

                    record_device_latency(conn, prev_ip, normalized_cidr, now_iso, None, "OFFLINE")

                    transition_events.append((
                        "DISCOVERY",
                        "WARNING",
                        f"DISPOSITIVO SAIU / OFFLINE: {prev_ip} ({prev_row.get('hostname') or 'Dispositivo na LAN'}) parou de responder em {normalized_cidr} após {new_missed} ciclos."
                    ))
            else:
                cursor.execute(
                    "UPDATE devices SET status = 'OFFLINE', connected_since = NULL WHERE ip = ? AND network_cidr = ?;",
                    (prev_ip, normalized_cidr)
                )

    cursor.execute("UPDATE devices SET status = 'OFFLINE', connected_since = NULL WHERE network_cidr != ?;", (normalized_cidr,))

    conn.commit()
    conn.close()

    for ev_type, ev_sev, ev_msg in transition_events:
        log_event(ev_type, ev_sev, ev_msg)

    discovered_devices = sort_devices(discovered_devices, my_ip=my_ip, gateway_ip=gateway_ip)
    return discovered_devices

def scan_network(network_cidr=None, my_ip=None, gateway_ip=None, interface=None):
    """Wrapper principal que executa quick_presence_scan."""
    return quick_presence_scan(
        network_cidr=network_cidr,
        my_ip=my_ip,
        gateway_ip=gateway_ip,
        interface=interface,
        force_deep=False
    )

if __name__ == "__main__":
    print("Iniciando quick_presence_scan()...")
    t0 = time.perf_counter()
    devices = quick_presence_scan()
    dt = time.perf_counter() - t0
    print(f"Concluído em {dt:.2f}s — {len(devices)} dispositivos ONLINE:")
    for d in devices:
        print(d)
