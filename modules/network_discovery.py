import subprocess
import socket
import re
import os
import time
import ipaddress

WIFI_DISCONNECTED_MSG = "Conecte o aparelho a uma rede Wi-Fi para iniciar o monitoramento"

# Cache em memória para cálculo de taxa RX/TX em KB/s do Host Local
_TRAFFIC_CACHE = {}

def get_prop(prop_name):
    """Lê propriedades do sistema Android via /system/bin/getprop (sem root)."""
    for cmd_bin in ["getprop", "/system/bin/getprop"]:
        try:
            res = subprocess.run([cmd_bin, prop_name], capture_output=True, text=True, timeout=2)
            val = res.stdout.strip()
            if val:
                return val
        except Exception:
            pass
    return None

def get_dns_servers():
    """Obtém os servidores DNS configurados no Android ou fallback local."""
    dns_list = []
    dns1 = get_prop("net.dns1")
    dns2 = get_prop("net.dns2")

    if dns1:
        dns_list.append(dns1)
    if dns2 and dns2 not in dns_list:
        dns_list.append(dns2)

    if not dns_list:
        dns_list = ["1.1.1.1", "8.8.8.8"]

    return dns_list

def get_interface_mac(interface="wlan0"):
    """
    Lê o endereço físico real da interface ativa em /sys/class/net/<interface>/address
    com fallback para `ip link show <interface>`, garantindo que nunca exiba N/A para o host local.
    """
    if not interface:
        interface = "wlan0"

    sysfs_path = f"/sys/class/net/{interface}/address"
    try:
        if os.path.exists(sysfs_path):
            with open(sysfs_path, "r") as f:
                mac = f.read().strip().upper()
                if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac) and mac != "00:00:00:00:00:00":
                    return mac
    except Exception:
        pass

    for ip_bin in ["ip", "/data/data/com.termux/files/usr/bin/ip", "/system/bin/ip"]:
        try:
            res = subprocess.run([ip_bin, "link", "show", interface], capture_output=True, text=True, timeout=2)
            m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", res.stdout or "")
            if m:
                mac = m.group(1).upper()
                if mac != "00:00:00:00:00:00":
                    return mac
        except Exception:
            pass

    prop_mac = get_prop("ro.boot.wifimacaddr") or get_prop("ro.wifimacaddr")
    if prop_mac and re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", prop_mac.strip()):
        return prop_mac.strip().upper()

    return "02:00:00:00:00:00"

def get_local_interface_traffic(interface="wlan0"):
    """
    Lê contadores de tráfego RX/TX da interface ativa em `/sys/class/net/<interface>/statistics/`
    com fallback automático para `/proc/net/dev` e `ip -s link show <interface>`.
    Retorna bytes recebidos/enviados, total em MB e taxa estimada em KB/s.
    """
    if not interface or interface == "desconectado":
        interface = "wlan0"

    rx_bytes = None
    tx_bytes = None
    rx_packets = 0
    tx_packets = 0
    source = None

    # 1. Tentativa via /sys/class/net/<interface>/statistics/
    rx_path = f"/sys/class/net/{interface}/statistics/rx_bytes"
    tx_path = f"/sys/class/net/{interface}/statistics/tx_bytes"
    try:
        if os.path.exists(rx_path) and os.path.exists(tx_path):
            with open(rx_path, "r") as fr, open(tx_path, "r") as ft:
                rx_bytes = int(fr.read().strip())
                tx_bytes = int(ft.read().strip())
                source = f"/sys/class/net/{interface}/statistics"
    except Exception:
        pass

    # 2. Fallback via /proc/net/dev (acessível sem root sob SELinux no Android 9)
    if rx_bytes is None or tx_bytes is None:
        try:
            if os.path.exists("/proc/net/dev"):
                with open("/proc/net/dev", "r") as f:
                    for line in f.readlines()[2:]:
                        if ":" not in line:
                            continue
                        iface_part, stats_part = line.split(":", 1)
                        if iface_part.strip() == interface:
                            fields = stats_part.split()
                            if len(fields) >= 10:
                                rx_bytes = int(fields[0])
                                rx_packets = int(fields[1])
                                tx_bytes = int(fields[8])
                                tx_packets = int(fields[9])
                                source = "/proc/net/dev"
                                break
        except Exception:
            pass

    # 3. Fallback via `ip -s link show <interface>`
    if rx_bytes is None or tx_bytes is None:
        for ip_bin in ["ip", "/data/data/com.termux/files/usr/bin/ip", "/system/bin/ip"]:
            try:
                res = subprocess.run([ip_bin, "-s", "link", "show", interface], capture_output=True, text=True, timeout=2)
                out = res.stdout or ""
                m_rx = re.search(r"RX:\s+bytes\s+packets.*?\n\s*(\d+)\s+(\d+)", out)
                m_tx = re.search(r"TX:\s+bytes\s+packets.*?\n\s*(\d+)\s+(\d+)", out)
                if m_rx and m_tx:
                    rx_bytes = int(m_rx.group(1))
                    rx_packets = int(m_rx.group(2))
                    tx_bytes = int(m_tx.group(1))
                    tx_packets = int(m_tx.group(2))
                    source = "ip -s link"
                    break
            except Exception:
                pass

    if rx_bytes is None or tx_bytes is None:
        return {
            "available": False,
            "interface": interface,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_mb": 0.0,
            "tx_mb": 0.0,
            "rx_rate_kbps": 0.0,
            "tx_rate_kbps": 0.0,
            "note": "Contadores de interface indisponíveis neste ambiente"
        }

    now_t = time.time()
    rx_rate_kbps = 0.0
    tx_rate_kbps = 0.0

    prev = _TRAFFIC_CACHE.get(interface)
    if prev:
        prev_t, prev_rx, prev_tx = prev
        dt = now_t - prev_t
        if dt > 0.2 and rx_bytes >= prev_rx and tx_bytes >= prev_tx:
            rx_rate_kbps = round(((rx_bytes - prev_rx) / 1024.0) / dt, 2)
            tx_rate_kbps = round(((tx_bytes - prev_tx) / 1024.0) / dt, 2)

    _TRAFFIC_CACHE[interface] = (now_t, rx_bytes, tx_bytes)

    return {
        "available": True,
        "interface": interface,
        "source": source,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_packets": rx_packets,
        "tx_packets": tx_packets,
        "rx_mb": round(rx_bytes / (1024.0 * 1024.0), 2),
        "tx_mb": round(tx_bytes / (1024.0 * 1024.0), 2),
        "rx_rate_kbps": rx_rate_kbps,
        "tx_rate_kbps": tx_rate_kbps,
        "note": f"Tráfego real da interface {interface} ({source})"
    }

def is_wifi_interface(iface_name):
    """Valida se a interface corresponde estritamente a uma interface Wi-Fi (wlan*)."""
    return bool(iface_name and str(iface_name).strip().lower().startswith("wlan"))

def get_network_info():
    """
    Descobre a interface de rede ativa, IP local, máscara, gateway padrão e faixa CIDR.
    Proteção Plug-and-Play Wi-Fi: considera `is_connected: True` APENAS quando a
    interface padrão começar com `wlan` (ex.: `wlan0`).
    """
    info = {
        "interface": "desconectado",
        "ip": "127.0.0.1",
        "mac": "N/A",
        "netmask": "255.255.255.0",
        "cidr": 24,
        "network_cidr": "127.0.0.0/24",
        "gateway": None,
        "dns": get_dns_servers(),
        "is_connected": False,
        "status_reason": WIFI_DISCONNECTED_MSG
    }

    detected_iface = None
    detected_gw = None

    for ip_bin in ["ip", "/data/data/com.termux/files/usr/bin/ip", "/system/bin/ip"]:
        try:
            res_get = subprocess.run([ip_bin, "route", "get", "8.8.8.8"], capture_output=True, text=True, timeout=2)
            out = res_get.stdout or ""
            m_dev = re.search(r"\bdev\s+(\S+)", out)
            m_via = re.search(r"\bvia\s+([0-9.]+)", out)
            if m_dev:
                detected_iface = m_dev.group(1)
                if m_via:
                    detected_gw = m_via.group(1)
                break
        except Exception:
            pass

    if not detected_iface:
        for ip_bin in ["ip", "/data/data/com.termux/files/usr/bin/ip", "/system/bin/ip"]:
            try:
                res = subprocess.run([ip_bin, "route", "show", "default"], capture_output=True, text=True, timeout=2)
                out = res.stdout or ""
                match = re.search(r"default\s+via\s+([0-9.]+)\s+dev\s+(\S+)", out)
                if match:
                    detected_gw = match.group(1)
                    detected_iface = match.group(2)
                    break
            except Exception:
                pass

    if not detected_iface:
        try:
            if os.path.exists("/proc/net/route"):
                with open("/proc/net/route", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 3 and parts[1] == "00000000":
                            gw_hex = parts[2]
                            gw_ip = socket.inet_ntoa(bytes.fromhex(gw_hex)[::-1])
                            detected_gw = gw_ip
                            detected_iface = parts[0]
                            break
        except Exception:
            pass

    wlan_addr_entry = None
    for ip_bin in ["ip", "/data/data/com.termux/files/usr/bin/ip", "/system/bin/ip"]:
        try:
            res = subprocess.run([ip_bin, "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=2)
            lines = (res.stdout or "").splitlines()
            if lines:
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        iface = parts[1]
                        inet_idx = parts.index("inet") if "inet" in parts else -1
                        if inet_idx != -1 and inet_idx + 1 < len(parts):
                            cidr_str = parts[inet_idx + 1]
                            if is_wifi_interface(iface):
                                if detected_iface == iface or not detected_iface:
                                    wlan_addr_entry = (iface, cidr_str)
                                    break
                break
        except Exception:
            pass

    if not detected_iface and wlan_addr_entry:
        detected_iface = wlan_addr_entry[0]

    if detected_iface:
        info["interface"] = detected_iface

    if not is_wifi_interface(detected_iface):
        info["is_connected"] = False
        info["status_reason"] = WIFI_DISCONNECTED_MSG
        return info

    if wlan_addr_entry and wlan_addr_entry[0] == detected_iface:
        try:
            net = ipaddress.IPv4Interface(wlan_addr_entry[1])
            local_ip = str(net.ip)
            if local_ip and not local_ip.startswith("127."):
                info["ip"] = local_ip
                info["netmask"] = str(net.netmask)
                info["cidr"] = net.network.prefixlen
                info["network_cidr"] = str(net.network)
                info["is_connected"] = True
        except Exception:
            pass

    if not info["is_connected"]:
        info["status_reason"] = WIFI_DISCONNECTED_MSG
        return info

    if detected_gw and detected_gw != "0.0.0.0":
        info["gateway"] = detected_gw
    else:
        octets = info["ip"].split(".")
        if len(octets) == 4:
            info["gateway"] = f"{octets[0]}.{octets[1]}.{octets[2]}.1"

    info["mac"] = get_interface_mac(detected_iface)
    info["status_reason"] = f"Monitoramento Wi-Fi ativo em {detected_iface} ({info['network_cidr']})"

    return info

if __name__ == "__main__":
    net_info = get_network_info()
    print("=== Descoberta de Rede Local ===")
    for k, v in net_info.items():
        print(f"{k}: {v}")
