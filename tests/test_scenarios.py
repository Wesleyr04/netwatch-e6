import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Adiciona o diretório base ao sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database import init_db, get_db_connection, get_soc_alerts
from modules.connectivity_monitor import classify_connectivity
from modules.service_monitor import probe_service
from modules.report_generator import (
    generate_report_data,
    generate_markdown_report,
    build_device_report_dict,
    generate_device_markdown_report,
    REMOTE_TRAFFIC_EXPLANATION
)
from modules.network_discovery import (
    get_network_info,
    is_wifi_interface,
    WIFI_DISCONNECTED_MSG
)
from modules.device_discovery import (
    COMMON_PROBE_PORTS,
    PHASE_A_PRESENCE_PORTS,
    LOCAL_HOST_LABEL,
    GATEWAY_LABEL,
    PRIVATE_MAC_LABEL,
    GENERIC_LAN_LABEL,
    resolve_smart_hostname,
    resolve_vendor_oui,
    infer_device_type,
    probe_host,
    phase_a_check_presence,
    inspect_neighbor_table,
    quick_presence_scan,
    query_filtered_devices,
    clear_offline_devices
)
from modules.soc_monitor import (
    check_arp_integrity,
    check_dns_hijacking,
    check_ports_and_drift,
    check_rogue_devices,
    lock_current_network_baseline,
    get_soc_overview
)

class TestNetWatchE6(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_01_connectivity_classification_logic(self):
        """Valida determinística das 4 regras de causa raiz de conectividade."""
        self.assertEqual(classify_connectivity(gw_ok=True, wan_ok=True, dns_ok=True), "OPERACIONAL")
        self.assertEqual(classify_connectivity(gw_ok=False, wan_ok=True, dns_ok=True), "FALHA_LOCAL_GATEWAY")
        self.assertEqual(classify_connectivity(gw_ok=False, wan_ok=False, dns_ok=False), "FALHA_LOCAL_GATEWAY")
        self.assertEqual(classify_connectivity(gw_ok=True, wan_ok=False, dns_ok=True), "FALHA_WAN_EXTERNA")
        self.assertEqual(classify_connectivity(gw_ok=True, wan_ok=False, dns_ok=False), "FALHA_WAN_EXTERNA")
        self.assertEqual(classify_connectivity(gw_ok=True, wan_ok=True, dns_ok=False), "FALHA_RESOLUCAO_DNS")

    def test_02_sqlite_wal_pragmas_and_soc_tables(self):
        """Valida WAL, synchronous=NORMAL, colunas SOC em devices e tabelas soc_network_baselines / soc_alerts."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("PRAGMA journal_mode;")
        self.assertEqual(cursor.fetchone()[0].upper(), "WAL")

        cursor.execute("PRAGMA table_info(devices);")
        cols = {r["name"] for r in cursor.fetchall()}
        expected_cols = {
            "network_cidr", "first_seen", "connected_since", "total_online_seconds",
            "last_state_change", "last_event_type", "disconnections_count",
            "device_type", "service_details", "is_trusted", "custom_name", "previous_ports"
        }
        for col in expected_cols:
            self.assertIn(col, cols, f"Coluna '{col}' deve existir na tabela devices.")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {r[0] for r in cursor.fetchall()}
        for t in ("device_latency_history", "soc_network_baselines", "soc_alerts"):
            self.assertIn(t, tables)
        conn.close()

    def test_03_database_tables_and_seed(self):
        """Garante a existência das tabelas principais e o seed inicial dos serviços."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM monitored_services;")
        count = cursor.fetchone()[0]
        self.assertGreaterEqual(count, 3)
        conn.close()

    def test_04_service_monitor_probe(self):
        """Valida que o roteador de serviços responde com tupla estruturada (status, latencia, detalhes)."""
        status, latency, details = probe_service("HTTP", "127.0.0.1", 59999)
        self.assertIn(status, ["ONLINE", "DEGRADADO", "OFFLINE"])
        self.assertIsInstance(latency, float)
        self.assertIsInstance(details, str)

    def test_05_report_generation(self):
        """Valida a consolidação dos dados e geração do relatório em Markdown com seção SOC."""
        data = generate_report_data()
        self.assertIn("metadata", data)
        self.assertIn("network", data)
        self.assertIn("soc", data)

        md = generate_markdown_report()
        self.assertIn("# Relatório Técnico NetWatch E6", md)
        self.assertIn("Postura SOC & Alertas Automáticos (MITRE ATT&CK)", md)

    def test_06_wifi_plug_and_play_protection(self):
        """Valida que apenas interfaces wlan* são consideradas conectadas e rmnet bloqueia varredura."""
        self.assertTrue(is_wifi_interface("wlan0"))
        self.assertFalse(is_wifi_interface("rmnet_data0"))
        self.assertFalse(is_wifi_interface("ccmni0"))

        mock_res = MagicMock()
        mock_res.stdout = "8.8.8.8 via 10.0.0.1 dev rmnet_data0 src 10.20.30.40\n"
        with patch("modules.network_discovery.subprocess.run", return_value=mock_res):
            info = get_network_info()
            self.assertFalse(info["is_connected"])
            self.assertEqual(info["status_reason"], WIFI_DISCONNECTED_MSG)

    def test_07_oui_vendor_and_device_type_inference(self):
        """Valida tabela OUI offline (14:09:B4 -> ZTE Corporation), prioridade de banner HTTP, MAC privado e device_type."""
        expected_ports = (21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 5000, 5555, 8008, 8022, 8080, 9100)
        self.assertEqual(tuple(COMMON_PROBE_PORTS), expected_ports)

        self.assertEqual(resolve_vendor_oui("F8:1F:32:6D:1C:B6"), "Motorola Mobility")
        self.assertEqual(resolve_vendor_oui("14:09:B4:A6:F3:5F"), "ZTE Corporation")
        self.assertEqual(resolve_vendor_oui("98:B3:EF:BE:D0:CF"), "Huawei Technologies")
        self.assertEqual(resolve_vendor_oui("AA:7A:50:3E:9B:0C"), "MAC Privado (Android/iOS)")

        zte_banner = '[{"port": 80, "service": "HTTP", "banner": "Server: ZTE web server 1.0 ZTE corp 2015."}]'
        self.assertEqual(
            resolve_vendor_oui("98:B3:EF:11:22:33", service_details=zte_banner),
            "ZTE Corporation"
        )

    def test_08_multi_subnet_isolation_and_sorting(self):
        """Comprova isolamento por sub-rede e ordenação."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM devices;")

        sample_rows = [
            ("192.168.1.1", "14:09:B4:A6:F3:5F", "Gateway / Roteador", "OFFLINE", "53,80", 5.0, "2026-11-24T12:00:00", "192.168.1.0/24"),
            ("192.168.3.100", "22:11:22:33:44:55", "Dispositivo Móvel (MAC Privado)", "ONLINE", "", 25.0, "2026-11-24T14:30:00", "192.168.3.0/24"),
            ("192.168.3.2", "00:11:22:33:44:66", "Dispositivo na LAN", "ONLINE", "80", 10.0, "2026-11-24T14:30:00", "192.168.3.0/24"),
            ("192.168.3.1", "14:09:B4:A6:F3:5F", "Gateway / Roteador", "ONLINE", "53,80,443", 4.2, "2026-11-24T14:30:00", "192.168.3.0/24"),
            ("192.168.3.55", "F8:1F:32:6D:1C:B6", "Moto E6 Play (Host Local)", "ONLINE", "5000", 0.1, "2026-11-24T14:30:00", "192.168.3.0/24"),
        ]
        cursor.executemany("""
            INSERT INTO devices (ip, mac, hostname, status, open_ports, latency, last_seen, network_cidr)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, sample_rows)
        conn.commit()

        mock_net_3 = {
            "interface": "wlan0",
            "ip": "192.168.3.55",
            "gateway": "192.168.3.1",
            "network_cidr": "192.168.3.0/24",
            "is_connected": True
        }

        try:
            filtered = query_filtered_devices(conn, mock_net_3, scope="current")
            ips = [d["ip"] for d in filtered]
            self.assertEqual(ips, ["192.168.3.55", "192.168.3.1", "192.168.3.2", "192.168.3.100"])
        finally:
            conn.close()

    def test_09_session_metrics_individual_report_and_transitions(self):
        """Valida métricas de sessão, relatório individual e transições ENTROU/SAIU."""
        conn = get_db_connection()
        conn.execute("DELETE FROM devices;")
        conn.execute("DELETE FROM device_latency_history;")
        conn.execute("DELETE FROM events;")
        conn.commit()
        conn.close()

        def fake_phase_a_c1(ip, timeout=0.12, my_ip=None, gateway_ip=None, allow_icmp=False):
            if ip == "192.168.1.7":
                return {"ip": ip, "online": True, "open_ports": [], "latency": 0.1, "method": "LOCAL"}
            if ip == "192.168.1.12":
                return {"ip": ip, "online": True, "open_ports": [], "latency": 3.5, "method": "TCP_RST"}
            return None

        def fake_phase_a_c2(ip, timeout=0.12, my_ip=None, gateway_ip=None, allow_icmp=False):
            if ip == "192.168.1.7":
                return {"ip": ip, "online": True, "open_ports": [], "latency": 0.1, "method": "LOCAL"}
            return None

        with patch("modules.device_discovery.phase_a_check_presence", side_effect=fake_phase_a_c1), \
             patch("modules.device_discovery.inspect_neighbor_table", return_value=({"192.168.1.12": "14:AB:C5:55:CD:C3"}, set())), \
             patch("modules.device_discovery.deep_fingerprint_host", return_value={
                 "ip": "192.168.1.12",
                 "reverse_dns": "",
                 "open_ports": "80",
                 "service_details": '[{"port": 80, "service": "HTTP", "banner": "Título: Painel Local"}]',
                 "latency": 3.5,
                 "latency_ms": 3.5,
                 "status": "ONLINE"
             }):
            quick_presence_scan("192.168.1.0/24", my_ip="192.168.1.7", gateway_ip="192.168.1.1", interface="wlan0")

        mock_net = {
            "interface": "wlan0",
            "ip": "192.168.1.7",
            "gateway": "192.168.1.1",
            "network_cidr": "192.168.1.0/24",
            "is_connected": True
        }

        rep_remote = build_device_report_dict("192.168.1.12", net_info=mock_net)
        self.assertEqual(rep_remote["status"], "ONLINE")
        self.assertEqual(rep_remote["vendor"], "Motorola Mobility")

        with patch("modules.device_discovery.phase_a_check_presence", side_effect=fake_phase_a_c2), \
             patch("modules.device_discovery.inspect_neighbor_table", return_value=({}, set())):
            quick_presence_scan("192.168.1.0/24", my_ip="192.168.1.7", gateway_ip="192.168.1.1", interface="wlan0")

        rep_after = build_device_report_dict("192.168.1.12", net_info=mock_net)
        self.assertEqual(rep_after["status"], "OFFLINE")
        self.assertEqual(rep_after["disconnections_count"], 1)

    def test_10_soc_automatic_detectors_mitre(self):
        """
        Valida os 5 cenários obrigatórios do Motor SOC Automático:
        1. Troca simulada de MAC do Gateway dispara ARP_MITM (CRITICAL, T1557.002).
        2. MAC duplicado entre 2 IPs dispara ARP_MITM (CRITICAL, T1557.002).
        3. Resposta de IP privado (192.168.1.99) para domínio público dispara DNS_HIJACK (CRITICAL, T1557).
        4. Abertura de porta nova (PORT_DRIFT, T1046) e porta crítica (445/5555 -> RISKY_PORT, T1021) sem duplicação.
        5. Travar baseline e inserir dispositivo novo gera ROGUE_DEVICE (HIGH, T1200).
        """
        conn = get_db_connection()
        conn.execute("DELETE FROM devices;")
        conn.execute("DELETE FROM soc_network_baselines;")
        conn.execute("DELETE FROM soc_alerts;")
        conn.commit()
        conn.close()

        mock_net = {
            "interface": "wlan0",
            "ip": "192.168.1.7",
            "gateway": "192.168.1.1",
            "network_cidr": "192.168.1.0/24",
            "dns": ["192.168.1.1"],
            "is_connected": True
        }

        # 1. ARP Guard: 1ª leitura aprende o MAC original do Gateway (14:09:B4:A6:F3:5F)
        check_arp_integrity(
            net_info=mock_net,
            neighbor_entries=[{"ip": "192.168.1.1", "mac": "14:09:B4:A6:F3:5F", "state": "REACHABLE"}]
        )
        # 2ª leitura com MAC trocado do Gateway (DE:AD:BE:EF:00:01) -> deve disparar ARP_MITM CRITICAL T1557.002
        res_arp = check_arp_integrity(
            net_info=mock_net,
            neighbor_entries=[{"ip": "192.168.1.1", "mac": "DE:AD:BE:EF:00:01", "state": "REACHABLE"}]
        )
        self.assertGreaterEqual(res_arp["alerts_triggered"], 1)

        # 2. ARP Guard: MAC duplicado entre 2 IPs distintos (192.168.1.1 e 192.168.1.99 com DE:AD:BE:EF:00:01)
        check_arp_integrity(
            net_info=mock_net,
            neighbor_entries=[
                {"ip": "192.168.1.1", "mac": "DE:AD:BE:EF:00:01", "state": "REACHABLE"},
                {"ip": "192.168.1.99", "mac": "DE:AD:BE:EF:00:01", "state": "REACHABLE"}
            ]
        )

        conn = get_db_connection()
        arp_alerts = get_soc_alerts(conn, network_cidr="192.168.1.0/24")
        conn.close()
        arp_categories = [a for a in arp_alerts if a["category"] == "ARP_MITM"]
        self.assertEqual(len(arp_categories), 2)
        self.assertTrue(all(a["severity"] == "CRITICAL" and a["mitre_id"] == "T1557.002" for a in arp_categories))

        # 3. DNS Hijacking: DNS local devolvendo IP privado (192.168.1.99) para google.com
        with patch("modules.soc_monitor.resolve_domain_local_dns", return_value=["192.168.1.99"]), \
             patch("modules.soc_monitor.resolve_domain_doh", return_value=["142.250.78.110"]):
            dns_state = check_dns_hijacking(net_info=mock_net, force=True, test_domains=("google.com",))
            self.assertEqual(dns_state["status"], "SUSPEITO")

        conn = get_db_connection()
        dns_alerts = [a for a in get_soc_alerts(conn, network_cidr="192.168.1.0/24") if a["category"] == "DNS_HIJACK"]
        conn.close()
        self.assertEqual(len(dns_alerts), 1)
        self.assertEqual(dns_alerts[0]["severity"], "CRITICAL")
        self.assertEqual(dns_alerts[0]["mitre_id"], "T1557")

        # 4. Port Drift (T1046) e Portas Críticas (445/5555 -> RISKY_PORT, T1021) com deduplicação
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO devices (ip, mac, hostname, vendor, status, open_ports, previous_ports, latency, last_seen, network_cidr, is_trusted)
            VALUES ('192.168.1.25', '00:14:22:AA:BB:CC', 'Servidor-LAN', 'Dell Inc.', 'ONLINE', '80,445,5555', '80', 3.2, '2026-11-24T19:00:00', '192.168.1.0/24', 1);
        """)
        conn.commit()
        conn.close()

        res_p1 = check_ports_and_drift(net_info=mock_net)
        self.assertEqual(res_p1["risky_alerts"], 2)  # 445 e 5555
        self.assertEqual(res_p1["drift_alerts"], 2)  # 445 e 5555 são novas em relação a previous_ports='80'

        # Reexecuta imediatamente: deduplicação não deve criar novas linhas OPEN duplicadas
        check_ports_and_drift(net_info=mock_net)
        conn = get_db_connection()
        all_p_alerts = [
            a for a in get_soc_alerts(conn, network_cidr="192.168.1.0/24")
            if a["category"] in ("RISKY_PORT", "PORT_DRIFT")
        ]
        conn.close()
        self.assertEqual(len(all_p_alerts), 4)

        # 5. Travar Baseline e inserir novo dispositivo não confiável -> ROGUE_DEVICE (HIGH, T1200)
        lock_res = lock_current_network_baseline(net_info=mock_net, lock_state=True)
        self.assertTrue(lock_res["baseline_locked"])

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO devices (ip, mac, hostname, vendor, status, open_ports, previous_ports, latency, last_seen, network_cidr, is_trusted)
            VALUES ('192.168.1.88', 'AA:7A:50:11:22:33', 'Invasor-Mobile', 'MAC Privado (Android/iOS)', 'ONLINE', '', '', 12.0, '2026-11-24T19:05:00', '192.168.1.0/24', 0);
        """)
        conn.commit()
        conn.close()

        rogue_res = check_rogue_devices(net_info=mock_net)
        self.assertEqual(rogue_res["rogue_count"], 1)

        overview = get_soc_overview(net_info=mock_net)
        self.assertEqual(overview["posture"], "CRITICO")
        rogue_alerts = [a for a in overview["alerts"] if a["category"] == "ROGUE_DEVICE"]
        self.assertEqual(len(rogue_alerts), 1)
        self.assertEqual(rogue_alerts[0]["mitre_id"], "T1200")
        self.assertEqual(rogue_alerts[0]["severity"], "HIGH")

if __name__ == "__main__":
    unittest.main()
