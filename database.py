import sqlite3
import os
import ipaddress
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netwatch.db")

SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "INFO": 3
}

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Configurações essenciais para evitar lock em ambientes concorrentes (Android/Termux)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def infer_cidr_from_ip(ip_str):
    """Infere o bloco /24 a partir de um endereço IPv4 para migração de registros legados."""
    try:
        net = ipaddress.IPv4Interface(f"{ip_str}/24")
        return str(net.network)
    except Exception:
        return ""

def record_device_latency(conn, ip, network_cidr, timestamp, latency_ms, status):
    """
    Insere uma amostra na tabela `device_latency_history` e mantém apenas
    os últimos 100 registros por IP para não inflar o banco SQLite.
    """
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO device_latency_history (ip, network_cidr, timestamp, latency_ms, status)
        VALUES (?, ?, ?, ?, ?);
    """, (ip, network_cidr or "", timestamp, latency_ms, status))

    cursor.execute("""
        DELETE FROM device_latency_history
        WHERE ip = ? AND id NOT IN (
            SELECT id FROM device_latency_history
            WHERE ip = ?
            ORDER BY id DESC
            LIMIT 100
        );
    """, (ip, ip))

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Tabela de dispositivos na LAN (com métricas de sessão, OUI, fingerprinting e campos SOC)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        mac TEXT,
        hostname TEXT,
        vendor TEXT,
        status TEXT DEFAULT 'ONLINE',
        open_ports TEXT,
        latency REAL,
        last_seen DATETIME NOT NULL,
        network_cidr TEXT DEFAULT '',
        first_seen TEXT,
        connected_since TEXT,
        total_online_seconds INTEGER DEFAULT 0,
        last_state_change TEXT,
        last_event_type TEXT DEFAULT '',
        disconnections_count INTEGER DEFAULT 0,
        device_type TEXT DEFAULT 'Desconhecido',
        service_details TEXT DEFAULT '[]',
        is_trusted INTEGER DEFAULT 0,
        custom_name TEXT DEFAULT '',
        previous_ports TEXT DEFAULT ''
    );
    """)

    # Migração segura: adiciona colunas caso o banco já exista de versões anteriores
    cursor.execute("PRAGMA table_info(devices);")
    existing_cols = {row["name"] for row in cursor.fetchall()}

    migrations = [
        ("network_cidr", "TEXT DEFAULT ''"),
        ("first_seen", "TEXT"),
        ("connected_since", "TEXT"),
        ("total_online_seconds", "INTEGER DEFAULT 0"),
        ("last_state_change", "TEXT"),
        ("last_event_type", "TEXT DEFAULT ''"),
        ("disconnections_count", "INTEGER DEFAULT 0"),
        ("device_type", "TEXT DEFAULT 'Desconhecido'"),
        ("service_details", "TEXT DEFAULT '[]'"),
        ("is_trusted", "INTEGER DEFAULT 0"),
        ("custom_name", "TEXT DEFAULT ''"),
        ("previous_ports", "TEXT DEFAULT ''")
    ]
    for col_name, col_def in migrations:
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_def};")

    # Preenche network_cidr, timestamps iniciais e previous_ports para eventuais registros legados
    cursor.execute("SELECT id, ip, status, open_ports, last_seen, network_cidr, first_seen, connected_since, previous_ports FROM devices;")
    for row in cursor.fetchall():
        updates = []
        params = []
        if not row["network_cidr"]:
            inferred = infer_cidr_from_ip(row["ip"])
            if inferred:
                updates.append("network_cidr = ?")
                params.append(inferred)
        if not row["first_seen"]:
            updates.append("first_seen = ?")
            params.append(row["last_seen"])
        if row["status"] == "ONLINE" and not row["connected_since"]:
            updates.append("connected_since = ?")
            params.append(row["last_seen"])
        if (row["previous_ports"] is None or row["previous_ports"] == "") and row["open_ports"]:
            updates.append("previous_ports = ?")
            params.append(row["open_ports"])
        if updates:
            params.append(row["id"])
            cursor.execute(f"UPDATE devices SET {', '.join(updates)} WHERE id = ?;", tuple(params))

    # Tabela de histórico de latência por dispositivo (últimos 100 pontos por IP)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_latency_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        network_cidr TEXT DEFAULT '',
        timestamp DATETIME NOT NULL,
        latency_ms REAL,
        status TEXT NOT NULL
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_latency_ip ON device_latency_history(ip, id DESC);")

    # Tabela SOC 1: Baselines por sub-rede (MAC travado do Gateway e trava de dispositivos autorizados)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS soc_network_baselines (
        network_cidr TEXT PRIMARY KEY,
        gateway_ip TEXT,
        gateway_mac TEXT,
        baseline_locked INTEGER DEFAULT 0,
        updated_at TEXT
    );
    """)

    # Tabela SOC 2: Alertas automáticos de segurança (MITRE ATT&CK)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS soc_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        network_cidr TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        mitre_id TEXT NOT NULL,
        target_ip TEXT DEFAULT '',
        target_mac TEXT DEFAULT '',
        title TEXT NOT NULL,
        details TEXT NOT NULL,
        status TEXT DEFAULT 'OPEN'
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_soc_alerts_cidr_status ON soc_alerts(network_cidr, status, id DESC);")

    # Tabela de logs de conectividade externa/gateway
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS connectivity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        gateway_ip TEXT,
        gateway_latency REAL,
        external_latency REAL,
        dns_latency REAL,
        classification TEXT NOT NULL,
        details TEXT
    );
    """)

    # Tabela de serviços monitorados
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS monitored_services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        service_type TEXT NOT NULL,
        status TEXT DEFAULT 'PENDING',
        latency REAL DEFAULT 0.0,
        last_check DATETIME,
        details TEXT
    );
    """)

    # Tabela de eventos e alertas
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL
    );
    """)

    # Seed inicial de serviços monitorados
    cursor.execute("SELECT COUNT(*) FROM monitored_services;")
    if cursor.fetchone()[0] == 0:
        initial_services = [
            ("Cloudflare Public DNS", "1.1.1.1", 53, "DNS", "ONLINE", 0.0, datetime.now().isoformat(), "Servidor DNS primário global"),
            ("Google HTTPS", "www.google.com", 443, "HTTPS", "ONLINE", 0.0, datetime.now().isoformat(), "Gateway de busca e conectividade Web segura"),
            ("Example HTTP", "example.com", 80, "HTTP", "ONLINE", 0.0, datetime.now().isoformat(), "Padrão de validação de HTTP claro")
        ]
        cursor.executemany("""
            INSERT INTO monitored_services (name, host, port, service_type, status, latency, last_check, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, initial_services)

    conn.commit()
    conn.close()

def log_event(event_type, severity, message):
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO events (timestamp, event_type, severity, message)
            VALUES (?, ?, ?, ?)
        """, (datetime.now().isoformat(), event_type, severity, message))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERRO DB] Falha ao registrar evento: {e}")

# ==============================================================================
# FUNÇÕES DE PERSISTÊNCIA E DEDUPLICAÇÃO SOC
# ==============================================================================

def create_soc_alert_dedup(
    network_cidr,
    severity,
    category,
    mitre_id,
    title,
    details,
    target_ip="",
    target_mac="",
    conn=None
):
    """
    Cria um alerta SOC em `soc_alerts` com deduplicação inteligente:
    Se já existir um alerta `status = 'OPEN'` com a mesma `(network_cidr, category, target_ip, title)`,
    atualiza `timestamp`, `details` e `target_mac` sem duplicar linha nem inundar a tabela `events`.
    Retorna `(alert_id, is_new)`.
    """
    own_conn = False
    if conn is None:
        conn = get_db_connection()
        own_conn = True

    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM soc_alerts
        WHERE network_cidr = ?
          AND category = ?
          AND target_ip = ?
          AND title = ?
          AND status = 'OPEN'
        LIMIT 1;
    """, (network_cidr or "", category, target_ip or "", title))
    existing = cursor.fetchone()

    if existing:
        alert_id = existing["id"]
        cursor.execute("""
            UPDATE soc_alerts
            SET timestamp = ?,
                severity = ?,
                mitre_id = ?,
                target_mac = CASE WHEN ? != '' THEN ? ELSE target_mac END,
                details = ?
            WHERE id = ?;
        """, (now_iso, severity, mitre_id, target_mac or "", target_mac or "", details, alert_id))
        if own_conn:
            conn.commit()
            conn.close()
        return alert_id, False

    cursor.execute("""
        INSERT INTO soc_alerts (
            timestamp, network_cidr, severity, category, mitre_id,
            target_ip, target_mac, title, details, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN');
    """, (
        now_iso,
        network_cidr or "",
        severity,
        category,
        mitre_id,
        target_ip or "",
        target_mac or "",
        title,
        details
    ))
    alert_id = cursor.lastrowid

    # Registra também na tabela global de eventos quando o alerta SOC é novo
    ev_sev = "CRITICAL" if severity in ("CRITICAL", "HIGH") else ("WARNING" if severity == "MEDIUM" else "INFO")
    cursor.execute("""
        INSERT INTO events (timestamp, event_type, severity, message)
        VALUES (?, ?, ?, ?);
    """, (now_iso, f"SOC_{category}", ev_sev, f"[{mitre_id}] {title} — {details}"))

    if own_conn:
        conn.commit()
        conn.close()
    return alert_id, True

def get_soc_alerts(conn, network_cidr=None, status=None, target_ip=None, limit=100):
    """Lista alertas SOC filtrados por sub-rede, status ou IP alvo, ordenados por prioridade."""
    cursor = conn.cursor()
    clauses = []
    params = []

    if network_cidr:
        clauses.append("network_cidr = ?")
        params.append(network_cidr)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if target_ip:
        clauses.append("target_ip LIKE ?")
        params.append(f"%{target_ip}%")

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    cursor.execute(f"SELECT * FROM soc_alerts {where_sql} ORDER BY id DESC LIMIT ?;", (*params, int(limit)))
    rows = [dict(r) for r in cursor.fetchall()]

    def alert_sort_key(a):
        st_rank = 0 if a.get("status") == "OPEN" else 1
        sev_rank = SEVERITY_RANK.get(a.get("severity", "INFO"), 9)
        return (st_rank, sev_rank, -int(a.get("id", 0)))

    return sorted(rows, key=alert_sort_key)

def get_open_soc_alert_counts(conn, network_cidr=None):
    """Retorna contagem de alertas `OPEN` por severidade para a sub-rede informada."""
    cursor = conn.cursor()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0, "total_open": 0}
    if network_cidr:
        cursor.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM soc_alerts
            WHERE network_cidr = ? AND status = 'OPEN'
            GROUP BY severity;
        """, (network_cidr,))
    else:
        cursor.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM soc_alerts
            WHERE status = 'OPEN'
            GROUP BY severity;
        """)
    for row in cursor.fetchall():
        sev = (row["severity"] or "INFO").upper()
        c = int(row["cnt"] or 0)
        if sev in counts:
            counts[sev] += c
        counts["total_open"] += c
    return counts

def ack_soc_alert(conn, alert_id):
    """Marca um alerta SOC como reconhecido (`ACK`)."""
    cursor = conn.cursor()
    cursor.execute("UPDATE soc_alerts SET status = 'ACK' WHERE id = ?;", (int(alert_id),))
    changed = cursor.rowcount
    conn.commit()
    return changed > 0

def clear_soc_alerts(conn, network_cidr=None, only_ack=True):
    """Remove alertas reconhecidos (ou todos) da sub-rede."""
    cursor = conn.cursor()
    if network_cidr and only_ack:
        cursor.execute("DELETE FROM soc_alerts WHERE network_cidr = ? AND status = 'ACK';", (network_cidr,))
    elif network_cidr:
        cursor.execute("DELETE FROM soc_alerts WHERE network_cidr = ?;", (network_cidr,))
    elif only_ack:
        cursor.execute("DELETE FROM soc_alerts WHERE status = 'ACK';")
    else:
        cursor.execute("DELETE FROM soc_alerts;")
    removed = cursor.rowcount
    conn.commit()
    return removed

if __name__ == "__main__":
    init_db()
    print("Banco de dados SQLite inicializado com sucesso em modo WAL:", DB_PATH)
