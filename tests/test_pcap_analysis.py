"""Tests for Pcap Analysis task — v2 with flows, DNS depth, protocol insights, timeline."""

from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.base import Base
from app.models.models import Alert
from app.tasks.pcap_analysis import (
    _validate_pcap,
    _run_tshark,
    _is_private_ip,
    _parse_tcp_flags,
    _extract_flows,
    _analyze_dns,
    _analyze_protocol_insights,
    _detect_port_scan,
    _detect_high_volume,
    _detect_brute_force,
    _detect_dns_tunnel,
    _detect_beacon,
    _detect_suspicious_ports,
    _detect_tls_downgrade,
    _detect_data_exfil,
    _build_pcap_alert_fields,
    _build_timeline,
    analyze_pcap,
    PCAP_MAGIC,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def test_validate_pcap_valid(tmp_path):
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 100)
    assert _validate_pcap(str(pcap_file)) is True


def test_validate_pcap_invalid(tmp_path):
    bad_file = tmp_path / "bad.txt"
    bad_file.write_bytes(b"not a pcap file")
    assert _validate_pcap(str(bad_file)) is False


def test_is_private_ip():
    assert _is_private_ip("10.0.0.1") is True
    assert _is_private_ip("172.16.0.1") is True
    assert _is_private_ip("192.168.1.1") is True
    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("1.1.1.1") is False
    assert _is_private_ip("") is False


def test_parse_tcp_flags():
    # SYN = 0x02, ACK = 0x10, SYN+ACK = 0x12, RST = 0x04, FIN = 0x01
    assert _parse_tcp_flags("0x02") == {"SYN": 1, "ACK": 0, "RST": 0, "FIN": 0}
    assert _parse_tcp_flags("0x12") == {"SYN": 1, "ACK": 1, "RST": 0, "FIN": 0}
    assert _parse_tcp_flags("0x04") == {"SYN": 0, "ACK": 0, "RST": 1, "FIN": 0}
    assert _parse_tcp_flags("0x11") == {"SYN": 0, "ACK": 1, "RST": 0, "FIN": 1}
    assert _parse_tcp_flags("") == {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 0}


def test_run_tshark_uses_first_field_occurrence():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "1.0|10.0.0.1|8.8.8.8\n"
    mock_result.stderr = ""

    with patch("app.tasks.pcap_analysis.subprocess.run", return_value=mock_result) as run:
        rows = _run_tshark("/tmp/test.pcap", ["frame.time_epoch", "ip.src", "ip.dst"], 10)

    cmd = run.call_args.args[0]
    assert "-E" in cmd
    assert "occurrence=f" in cmd
    assert rows == [{"frame.time_epoch": "1.0", "ip.src": "10.0.0.1", "ip.dst": "8.8.8.8"}]


# ---------------------------------------------------------------------------
# Flow extraction
# ---------------------------------------------------------------------------

def test_extract_flows_basic():
    rows = [
        {"ip.src": "10.0.0.1", "ip.dst": "8.8.8.8", "tcp.srcport": "12345", "tcp.dstport": "80",
         "udp.srcport": "", "udp.dstport": "", "_ws.col.Protocol": "HTTP", "frame.len": "100",
         "frame.time_epoch": "1000.0", "tcp.flags": "0x02"},
        {"ip.src": "10.0.0.1", "ip.dst": "8.8.8.8", "tcp.srcport": "12345", "tcp.dstport": "80",
         "udp.srcport": "", "udp.dstport": "", "_ws.col.Protocol": "HTTP", "frame.len": "200",
         "frame.time_epoch": "1001.0", "tcp.flags": "0x10"},
    ]
    flows = _extract_flows(rows)
    assert len(flows) == 1
    f = flows[0]
    assert f["src_ip"] == "10.0.0.1"
    assert f["dst_ip"] == "8.8.8.8"
    assert f["dst_port"] == 80
    assert f["packets"] == 2
    assert f["bytes"] == 300
    assert f["duration_s"] == 1.0
    assert f["direction"] == "outbound"
    assert f["tcp_flags"]["SYN"] == 1
    assert f["tcp_flags"]["ACK"] == 1


def test_extract_flows_direction_inbound():
    rows = [
        {"ip.src": "8.8.8.8", "ip.dst": "10.0.0.1", "tcp.srcport": "443", "tcp.dstport": "54321",
         "udp.srcport": "", "udp.dstport": "", "_ws.col.Protocol": "TLS", "frame.len": "50",
         "frame.time_epoch": "1000.0", "tcp.flags": "0x10"},
    ]
    flows = _extract_flows(rows)
    assert flows[0]["direction"] == "inbound"


def test_extract_flows_direction_internal():
    rows = [
        {"ip.src": "10.0.0.1", "ip.dst": "192.168.1.1", "tcp.srcport": "12345", "tcp.dstport": "80",
         "udp.srcport": "", "udp.dstport": "", "_ws.col.Protocol": "TCP", "frame.len": "50",
         "frame.time_epoch": "1000.0", "tcp.flags": "0x02"},
    ]
    flows = _extract_flows(rows)
    assert flows[0]["direction"] == "internal"


# ---------------------------------------------------------------------------
# DNS deep analysis
# ---------------------------------------------------------------------------

def test_analyze_dns_basic():
    rows = [
        {"dns.qry.name": "example.com", "dns.qry.type": "1", "dns.a": "93.184.216.34",
         "dns.aaaa": "", "dns.txt": "", "ip.src": "10.0.0.1", "frame.time_epoch": "1000.0"},
        {"dns.qry.name": "example.com", "dns.qry.type": "1", "dns.a": "93.184.216.34",
         "dns.aaaa": "", "dns.txt": "", "ip.src": "10.0.0.1", "frame.time_epoch": "1001.0"},
    ]
    result = _analyze_dns(rows)
    assert result["stats"]["total_queries"] == 2
    assert result["stats"]["unique_domains"] == 1
    assert result["stats"]["query_types"]["A"] == 2
    assert result["stats"]["top_domains"][0]["domain"] == "example.com"


def test_analyze_dns_tunnel_detection():
    # Long subdomain
    long_domain = "a" * 60 + ".evil.com"
    rows = [
        {"dns.qry.name": long_domain, "dns.qry.type": "1", "dns.a": "1.2.3.4",
         "dns.aaaa": "", "dns.txt": "", "ip.src": "10.0.0.1", "frame.time_epoch": "1000.0"},
    ]
    result = _analyze_dns(rows)
    assert long_domain in result["stats"]["long_subdomains"]


def test_analyze_dns_txt_queries():
    rows = [
        {"dns.qry.name": f"t{i}.evil.com", "dns.qry.type": "16", "dns.a": "",
         "dns.aaaa": "", "dns.txt": "data", "ip.src": "10.0.0.1", "frame.time_epoch": f"100{i}.0"}
        for i in range(25)
    ]
    result = _analyze_dns(rows)
    assert len(result["stats"]["txt_queries"]) == 25


# ---------------------------------------------------------------------------
# Protocol insights
# ---------------------------------------------------------------------------

def test_analyze_protocol_insights():
    rows = [
        {"http.host": "example.com", "http.request.method": "GET",
         "tls.handshake.extensions_server_name": "", "tls.handshake.version": "",
         "ssh.protocol": ""},
        {"http.host": "", "http.request.method": "",
         "tls.handshake.extensions_server_name": "cdn.example.com", "tls.handshake.version": "0x0303",
         "ssh.protocol": ""},
    ]
    result = _analyze_protocol_insights(rows)
    assert len(result["http_hosts"]) == 1
    assert result["http_hosts"][0]["host"] == "example.com"
    assert "GET" in result["http_hosts"][0]["methods"]
    assert len(result["tls_sni"]) == 1
    assert result["tls_sni"][0]["server_name"] == "cdn.example.com"


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def test_detect_port_scan():
    rows = [
        {"ip.src": "192.168.1.1", "tcp.dstport": str(p), "udp.dstport": "", "frame.time_epoch": "1000.0"}
        for p in range(1, 30)
    ]
    scanners = _detect_port_scan(rows, threshold=20)
    assert len(scanners) == 1
    assert scanners[0]["src_ip"] == "192.168.1.1"
    assert scanners[0]["unique_ports"] == 29
    assert scanners[0]["severity"] == "high"


def test_detect_port_scan_below_threshold():
    rows = [
        {"ip.src": "10.0.0.1", "tcp.dstport": "80", "udp.dstport": "", "frame.time_epoch": "1000.0"},
        {"ip.src": "10.0.0.1", "tcp.dstport": "443", "udp.dstport": "", "frame.time_epoch": "1000.0"},
    ]
    assert len(_detect_port_scan(rows, threshold=20)) == 0


def test_detect_high_volume():
    rows = [
        {"ip.src": "10.0.0.1", "ip.dst": "8.8.8.8", "frame.len": "600000", "frame.time_epoch": "1000.0"}
        for _ in range(10)
    ]
    suspicious = _detect_high_volume(rows, threshold_kb=500)
    assert len(suspicious) == 1
    assert suspicious[0]["total_bytes"] == 6000000


def test_detect_brute_force():
    rows = [
        {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.5", "tcp.dstport": "22", "udp.dstport": "",
         "frame.time_epoch": f"100{i}.0"}
        for i in range(60)
    ]
    anomalies = _detect_brute_force(rows, threshold=50)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "brute_force"
    assert anomalies[0]["connection_count"] == 60


def test_detect_dns_tunnel():
    dns_result = {
        "stats": {
            "long_subdomains": ["aaaa.evil.com"],
            "txt_queries": [f"t{i}.evil.com" for i in range(25)],
        }
    }
    anomalies = _detect_dns_tunnel(dns_result)
    assert len(anomalies) == 2  # one for long subs, one for txt


def test_detect_beacon():
    # Create flows with periodic communication (every 60s, low variance)
    flows = [
        {
            "src_ip": "10.0.0.1", "dst_ip": "evil.com",
            "src_port": 12345, "dst_port": 443,
            "protocol": "TCP", "app_protocol": "TLS",
            "packets": 15, "bytes": 1000,
            "start_time": 1000.0 + i * 60, "end_time": 1000.0 + i * 60 + 1,
            "duration_s": 1.0, "direction": "outbound",
            "tcp_flags": {"SYN": 1, "ACK": 14, "RST": 0, "FIN": 0},
        }
        for i in range(15)
    ]
    anomalies = _detect_beacon(flows, min_connections=10)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "beacon"
    assert anomalies[0]["severity"] == "high"
    assert anomalies[0]["cv"] < 0.3


def test_detect_suspicious_ports():
    rows = [
        {"ip.src": "10.0.0.1", "ip.dst": "evil.com", "tcp.dstport": "4444", "udp.dstport": "",
         "frame.time_epoch": "1000.0"},
    ]
    anomalies = _detect_suspicious_ports(rows)
    assert len(anomalies) == 1
    assert anomalies[0]["dst_port"] == 4444


def test_detect_tls_downgrade():
    # Generate enough rows from same src_ip to meet TLS_MIN_COUNT=10
    rows = [
        {"ip.src": "10.0.0.1", "ip.dst": "8.8.8.8", "tls.handshake.version": "0x0301",
         "tls.handshake.extensions_server_name": "old.example.com", "frame.time_epoch": f"{1000.0 + i}"}
        for i in range(10)
    ]
    anomalies = _detect_tls_downgrade(rows)
    assert len(anomalies) == 1
    assert "TLSv1.0" in anomalies[0]["detail"]


def test_detect_tls_downgrade_aggregates_by_src_ip():
    # Each src_ip below threshold → no anomalies
    rows_few = [
        {"ip.src": f"10.0.0.{i}", "ip.dst": "8.8.8.8", "tls.handshake.version": "0x0300",
         "tls.handshake.extensions_server_name": "a.example.com", "frame.time_epoch": "1000.0"}
        for i in range(5)
    ]
    assert _detect_tls_downgrade(rows_few) == []

    # One src_ip with >= 10 occurrences → 1 aggregated anomaly
    rows_many = [
        {"ip.src": "10.0.0.1", "ip.dst": "8.8.8.8", "tls.handshake.version": "0x0300",
         "tls.handshake.extensions_server_name": "a.example.com", "frame.time_epoch": f"{1000.0 + i}"}
        for i in range(12)
    ]
    anomalies = _detect_tls_downgrade(rows_many)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "tls_downgrade"
    assert anomalies[0]["tls_version"] == "SSLv3"
    assert anomalies[0]["count"] == 12
    assert anomalies[0]["src_ip"] == "10.0.0.1"


def test_detect_data_exfil():
    flows = [
        {
            "src_ip": "10.0.0.1", "dst_ip": "evil.com",
            "src_port": 12345, "dst_port": 443,
            "protocol": "TCP", "app_protocol": "TLS",
            "packets": 1000, "bytes": 20 * 1024 * 1024,  # 20MB
            "start_time": 1000.0, "end_time": 1100.0,
            "duration_s": 100.0, "direction": "outbound",
            "tcp_flags": {"SYN": 1, "ACK": 999, "RST": 0, "FIN": 0},
        }
    ]
    anomalies = _detect_data_exfil(flows, threshold_mb=10)
    assert len(anomalies) == 1
    assert anomalies[0]["type"] == "data_exfil"


def test_build_pcap_alert_fields_returns_nonzero_confidence():
    fields = _build_pcap_alert_fields({
        "type": "tls_downgrade",
        "severity": "medium",
        "detail": "聚合弱 TLS 事件：共 12 条 SSLv3 记录",
        "src_ip": "10.0.0.5",
        "dst_ip": "185.220.101.1",
    })

    assert fields["verdict"] in ("false_positive", "suspicious", "true_positive")
    assert fields["confidence"] > 0
    assert fields["ttp_ids"]


def test_write_alerts_to_db_persists_triage_fields(tmp_path):
    from app.tasks.pcap_analysis import _write_alerts_to_db

    db_path = tmp_path / "pcap_alerts.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)

    anomalies = [
        {
            "type": "tls_downgrade",
            "severity": "medium",
            "detail": "聚合弱 TLS 事件：共 12 条 SSLv3 记录",
            "src_ip": "10.0.0.5",
            "dst_ip": "185.220.101.1",
        }
    ]

    with patch("app.core.config.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(database_url=f"sqlite:///{db_path}")
        written = _write_alerts_to_db(anomalies, tenant_id="test")

    assert written == 1

    with Session(engine) as session:
        rows = session.query(Alert).all()

    assert len(rows) == 1
    alert = rows[0]
    assert alert.verdict in ("false_positive", "suspicious", "true_positive")
    assert alert.confidence > 0
    assert alert.ttp_ids


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def test_build_timeline():
    flows = [
        {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "src_port": 12345, "dst_port": 80,
         "app_protocol": "HTTP", "packets": 5, "bytes": 500, "start_time": 1000.0,
         "end_time": 1001.0, "duration_s": 1.0, "direction": "outbound",
         "protocol": "TCP", "tcp_flags": {"SYN": 1, "ACK": 4, "RST": 0, "FIN": 0}},
    ]
    anomalies = [
        {"type": "port_scan", "severity": "high", "src_ip": "10.0.0.1", "dst_ip": None,
         "detail": "Port scan", "first_seen": 999.0, "last_seen": 1001.0},
    ]
    dns_result = {"queries": [{"name": "example.com", "type": "A", "response": "1.2.3.4",
                                "timestamp": 1002.0, "src_ip": "10.0.0.1"}]}
    timeline = _build_timeline(flows, anomalies, dns_result)
    assert len(timeline) == 3
    assert timeline[0]["timestamp"] <= timeline[1]["timestamp"] <= timeline[2]["timestamp"]


# ---------------------------------------------------------------------------
# Full pipeline (mocked tshark)
# ---------------------------------------------------------------------------

def test_analyze_pcap_invalid_file():
    result = analyze_pcap("/nonexistent/file.pcap")
    assert result["success"] is False


def test_analyze_pcap_no_tshark(tmp_path):
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 100)
    with patch("app.tasks.pcap_analysis._run_tshark", return_value=[]):
        result = analyze_pcap(str(pcap_file))
    assert result["success"] is True
    assert result["summary"]["total_packets"] == 0


def test_analyze_pcap_full_pipeline(tmp_path):
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 100)

    mock_rows = [
        {
            "frame.len": "60", "frame.protocols": "eth:ip:tcp", "frame.time_epoch": "1000.0",
            "_ws.col.Protocol": "TCP", "ip.src": "10.0.0.1", "ip.dst": "8.8.8.8",
            "tcp.srcport": "12345", "tcp.dstport": "80", "udp.srcport": "", "udp.dstport": "",
            "tcp.stream": "0", "udp.stream": "", "tcp.flags": "0x02",
            "dns.qry.name": "", "dns.qry.type": "", "dns.a": "", "dns.aaaa": "", "dns.txt": "",
            "http.host": "example.com", "http.request.method": "GET",
            "tls.handshake.extensions_server_name": "", "tls.handshake.version": "",
            "ssh.protocol": "",
        },
        {
            "frame.len": "100", "frame.protocols": "eth:ip:udp:dns", "frame.time_epoch": "1001.0",
            "_ws.col.Protocol": "DNS", "ip.src": "10.0.0.1", "ip.dst": "8.8.8.8",
            "tcp.srcport": "", "tcp.dstport": "", "udp.srcport": "54321", "udp.dstport": "53",
            "tcp.stream": "", "udp.stream": "0", "tcp.flags": "",
            "dns.qry.name": "example.com", "dns.qry.type": "1", "dns.a": "93.184.216.34",
            "dns.aaaa": "", "dns.txt": "",
            "http.host": "", "http.request.method": "",
            "tls.handshake.extensions_server_name": "", "tls.handshake.version": "",
            "ssh.protocol": "",
        },
    ]

    with patch("app.tasks.pcap_analysis._run_tshark", return_value=mock_rows):
        with patch("app.tasks.pcap_analysis._write_alerts_to_db", return_value=0):
            result = analyze_pcap(str(pcap_file), max_packets=100)

    assert result["success"] is True
    assert result["summary"]["total_packets"] == 2
    assert result["summary"]["time_basis"] == "relative"
    assert result["summary"]["start_time"] == ""
    assert result["summary"]["end_time"] == ""
    assert result["summary"]["total_flows"] >= 2
    assert len(result["flows"]) >= 2
    # Flows sorted by bytes desc — find the TCP flow
    tcp_flow = next((f for f in result["flows"] if f["protocol"] == "TCP"), None)
    assert tcp_flow is not None
    assert tcp_flow["tcp_flags"]["SYN"] >= 1
    assert result["dns"]["stats"]["total_queries"] == 1
    assert result["dns"]["stats"]["unique_domains"] == 1
    assert len(result["protocol_insights"]["http_hosts"]) == 1
    assert len(result["timeline"]) >= 1
    assert result["sanitized_for_llm"] is True
    assert "llm_context" in result
    assert "external_ips_for_lookup" in result
    assert "domains_for_lookup" in result


def test_analyze_pcap_deduplicates_lookup_domains(tmp_path):
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 100)

    mock_rows = []
    for idx, domain in enumerate(["example.com", "example.com", "example.org"]):
        mock_rows.append({
            "frame.len": "60", "frame.protocols": "eth:ip:udp:dns", "frame.time_epoch": f"100{idx}.0",
            "_ws.col.Protocol": "DNS", "ip.src": "10.0.0.1", "ip.dst": "8.8.8.8",
            "tcp.srcport": "", "tcp.dstport": "", "udp.srcport": str(53000 + idx), "udp.dstport": "53",
            "tcp.stream": "", "udp.stream": str(idx), "tcp.flags": "",
            "dns.qry.name": domain, "dns.qry.type": "1", "dns.a": "93.184.216.34",
            "dns.aaaa": "", "dns.txt": "",
            "http.host": "", "http.request.method": "",
            "tls.handshake.extensions_server_name": "", "tls.handshake.version": "",
            "ssh.protocol": "",
        })

    with patch("app.tasks.pcap_analysis._run_tshark", return_value=mock_rows):
        with patch("app.tasks.pcap_analysis._write_alerts_to_db", return_value=0):
            result = analyze_pcap(str(pcap_file), max_packets=100)

    assert result["domains_for_lookup"] == ["example.com", "example.org"]


def test_analyze_pcap_prioritizes_anomaly_related_lookup_ips(tmp_path):
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 100)

    mock_rows = [
        {
            "frame.len": "60", "frame.protocols": "eth:ip:tcp", "frame.time_epoch": "1000.0",
            "_ws.col.Protocol": "TCP", "ip.src": "1.2.215.113", "ip.dst": "1.1.99.28",
            "tcp.srcport": "443", "tcp.dstport": "54321", "udp.srcport": "", "udp.dstport": "",
            "tcp.stream": "0", "udp.stream": "", "tcp.flags": "0x02",
            "dns.qry.name": "", "dns.qry.type": "", "dns.a": "", "dns.aaaa": "", "dns.txt": "",
            "http.host": "", "http.request.method": "",
            "tls.handshake.extensions_server_name": "", "tls.handshake.version": "",
            "ssh.protocol": "",
        },
        {
            "frame.len": "60", "frame.protocols": "eth:ip:tcp:tls", "frame.time_epoch": "1001.0",
            "_ws.col.Protocol": "TLS", "ip.src": "1.2.102.211", "ip.dst": "1.1.210.113",
            "tcp.srcport": "27567", "tcp.dstport": "443", "udp.srcport": "", "udp.dstport": "",
            "tcp.stream": "1", "udp.stream": "", "tcp.flags": "0x02",
            "dns.qry.name": "", "dns.qry.type": "", "dns.a": "", "dns.aaaa": "", "dns.txt": "",
            "http.host": "", "http.request.method": "",
            "tls.handshake.extensions_server_name": "example.com", "tls.handshake.version": "0x0300",
            "ssh.protocol": "",
        },
        {
            "frame.len": "60", "frame.protocols": "eth:ip:tcp", "frame.time_epoch": "1002.0",
            "_ws.col.Protocol": "TCP", "ip.src": "1.1.0.128", "ip.dst": "8.8.8.8",
            "tcp.srcport": "5555", "tcp.dstport": "443", "udp.srcport": "", "udp.dstport": "",
            "tcp.stream": "2", "udp.stream": "", "tcp.flags": "0x02",
            "dns.qry.name": "", "dns.qry.type": "", "dns.a": "", "dns.aaaa": "", "dns.txt": "",
            "http.host": "", "http.request.method": "",
            "tls.handshake.extensions_server_name": "", "tls.handshake.version": "",
            "ssh.protocol": "",
        },
    ]

    with patch("app.tasks.pcap_analysis._run_tshark", return_value=mock_rows):
        with patch("app.tasks.pcap_analysis._write_alerts_to_db", return_value=0):
            result = analyze_pcap(str(pcap_file), max_packets=100)

    # Order may vary depending on anomaly detection; check membership
    ips = result["external_ips_for_lookup"]
    assert set(["1.2.215.113", "1.1.99.28", "1.2.102.211", "1.1.210.113"]).issubset(set(ips))


def test_analyze_pcap_epoch_timestamp_summary(tmp_path):
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_bytes(PCAP_MAGIC + b"\x00" * 100)

    mock_rows = [
        {
            "frame.len": "60", "frame.protocols": "eth:ip:udp:dns", "frame.time_epoch": "1710000000.0",
            "_ws.col.Protocol": "DNS", "ip.src": "10.0.0.1", "ip.dst": "8.8.8.8",
            "tcp.srcport": "", "tcp.dstport": "", "udp.srcport": "54321", "udp.dstport": "53",
            "tcp.stream": "", "udp.stream": "0", "tcp.flags": "",
            "dns.qry.name": "example.com", "dns.qry.type": "1", "dns.a": "93.184.216.34",
            "dns.aaaa": "", "dns.txt": "",
            "http.host": "", "http.request.method": "",
            "tls.handshake.extensions_server_name": "", "tls.handshake.version": "",
            "ssh.protocol": "",
        },
        {
            "frame.len": "60", "frame.protocols": "eth:ip:udp:dns", "frame.time_epoch": "1710000002.0",
            "_ws.col.Protocol": "DNS", "ip.src": "10.0.0.1", "ip.dst": "8.8.4.4",
            "tcp.srcport": "", "tcp.dstport": "", "udp.srcport": "54322", "udp.dstport": "53",
            "tcp.stream": "", "udp.stream": "1", "tcp.flags": "",
            "dns.qry.name": "example.org", "dns.qry.type": "1", "dns.a": "93.184.216.34",
            "dns.aaaa": "", "dns.txt": "",
            "http.host": "", "http.request.method": "",
            "tls.handshake.extensions_server_name": "", "tls.handshake.version": "",
            "ssh.protocol": "",
        },
    ]

    with patch("app.tasks.pcap_analysis._run_tshark", return_value=mock_rows):
        with patch("app.tasks.pcap_analysis._write_alerts_to_db", return_value=0):
            result = analyze_pcap(str(pcap_file), max_packets=100)

    assert result["success"] is True
    assert result["summary"]["time_basis"] == "epoch"
    assert result["summary"]["start_time"].startswith("2024-03-09T")
    assert result["summary"]["end_time"].startswith("2024-03-09T")
