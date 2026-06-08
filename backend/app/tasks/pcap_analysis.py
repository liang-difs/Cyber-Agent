"""
Pcap analysis task — tshark-based packet analysis with sanitizer pipeline.

Data dimensions:
  1. Flow records (src↔dst sessions with packets/bytes/duration)
  2. Timeline (ordered events: new flows, anomalies, DNS queries)
  3. DNS deep analysis (query types, high-frequency, tunnel detection)
  4. Protocol insights (HTTP Host, TLS SNI, TLS versions, SSH versions)
  5. Extended anomaly detection (7 types)
  6. Alert generation (anomalies → alerts table)
"""

from __future__ import annotations

import logging
import subprocess
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2GB

# DNS query type code → name
DNS_QTYPE_NAMES = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR",
    "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV", "255": "ANY",
}

# Known suspicious ports
SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 12345, 54321}

# TLS versions below this are considered weak
WEAK_TLS_VERSIONS = {"0x0300", "0x0301", "0x0302"}  # SSL3.0, TLS1.0, TLS1.1


def _alert_base_confidence(severity: str) -> float:
    severity = (severity or "").lower()
    if severity == "critical":
        return 0.8
    if severity == "high":
        return 0.65
    if severity == "medium":
        return 0.45
    if severity == "low":
        return 0.25
    return 0.35


def _build_pcap_alert_fields(anomaly: dict[str, Any], ip_reputation: Optional[int] = None) -> dict[str, Any]:
    """Build pcap alert triage fields from a detected anomaly.

    Args:
        anomaly: The detected anomaly dict.
        ip_reputation: Optional AbuseIPDB score (0-100) for the source IP.
    """
    from app.tasks.alert_triage import _compute_verdict, _map_ttps

    rule_id = f"pcap_{anomaly.get('type', 'unknown')}"
    description = anomaly.get("detail", "")
    severity = anomaly.get("severity", "medium")
    ttps = _map_ttps(rule_id, description)
    verdict, final_confidence = _compute_verdict(
        confidence=_alert_base_confidence(severity),
        src_ip_reputation=ip_reputation,
    )
    return {
        "verdict": verdict,
        "confidence": round(final_confidence, 2),
        "ttp_ids": [t.get("technique") for t in ttps if t.get("technique")],
        "ttps": ttps,
    }


def _validate_pcap(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            header = f.read(4)
        return header in (PCAP_MAGIC, PCAPNG_MAGIC)
    except Exception:
        return False


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC 1918 private."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
    except ValueError:
        return False
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


def _run_tshark(path: str, fields: list[str], max_packets: int = 10000) -> Optional[list[dict[str, str]]]:
    """Run tshark to extract fields from pcap.

    Returns None when tshark failed or is unavailable, and an empty list when
    tshark ran successfully but found no rows.
    """
    cmd = [
        "tshark",
        "-r", path,
        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",
        "-c", str(max_packets),
    ]
    for f in fields:
        cmd.extend(["-e", f])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            logger.warning("tshark error: %s", result.stderr[:500])
            return None
    except FileNotFoundError:
        logger.warning("tshark not installed, falling back to basic analysis")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("tshark timeout after 120s")
        return None

    rows = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        values = line.split("|")
        row = {}
        for i, field in enumerate(fields):
            row[field] = values[i] if i < len(values) else ""
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Flow extraction
# ---------------------------------------------------------------------------

def _parse_tcp_flags(flag_str: str) -> dict[str, int]:
    """Parse tshark tcp.flags hex string into SYN/ACK/RST/FIN counts."""
    flags = {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 0}
    if not flag_str:
        return flags
    try:
        val = int(flag_str, 16) if flag_str.startswith("0x") else int(flag_str)
    except (ValueError, TypeError):
        return flags
    if val & 0x02:
        flags["SYN"] = 1
    if val & 0x10:
        flags["ACK"] = 1
    if val & 0x04:
        flags["RST"] = 1
    if val & 0x01:
        flags["FIN"] = 1
    return flags


def _is_epoch_timestamp(ts: float) -> bool:
    """Return true when tshark timestamp looks like Unix epoch seconds."""
    return ts >= 946684800  # 2000-01-01T00:00:00Z


def _extract_flows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Aggregate packets into flow records by (src_ip, src_port, dst_ip, dst_port, protocol)."""
    flow_map: dict[str, dict[str, Any]] = {}

    for row in rows:
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")
        if not src_ip or not dst_ip:
            continue

        src_port_raw = row.get("tcp.srcport", "") or row.get("udp.srcport", "")
        dst_port_raw = row.get("tcp.dstport", "") or row.get("udp.dstport", "")
        src_port = int(src_port_raw) if src_port_raw.isdigit() else None
        dst_port = int(dst_port_raw) if dst_port_raw.isdigit() else None

        proto = row.get("_ws.col.Protocol", "") or row.get("frame.protocols", "unknown")
        transport = "TCP" if row.get("tcp.srcport") else ("UDP" if row.get("udp.srcport") else "OTHER")

        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{transport}"

        ts_raw = row.get("frame.time_epoch", "0")
        try:
            ts = float(ts_raw)
        except (ValueError, TypeError):
            ts = 0.0

        pkt_len_raw = row.get("frame.len", "0")
        try:
            pkt_len = int(pkt_len_raw)
        except (ValueError, TypeError):
            pkt_len = 0

        pkt_flags = _parse_tcp_flags(row.get("tcp.flags", ""))

        if key not in flow_map:
            flow_map[key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": transport,
                "app_protocol": proto,
                "packets": 0,
                "bytes": 0,
                "start_time": ts,
                "end_time": ts,
                "tcp_flags": {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 0},
            }
        else:
            if ts and ts < flow_map[key]["start_time"]:
                flow_map[key]["start_time"] = ts
            if ts and ts > flow_map[key]["end_time"]:
                flow_map[key]["end_time"] = ts

        flow_map[key]["packets"] += 1
        flow_map[key]["bytes"] += pkt_len
        for flag_name, val in pkt_flags.items():
            flow_map[key]["tcp_flags"][flag_name] += val

    flows = []
    for f in flow_map.values():
        f["duration_s"] = round(max(0, f["end_time"] - f["start_time"]), 3)
        # Determine direction
        if _is_private_ip(f["src_ip"]) and not _is_private_ip(f["dst_ip"]):
            f["direction"] = "outbound"
        elif not _is_private_ip(f["src_ip"]) and _is_private_ip(f["dst_ip"]):
            f["direction"] = "inbound"
        else:
            f["direction"] = "internal"
        flows.append(f)

    flows.sort(key=lambda x: x["bytes"], reverse=True)
    return flows[:500]


# ---------------------------------------------------------------------------
# DNS deep analysis
# ---------------------------------------------------------------------------

def _analyze_dns(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Deep DNS analysis: queries, types, frequency, tunnel detection."""
    queries = []
    domain_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    txt_queries = []
    long_subdomains = []
    domain_times: dict[str, list[float]] = defaultdict(list)

    for row in rows:
        qname = row.get("dns.qry.name", "")
        if not qname:
            continue

        qtype_code = row.get("dns.qry.type", "")
        qtype = DNS_QTYPE_NAMES.get(qtype_code, qtype_code)
        response = row.get("dns.a", "") or row.get("dns.aaaa", "")
        src_ip = row.get("ip.src", "")

        ts_raw = row.get("frame.time_epoch", "0")
        try:
            ts = float(ts_raw)
        except (ValueError, TypeError):
            ts = 0.0

        queries.append({
            "name": qname,
            "type": qtype,
            "response": response,
            "timestamp": ts,
            "src_ip": src_ip,
        })

        domain_counts[qname] += 1
        type_counts[qtype] += 1
        if ts:
            domain_times[qname].append(ts)

        # DNS tunnel: long subdomain
        if len(qname) > 50:
            long_subdomains.append(qname)
        # TXT queries (common for tunneling)
        if qtype == "TXT":
            txt_queries.append(qname)

    # High-frequency detection: >10 queries in 60s window
    high_frequency = []
    for domain, times in domain_times.items():
        if len(times) < 10:
            continue
        times_sorted = sorted(times)
        for i in range(len(times_sorted) - 9):
            window = times_sorted[i + 9] - times_sorted[i]
            if window <= 60:
                high_frequency.append({
                    "domain": domain,
                    "count": len(times),
                    "window_s": round(window, 1),
                })
                break

    top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:20]

    return {
        "queries": queries[:500],
        "stats": {
            "total_queries": len(queries),
            "unique_domains": len(domain_counts),
            "query_types": dict(type_counts),
            "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
            "long_subdomains": sorted(set(long_subdomains)),
            "txt_queries": sorted(set(txt_queries)),
            "high_frequency": high_frequency,
        },
    }


# ---------------------------------------------------------------------------
# Protocol insights
# ---------------------------------------------------------------------------

def _analyze_protocol_insights(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Extract HTTP hosts, TLS SNI, TLS versions, SSH versions."""
    http_hosts: dict[str, dict[str, Any]] = {}
    tls_sni: dict[str, dict[str, Any]] = {}
    tls_versions: dict[str, int] = defaultdict(int)
    ssh_versions = set()

    for row in rows:
        # HTTP Host
        host = row.get("http.host", "")
        if host:
            method = row.get("http.request.method", "")
            if host not in http_hosts:
                http_hosts[host] = {"host": host, "count": 0, "methods": set()}
            http_hosts[host]["count"] += 1
            if method:
                http_hosts[host]["methods"].add(method)

        # TLS SNI
        sni = row.get("tls.handshake.extensions_server_name", "")
        if sni:
            tls_ver = row.get("tls.handshake.version", "")
            if sni not in tls_sni:
                tls_sni[sni] = {"server_name": sni, "count": 0, "tls_versions": set()}
            tls_sni[sni]["count"] += 1
            if tls_ver:
                tls_sni[sni]["tls_versions"].add(tls_ver)

        # TLS version
        tls_ver = row.get("tls.handshake.version", "")
        if tls_ver:
            tls_versions[tls_ver] = tls_versions.get(tls_ver, 0) + 1

        # SSH
        ssh_ver = row.get("ssh.protocol", "")
        if ssh_ver:
            ssh_versions.add(ssh_ver)

    # Convert sets to lists for JSON serialization
    for h in http_hosts.values():
        h["methods"] = sorted(h["methods"])
    for t in tls_sni.values():
        t["tls_versions"] = sorted(t["tls_versions"])

    return {
        "http_hosts": sorted(http_hosts.values(), key=lambda x: -x["count"]),
        "tls_sni": sorted(tls_sni.values(), key=lambda x: -x["count"]),
        "tls_versions": dict(tls_versions),
        "ssh_versions": sorted(ssh_versions),
    }


# ---------------------------------------------------------------------------
# Anomaly detection (7 types)
# ---------------------------------------------------------------------------

def _detect_port_scan(rows: list[dict[str, str]], threshold: int = 20) -> list[dict[str, Any]]:
    """Detect port scanning: a source IP connects to many different destination ports.

    Excludes DNS response traffic (src port 53) which naturally targets many
    random client source ports and would cause false positives.
    """
    # Known DNS resolver IPs — skip these to avoid false positives
    _DNS_SERVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"}

    ip_ports: dict[str, set[str]] = {}
    ip_src_port53: dict[str, bool] = {}  # track if IP has src port 53 (DNS server)
    ip_times: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        src = row.get("ip.src", "")
        src_port = row.get("tcp.srcport", "") or row.get("udp.srcport", "")
        dst_port = row.get("tcp.dstport", "") or row.get("udp.dstport", "")
        if src and dst_port:
            ip_ports.setdefault(src, set()).add(dst_port)
            # Flag if this IP ever sends FROM port 53 (DNS response pattern)
            if src_port == "53":
                ip_src_port53[src] = True
            ts_raw = row.get("frame.time_epoch", "0")
            try:
                ip_times[src].append(float(ts_raw))
            except (ValueError, TypeError):
                pass

    scanners = []
    for ip, ports in ip_ports.items():
        if len(ports) < threshold:
            continue
        # Skip known DNS servers
        if ip in _DNS_SERVERS:
            continue
        # Skip IPs that send from port 53 (DNS responses target random client ports)
        if ip_src_port53.get(ip):
            continue
        times = sorted(ip_times.get(ip, []))
        scanners.append({
            "type": "port_scan",
            "severity": "high",
            "src_ip": ip,
            "dst_ip": None,
            "detail": f"端口扫描: {ip} 扫描了 {len(ports)} 个不同端口",
            "unique_ports": len(ports),
            "sample_ports": sorted(list(ports))[:10],
            "first_seen": times[0] if times else 0,
            "last_seen": times[-1] if times else 0,
        })
    return scanners


def _detect_high_volume(rows: list[dict[str, str]], threshold_kb: int = 500) -> list[dict[str, Any]]:
    flow_bytes: dict[str, int] = {}
    flow_times: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        src = row.get("ip.src", "")
        dst = row.get("ip.dst", "")
        length = row.get("frame.len", "0")
        if src and dst:
            key = f"{src}->{dst}"
            flow_bytes[key] = flow_bytes.get(key, 0) + int(length or 0)
            ts_raw = row.get("frame.time_epoch", "0")
            try:
                flow_times[key].append(float(ts_raw))
            except (ValueError, TypeError):
                pass

    suspicious = []
    for flow, total in flow_bytes.items():
        if total >= threshold_kb * 1000:
            src, dst = flow.split("->")
            times = sorted(flow_times.get(flow, []))
            suspicious.append({
                "type": "high_volume",
                "severity": "high",
                "src_ip": src,
                "dst_ip": dst,
                "detail": f"高流量: {src}→{dst} 传输 {total / 1024:.1f} KB",
                "total_bytes": total,
                "first_seen": times[0] if times else 0,
                "last_seen": times[-1] if times else 0,
            })
    return suspicious


def _detect_brute_force(rows: list[dict[str, str]], threshold: int = 50) -> list[dict[str, Any]]:
    """Detect brute force and C2 beacon patterns.

    Brute force: same src → single dst:port with many connections (credential guessing).
    C2 beacon: same src → many dst on same port with many connections each (beaconing).
    """
    conn_count: dict[str, int] = defaultdict(int)
    conn_times: dict[str, list[float]] = defaultdict(list)
    # Track unique destinations per (src, port) for C2 beacon detection
    src_port_dsts: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        src = row.get("ip.src", "")
        dst = row.get("ip.dst", "")
        dst_port = row.get("tcp.dstport", "") or row.get("udp.dstport", "")
        if src and dst and dst_port:
            key = f"{src}->{dst}:{dst_port}"
            conn_count[key] += 1
            src_port_dsts[f"{src}:{dst_port}"].add(dst)
            ts_raw = row.get("frame.time_epoch", "0")
            try:
                conn_times[key].append(float(ts_raw))
            except (ValueError, TypeError):
                pass

    results = []
    seen_src_ports: set[str] = set()

    for key, count in conn_count.items():
        if count < threshold:
            continue
        parts = key.split("->")
        src = parts[0]
        dst_port = parts[1] if len(parts) > 1 else ""
        dst = dst_port.split(":")[0] if ":" in dst_port else dst_port
        port = dst_port.split(":")[1] if ":" in dst_port else ""
        times = sorted(conn_times.get(key, []))
        src_port_key = f"{src}:{port}"

        # Check if this src:port targets many destinations (C2 beacon pattern)
        dst_count = len(src_port_dsts.get(src_port_key, set()))

        if dst_count >= 3 and src_port_key not in seen_src_ports:
            # C2 beacon: same src, same port, many destinations
            seen_src_ports.add(src_port_key)
            all_dsts = sorted(src_port_dsts[src_port_key])
            total_conns = sum(conn_count.get(f"{src}->{d}:{port}", 0) for d in all_dsts)
            results.append({
                "type": "c2_beacon",
                "severity": "critical",
                "src_ip": src,
                "dst_ip": None,
                "detail": (
                    f"C2 信标: {src} 向 {dst_count} 个目标的 {port} 端口发起 "
                    f"共 {total_conns} 次连接，疑似命令控制通信"
                ),
                "count": total_conns,
                "connection_count": total_conns,
                "target_count": dst_count,
                "dst_port": port,
                "sample_ips": all_dsts[:10],
                "first_seen": min(times) if times else 0,
                "last_seen": max(times) if times else 0,
            })
        elif dst_count < 3:
            # Brute force: same src → few destinations, high connection count
            results.append({
                "type": "brute_force",
                "severity": "high",
                "src_ip": src,
                "dst_ip": dst,
                "detail": f"暴力破解: {src} 对 {dst}:{port} 发起 {count} 次连接",
                "count": count,
                "connection_count": count,
                "dst_port": port,
                "first_seen": times[0] if times else 0,
                "last_seen": times[-1] if times else 0,
            })
    return results


def _detect_dns_tunnel(dns_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect DNS tunnel: long subdomains or excessive TXT queries."""
    anomalies = []
    stats = dns_result.get("stats", {})

    long_subs = stats.get("long_subdomains", [])
    if long_subs:
        anomalies.append({
            "type": "dns_tunnel",
            "severity": "high",
            "src_ip": "",
            "dst_ip": None,
            "detail": f"DNS 隧道嫌疑: 发现 {len(long_subs)} 个超长子域名（>50字符）",
            "sample_domains": long_subs[:5],
            "first_seen": 0,
            "last_seen": 0,
        })

    txt_qs = stats.get("txt_queries", [])
    if len(txt_qs) > 20:
        anomalies.append({
            "type": "dns_tunnel",
            "severity": "high",
            "src_ip": "",
            "dst_ip": None,
            "detail": f"DNS 隧道嫌疑: 发现 {len(txt_qs)} 个 TXT 查询",
            "sample_domains": txt_qs[:5],
            "first_seen": 0,
            "last_seen": 0,
        })

    return anomalies


def _detect_beacon(flows: list[dict[str, Any]], min_connections: int = 10) -> list[dict[str, Any]]:
    """Detect C2 beacon: periodic communication (coefficient of variation < 0.3)."""
    # Group flows by src→dst pair
    pair_times: dict[str, list[float]] = defaultdict(list)
    for flow in flows:
        if flow["packets"] < min_connections:
            continue
        key = f"{flow['src_ip']}->{flow['dst_ip']}"
        if flow["start_time"]:
            pair_times[key].append(flow["start_time"])

    anomalies = []
    for pair, times in pair_times.items():
        if len(times) < min_connections:
            continue
        times_sorted = sorted(times)
        intervals = [times_sorted[i + 1] - times_sorted[i] for i in range(len(times_sorted) - 1)]
        if not intervals:
            continue
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 1:  # Skip if interval < 1s (not beacon-like)
            continue
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / mean_interval if mean_interval > 0 else 999

        if cv < 0.3:
            src, dst = pair.split("->")
            anomalies.append({
                "type": "beacon",
                "severity": "high",
                "src_ip": src,
                "dst_ip": dst,
                "detail": f"C2 信标: {src}→{dst} 周期性通信，平均间隔 {mean_interval:.1f}s，变异系数 {cv:.2f}",
                "mean_interval_s": round(mean_interval, 1),
                "cv": round(cv, 3),
                "connection_count": len(times),
                "first_seen": times_sorted[0],
                "last_seen": times_sorted[-1],
            })
    return anomalies


def _detect_suspicious_ports(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Detect usage of known suspicious ports."""
    port_usage: dict[str, dict[str, Any]] = {}
    for row in rows:
        dst_port_raw = row.get("tcp.dstport", "") or row.get("udp.dstport", "")
        if not dst_port_raw or not dst_port_raw.isdigit():
            continue
        dst_port = int(dst_port_raw)
        if dst_port in SUSPICIOUS_PORTS:
            src = row.get("ip.src", "")
            dst = row.get("ip.dst", "")
            key = f"{src}:{dst_port}"
            if key not in port_usage:
                ts_raw = row.get("frame.time_epoch", "0")
                try:
                    ts = float(ts_raw)
                except (ValueError, TypeError):
                    ts = 0.0
                port_usage[key] = {
                    "type": "suspicious_port",
                    "severity": "medium",
                    "src_ip": src,
                    "dst_ip": dst,
                    "detail": f"可疑端口: {src}→{dst}:{dst_port}",
                    "dst_port": dst_port,
                    "first_seen": ts,
                    "last_seen": ts,
                    "count": 0,
                }
            port_usage[key]["count"] += 1

    return list(port_usage.values())


def _detect_tls_downgrade(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Detect TLS versions below 1.2 and aggregate by (version, source IP)."""
    TLS_MIN_COUNT = 10  # Minimum occurrences to generate an alert
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        tls_ver = row.get("tls.handshake.version", "")
        if tls_ver and tls_ver in WEAK_TLS_VERSIONS:
            sni = row.get("tls.handshake.extensions_server_name", "")
            src = row.get("ip.src", "")
            dst = row.get("ip.dst", "")
            ver_name = {"0x0300": "SSLv3", "0x0301": "TLSv1.0", "0x0302": "TLSv1.1"}.get(tls_ver, tls_ver)
            # Aggregate by (version, src_ip) to produce per-source alerts
            key = f"{tls_ver}:{src}"
            if key not in found:
                ts_raw = row.get("frame.time_epoch", "0")
                try:
                    ts = float(ts_raw)
                except (ValueError, TypeError):
                    ts = 0.0
                found[key] = {
                    "type": "tls_downgrade",
                    "severity": "medium",
                    "src_ip": src,
                    "dst_ip": dst or None,
                    "detail": "",
                    "tls_version": ver_name,
                    "server_name": sni,
                    "count": 0,
                    "sample_ips": [],
                    "sample_dest_ips": [],
                    "server_names": [],
                    "first_seen": ts,
                    "last_seen": ts,
                }

            entry = found[key]
            entry["count"] += 1
            if src and src not in entry["sample_ips"] and len(entry["sample_ips"]) < 10:
                entry["sample_ips"].append(src)
            if dst and dst not in entry["sample_dest_ips"] and len(entry["sample_dest_ips"]) < 10:
                entry["sample_dest_ips"].append(dst)
            if sni and sni not in entry["server_names"]:
                entry["server_names"].append(sni)

            ts_raw = row.get("frame.time_epoch", "0")
            try:
                ts = float(ts_raw)
            except (ValueError, TypeError):
                ts = 0.0
            if ts and ts < entry["first_seen"]:
                entry["first_seen"] = ts
            if ts and ts > entry["last_seen"]:
                entry["last_seen"] = ts

    results = []
    global_count = 0
    global_src_ips: set[str] = set()
    global_ver_counts: dict[str, int] = {}

    for entry in found.values():
        global_count += entry["count"]
        if entry.get("src_ip"):
            global_src_ips.add(entry["src_ip"])
        ver = entry.get("tls_version", "unknown")
        global_ver_counts[ver] = global_ver_counts.get(ver, 0) + entry["count"]

        if entry["count"] < TLS_MIN_COUNT:
            continue
        dest_ips = entry.get("sample_dest_ips", [])
        server_names = entry.get("server_names", [])
        entry["detail"] = (
            f"弱 TLS 事件：源 {entry.get('src_ip', '?')} 使用 {entry['tls_version']} "
            f"共 {entry['count']} 次，目标 {len(set(dest_ips))} 个"
        )
        if server_names:
            entry["detail"] += f"；SNI: {', '.join(server_names[:3])}"
        entry["detail"] += "，建议升级到 TLS 1.2+"
        results.append(entry)

    # Global summary: when total weak TLS is high but per-src_ip counts are below threshold
    if global_count >= 50 and not results:
        ver_summary = ", ".join(f"{v}({c}次)" for v, c in sorted(global_ver_counts.items(), key=lambda x: -x[1]))
        severity = "high" if global_count >= 200 else "medium"
        results.append({
            "type": "tls_downgrade",
            "severity": severity,
            "src_ip": None,
            "dst_ip": None,
            "detail": (
                f"全局弱TLS汇总：检测到 {global_count} 条弱协议记录（{ver_summary}），"
                f"分散于 {len(global_src_ips)} 个源IP，"
                f"可能为客户端配置问题而非主动攻击，建议统一升级到 TLS 1.2+"
            ),
            "tls_version": ver_summary,
            "server_name": "",
            "count": global_count,
            "sample_ips": list(global_src_ips)[:10],
            "sample_dest_ips": [],
            "server_names": [],
            "first_seen": 0,
            "last_seen": 0,
        })

    return results


def _detect_data_exfil(flows: list[dict[str, Any]], threshold_mb: int = 10) -> list[dict[str, Any]]:
    """Detect large outbound flows (potential data exfiltration)."""
    anomalies = []
    for flow in flows:
        if flow["direction"] == "outbound" and flow["bytes"] >= threshold_mb * 1024 * 1024:
            anomalies.append({
                "type": "data_exfil",
                "severity": "high",
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "detail": f"数据外泄嫌疑: {flow['src_ip']}→{flow['dst_ip']} 传出 {flow['bytes'] / 1024 / 1024:.1f} MB",
                "total_bytes": flow["bytes"],
                "first_seen": flow["start_time"],
                "last_seen": flow["end_time"],
            })
    return anomalies


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def _build_timeline(
    flows: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    dns_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Merge flows, anomalies, DNS into a unified timeline."""
    events = []

    for flow in flows[:100]:  # Top 100 flows by bytes
        if flow["start_time"]:
            events.append({
                "timestamp": flow["start_time"],
                "event_type": "new_flow",
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "detail": f"{flow['src_ip']}:{flow.get('src_port', '')} → {flow['dst_ip']}:{flow.get('dst_port', '')} ({flow['app_protocol']}, {flow['packets']}pkts, {flow['bytes']}B)",
            })

    for anomaly in anomalies:
        ts = anomaly.get("first_seen", 0) or anomaly.get("last_seen", 0)
        if ts:
            events.append({
                "timestamp": ts,
                "event_type": "anomaly",
                "src_ip": anomaly.get("src_ip", ""),
                "dst_ip": anomaly.get("dst_ip"),
                "detail": f"[{anomaly['severity'].upper()}] {anomaly['detail']}",
            })

    for q in dns_result.get("queries", [])[:100]:
        if q.get("timestamp"):
            events.append({
                "timestamp": q["timestamp"],
                "event_type": "dns_query",
                "src_ip": q.get("src_ip", ""),
                "dst_ip": None,
                "detail": f"DNS: {q['name']} ({q['type']})" + (f" → {q['response']}" if q.get("response") else ""),
            })

    events.sort(key=lambda x: x["timestamp"])
    return events[:200]


# ---------------------------------------------------------------------------
# Alert generation
# ---------------------------------------------------------------------------

def _write_alerts_to_db(anomalies: list[dict[str, Any]], tenant_id: str) -> int:
    """Write detected anomalies as alerts to the database. Returns count written."""
    try:
        from app.models.models import Alert
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from app.core.config import get_settings

        settings = get_settings()
        if not settings.database_url:
            return 0

        # Celery tasks run in sync context — use sync engine.
        sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
        engine = create_engine(sync_url)
        count = 0
        with Session(engine) as session:
            for anomaly in anomalies:
                triage = _build_pcap_alert_fields(anomaly)
                alert = Alert(
                    rule_id=f"pcap_{anomaly['type']}",
                    src_ip=anomaly.get("src_ip") or None,
                    dst_ip=anomaly.get("dst_ip") or None,
                    severity=anomaly.get("severity", "medium"),
                    description=anomaly.get("detail", ""),
                    verdict=triage["verdict"],
                    confidence=triage["confidence"],
                    ttp_ids=triage["ttp_ids"],
                    tenant_id=tenant_id,
                )
                session.add(alert)
                count += 1
            session.commit()
        engine.dispose()
        return count
    except Exception as e:
        logger.warning("Failed to write PCAP alerts to DB: %s", e)
        return 0


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

@celery_app.task(name="app.tasks.pcap_analysis.analyze_pcap", queue="celery_high")
def analyze_pcap(
    pcap_path: str,
    tenant_id: str = "default",
    max_packets: int = 10000,
    display_filename: str | None = None,
) -> dict[str, Any]:
    """Analyze a pcap file for security anomalies."""
    logger.info("Analyzing pcap: %s (tenant=%s)", pcap_path, tenant_id)

    # Path traversal protection
    try:
        resolved = os.path.realpath(os.path.abspath(pcap_path))
        backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        project_root = os.path.abspath(os.path.join(backend_root, ".."))
        allowed_bases = [
            os.path.join(project_root, "data"),   # Agent/data/
            os.path.join(backend_root, "data"),    # backend/data/
            "/tmp",
        ]
        if not any(resolved.startswith(b + os.sep) or resolved == b for b in allowed_bases):
            return {"success": False, "error": "Path not in allowed directories", "tenant_id": tenant_id}
    except (ValueError, OSError) as e:
        return {"success": False, "error": f"Invalid path: {e}", "tenant_id": tenant_id}

    if not _validate_pcap(pcap_path):
        return {"success": False, "error": "Invalid pcap file (magic bytes mismatch)", "tenant_id": tenant_id}

    # Extended tshark fields
    fields = [
        "frame.len", "frame.protocols", "frame.time_epoch",
        "_ws.col.Protocol",
        "ip.src", "ip.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        "tcp.stream", "udp.stream", "tcp.flags",
        "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.txt",
        "http.host", "http.request.method",
        "tls.handshake.extensions_server_name", "tls.handshake.version",
        "ssh.protocol",
    ]

    rows = _run_tshark(pcap_path, fields, max_packets)

    if rows is None:
        return {
            "success": False,
            "error": "tshark unavailable or failed to parse pcap",
            "tenant_id": tenant_id,
            "dependency": "tshark",
        }

    if not rows:
        return {
            "success": True,
            "warning": "No packets parsed (empty file or no supported packet rows)",
            "summary": {"total_packets": 0, "total_flows": 0, "duration_s": 0, "total_bytes": 0,
                        "start_time": "", "end_time": "", "time_basis": "unknown",
                        "anomaly_count": 0, "top_protocols": []},
            "flows": [], "anomalies": [], "protocols": {},
            "ips": {"source_ips": [], "destination_ips": [], "internal_ips": [], "external_ips": []},
            "dns": {"queries": [], "stats": {"total_queries": 0, "unique_domains": 0, "query_types": {},
                    "top_domains": [], "long_subdomains": [], "txt_queries": [], "high_frequency": []}},
            "protocol_insights": {"http_hosts": [], "tls_sni": [], "tls_versions": {}, "ssh_versions": []},
            "timeline": [],
            "tenant_id": tenant_id,
        }

    # 1. Flow extraction
    flows = _extract_flows(rows)

    # 2. Protocol distribution
    protocols: dict[str, int] = {}
    for row in rows:
        proto = row.get("_ws.col.Protocol", "") or row.get("frame.protocols", "unknown")
        protocols[proto] = protocols.get(proto, 0) + 1

    # 3. IP extraction
    src_ips = set()
    dst_ips = set()
    for row in rows:
        s = row.get("ip.src", "")
        d = row.get("ip.dst", "")
        if s:
            src_ips.add(s)
        if d:
            dst_ips.add(d)
    all_ips = src_ips | dst_ips
    internal_ips = sorted(ip for ip in all_ips if _is_private_ip(ip))
    external_ips = sorted(ip for ip in all_ips if not _is_private_ip(ip))

    # 4. DNS deep analysis
    dns_result = _analyze_dns(rows)

    # 5. Protocol insights
    protocol_insights = _analyze_protocol_insights(rows)

    # 6. Anomaly detection
    anomalies = []
    anomalies.extend(_detect_port_scan(rows))
    anomalies.extend(_detect_high_volume(rows))
    anomalies.extend(_detect_brute_force(rows))
    anomalies.extend(_detect_dns_tunnel(dns_result))
    anomalies.extend(_detect_beacon(flows))
    anomalies.extend(_detect_suspicious_ports(rows))
    anomalies.extend(_detect_tls_downgrade(rows))
    anomalies.extend(_detect_data_exfil(flows))

    # 7. Timeline
    timeline = _build_timeline(flows, anomalies, dns_result)

    # 8. Write alerts to DB
    alerts_written = _write_alerts_to_db(anomalies, tenant_id)
    if alerts_written:
        logger.info("Wrote %d PCAP alerts to database", alerts_written)

        # 触发告警管线（异步）
        try:
            from app.events.alert_pipeline import get_alert_pipeline
            import asyncio

            pipeline = get_alert_pipeline()

            # 为每个异常触发管线
            for anomaly in anomalies:
                alert_data = {
                    "id": f"pcap-{anomaly['type']}-{anomaly.get('src_ip', 'unknown')}",
                    "rule_id": f"pcap_{anomaly['type']}",
                    "description": anomaly.get("detail", ""),
                    "src_ip": anomaly.get("src_ip"),
                    "dst_ip": anomaly.get("dst_ip"),
                    "severity": anomaly.get("severity", "medium"),
                    "tenant_id": tenant_id,
                }

                # 异步触发管线
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.ensure_future(pipeline.process_alert(alert_data))
                    else:
                        loop.run_until_complete(pipeline.process_alert(alert_data))
                except RuntimeError:
                    asyncio.run(pipeline.process_alert(alert_data))

            logger.info("Alert pipeline triggered for %d anomalies", len(anomalies))
        except Exception as e:
            logger.warning("Failed to trigger alert pipeline: %s", e)

    # 9. Summary
    # Calculate time range from first/last packet
    timestamps = []
    for row in rows:
        ts_raw = row.get("frame.time_epoch", "0")
        try:
            ts = float(ts_raw)
            if ts > 0:
                timestamps.append(ts)
        except (ValueError, TypeError):
            pass

    start_ts = min(timestamps) if timestamps else 0
    end_ts = max(timestamps) if timestamps else 0
    duration = end_ts - start_ts if start_ts and end_ts else 0

    top_protocols = sorted(protocols.items(), key=lambda x: -x[1])[:5]
    total_bytes = sum(f["bytes"] for f in flows)

    has_epoch_timestamps = bool(timestamps) and _is_epoch_timestamp(start_ts) and _is_epoch_timestamp(end_ts)
    start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat() if has_epoch_timestamps else ""
    end_iso = datetime.fromtimestamp(end_ts, tz=timezone.utc).isoformat() if has_epoch_timestamps else ""

    # In relative mode, duration=0 with multiple frames means timestamps are identical — mark as N/A
    if not has_epoch_timestamps and duration == 0 and len(rows) > 1:
        duration_display = None  # Report should show N/A
    else:
        duration_display = round(duration, 2)

    result = {
        "success": True,
        "summary": {
            "total_packets": len(rows),
            "total_flows": len(flows),
            "duration_s": duration_display,
            "total_bytes": total_bytes,
            "start_time": start_iso,
            "end_time": end_iso,
            "time_basis": "epoch" if has_epoch_timestamps else "relative",
            "anomaly_count": len(anomalies),
            "top_protocols": [{"protocol": p, "count": c} for p, c in top_protocols],
        },
        "flows": flows,
        "anomalies": anomalies,
        "protocols": protocols,
        "ips": {
            "source_ips": sorted(src_ips),
            "destination_ips": sorted(dst_ips),
            "internal_ips": internal_ips,
            "external_ips": external_ips,
        },
        "dns": dns_result,
        "protocol_insights": protocol_insights,
        "timeline": timeline,
        "tenant_id": tenant_id,
    }
    result_display_filename = display_filename or os.path.basename(pcap_path)
    result["display_filename"] = result_display_filename
    result["pcap_identity"] = {
        "display_filename": result_display_filename,
        "original_filename": display_filename or result_display_filename,
        "source_path": pcap_path,
        "sha256": None,
    }

    # Known-good IP prefixes to exclude from IoC threat lookup
    _IOC_WHITELIST_PREFIXES = ("1.1.1.", "1.0.0.", "8.8.8.", "8.8.4.", "9.9.9.", "149.112.")

    # Build llm_context — curated subset for LLM prompts (avoids token explosion)
    priority_external_ips: list[str] = []
    seen_lookup_ips: set[str] = set()

    def _add_lookup_ip(ip: str) -> None:
        ip = str(ip or "").strip()
        if not ip or _is_private_ip(ip) or ip in seen_lookup_ips or ip not in external_ips:
            return
        if any(ip.startswith(p) for p in _IOC_WHITELIST_PREFIXES):
            return
        # Filter multicast (224.0.0.0/4) and broadcast
        first_octet = int(ip.split(".")[0]) if "." in ip else 0
        if first_octet >= 224:
            return
        seen_lookup_ips.add(ip)
        priority_external_ips.append(ip)

    for anomaly in anomalies:
        _add_lookup_ip(anomaly.get("src_ip"))
        _add_lookup_ip(anomaly.get("dst_ip"))
        sample_ips = anomaly.get("sample_ips") if isinstance(anomaly.get("sample_ips"), list) else []
        sample_dest_ips = anomaly.get("sample_dest_ips") if isinstance(anomaly.get("sample_dest_ips"), list) else []
        for sample_ip in sample_ips:
            _add_lookup_ip(sample_ip)
        for sample_ip in sample_dest_ips:
            _add_lookup_ip(sample_ip)

    for ip in external_ips:
        _add_lookup_ip(ip)

    external_for_lookup = priority_external_ips[:20]
    domains_for_lookup = list(dict.fromkeys(
        q["name"] for q in dns_result.get("queries", [])
        if q.get("type") in ("A", "AAAA", "CNAME") and q.get("name")
        and "." in q["name"]  # Filter non-FQDN local names like "wpad"
    ))[:20]

    result["external_ips_for_lookup"] = external_for_lookup
    result["domains_for_lookup"] = domains_for_lookup
    result["llm_context"] = {
        "summary": result["summary"],
        "anomalies": anomalies,
        "dns_stats": dns_result.get("stats", {}),
        "protocol_insights": protocol_insights,
        "external_ips_for_lookup": external_for_lookup,
        "domains_for_lookup": domains_for_lookup,
    }

    # Sanitize output — but preserve lookup fields (IPs/domains needed for threat queries)
    from app.sanitizer.pipeline import sanitizer
    saved_external_ips = result.get("external_ips_for_lookup", [])
    saved_domains = result.get("domains_for_lookup", [])
    saved_llm_lookup = {
        "external_ips_for_lookup": saved_external_ips,
        "domains_for_lookup": saved_domains,
    }
    sanitized = sanitizer.sanitize(json.dumps(result))
    result = json.loads(sanitized.sanitized_text)
    result["external_ips_for_lookup"] = saved_external_ips
    result["domains_for_lookup"] = saved_domains
    if "llm_context" in result:
        result["llm_context"]["external_ips_for_lookup"] = saved_external_ips
        result["llm_context"]["domains_for_lookup"] = saved_domains
    result["sanitized_for_llm"] = True
    result["redaction_count"] = sanitized.redaction_count
    result["pcap_identity"]["sha256"] = result.get("sha256")

    logger.info(
        "Pcap analysis complete: %d packets, %d flows, %d anomalies, %d redactions",
        len(rows), len(flows), len(anomalies), sanitized.redaction_count,
    )

    return result
