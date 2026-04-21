#!/usr/bin/env python3
"""
pcap_bandwidth_analyzer.py
Analyze bandwidth per domain from a pcap captured with:
    tcp port 443 || port 53

Usage:
    python3 pcap_bandwidth_analyzer.py capture.pcap
    python3 pcap_bandwidth_analyzer.py capture.pcap --sort tx
    python3 pcap_bandwidth_analyzer.py capture.pcap --min-bytes 1024
    python3 pcap_bandwidth_analyzer.py capture.pcap --csv out.csv

Requirements:
    pip install scapy
"""

import argparse
import sys
import csv
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSRR, DNSQR
    from scapy.layers.dns import DNSRR
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DomainStats:
    domain: str
    ips: set = field(default_factory=set)

    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_packets: int = 0
    rx_packets: int = 0

    handshake_packets: int = 0
    handshake_bytes: int = 0
    retrans_packets: int = 0
    retrans_bytes: int = 0

    @property
    def total_packets(self):
        return self.tx_packets + self.rx_packets

    @property
    def total_bytes(self):
        return self.tx_bytes + self.rx_bytes

    @property
    def handshake_pct_packets(self):
        return 100.0 * self.handshake_packets / self.total_packets if self.total_packets else 0.0

    @property
    def handshake_pct_bytes(self):
        return 100.0 * self.handshake_bytes / self.total_bytes if self.total_bytes else 0.0

    @property
    def retrans_pct_packets(self):
        return 100.0 * self.retrans_packets / self.total_packets if self.total_packets else 0.0

    @property
    def retrans_pct_bytes(self):
        return 100.0 * self.retrans_bytes / self.total_bytes if self.total_bytes else 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"



def ip_pkt_size(pkt) -> int:
    if IP in pkt:
        return pkt[IP].len
    return len(pkt)


def tcp_flags(pkt) -> dict:
    if TCP not in pkt:
        return {}
    f = pkt[TCP].flags
    return {
        "SYN": bool(f & 0x02),
        "ACK": bool(f & 0x10),
        "FIN": bool(f & 0x01),
        "RST": bool(f & 0x04),
        "PSH": bool(f & 0x08),
    }


def is_handshake(pkt) -> bool:
    if TCP not in pkt:
        return False
    return tcp_flags(pkt).get("SYN", False)


def is_retransmission(pkt, seen_seq: set) -> bool:
    if TCP not in pkt:
        return False
    if tcp_flags(pkt).get("RST", False):
        return True
    if IP in pkt:
        key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].seq)
        if len(pkt[TCP].payload) > 0:
            if key in seen_seq:
                return True
            seen_seq.add(key)
    return False


def extract_sni(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello and return the SNI hostname, or None.

    TLS record layout:
      1B  content_type  (0x16 = handshake)
      2B  version
      2B  record length
      1B  handshake_type (0x01 = ClientHello)
      3B  handshake length
      2B  client_hello version
      32B random
      1B  session_id length  + session_id
      2B  cipher_suites length + cipher_suites
      1B  compression_methods length + compression_methods
      2B  extensions length
        extensions…
          2B ext_type  (0x0000 = SNI)
          2B ext_data_length
          2B server_name_list_length
          1B name_type (0x00 = host_name)
          2B name_length
          NB name
    """
    try:
        if len(payload) < 5:
            return None
        # TLS handshake record
        if payload[0] != 0x16:
            return None
        record_len = int.from_bytes(payload[3:5], "big")
        if len(payload) < 5 + record_len:
            return None
        hs = payload[5:5 + record_len]
        if hs[0] != 0x01:          # ClientHello
            return None
        # skip: handshake_type(1) + length(3) + version(2) + random(32)
        pos = 1 + 3 + 2 + 32
        # session id
        sid_len = hs[pos]; pos += 1 + sid_len
        # cipher suites
        cs_len = int.from_bytes(hs[pos:pos+2], "big"); pos += 2 + cs_len
        # compression methods
        cm_len = hs[pos]; pos += 1 + cm_len
        # extensions
        if pos + 2 > len(hs):
            return None
        ext_total = int.from_bytes(hs[pos:pos+2], "big"); pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type = int.from_bytes(hs[pos:pos+2], "big")
            ext_len  = int.from_bytes(hs[pos+2:pos+4], "big")
            pos += 4
            if ext_type == 0x0000:  # SNI
                # server_name_list_length(2) + name_type(1) + name_length(2)
                if ext_len < 5:
                    return None
                name_len = int.from_bytes(hs[pos+3:pos+5], "big")
                return hs[pos+5:pos+5+name_len].decode("ascii", errors="replace")
            pos += ext_len
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze_pcap(
    path: str,
    capture_ip: Optional[str] = None,
) -> tuple[dict[str, DomainStats], dict[str, DomainStats]]:
    """
    Returns (domain_stats, unmatched_stats) where unmatched_stats keys are
    raw IPs for TCP flows not resolved by any DNS answer in the capture.
    """
    print(f"[*] Reading {path} …", flush=True)
    packets = rdpcap(path)
    print(f"[*] Loaded {len(packets):,} packets", flush=True)

    # --- Pass 1: DNS answers → IP-to-domain map ---------------------------
    ip_to_domain: dict[str, str] = {}
    domain_ips: dict[str, set] = defaultdict(set)

    for pkt in packets:
        if DNS not in pkt:
            continue
        dns = pkt[DNS]
        if dns.qr != 1 or dns.ancount == 0:
            continue
        for i in range(dns.ancount):
            try:
                rr = dns.an
                for _ in range(i):
                    rr = rr.payload
                if rr.type in (1, 28):   # A or AAAA
                    name = rr.rrname.decode().rstrip(".")
                    ip = rr.rdata
                    ip_to_domain[ip] = name
                    domain_ips[name].add(ip)
            except Exception:
                continue

    print(f"[*] Resolved {len(ip_to_domain):,} IPs → {len(domain_ips):,} domains via DNS", flush=True)

    # --- Pass 1b: TLS SNI → supplement IP-to-domain map ------------------
    # For each TCP/443 ClientHello, map the server IP to the SNI hostname.
    # This catches flows where DNS was resolved before the capture started.
    sni_count = 0
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        if pkt[TCP].dport != 443:
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue
        sni = extract_sni(payload)
        if sni:
            server_ip = pkt[IP].dst
            if server_ip not in ip_to_domain:
                ip_to_domain[server_ip] = sni
                domain_ips[sni].add(server_ip)
                sni_count += 1
            elif ip_to_domain[server_ip] != sni:
                # DNS gave us a name already; also register under SNI if different
                # (e.g. CDN IP serving multiple hostnames — keep DNS name but note SNI)
                domain_ips[sni].add(server_ip)

    if sni_count:
        print(f"[*] SNI: mapped {sni_count:,} additional IPs from TLS ClientHello", flush=True)
    else:
        print(f"[*] SNI: no new IPs discovered (all already covered by DNS)", flush=True)

    # --- Auto-detect capture IP -------------------------------------------
    if capture_ip is None:
        dns_srcs: dict[str, int] = defaultdict(int)
        for pkt in packets:
            if DNS in pkt and pkt[DNS].qr == 0 and IP in pkt:
                dns_srcs[pkt[IP].src] += 1
        if dns_srcs:
            capture_ip = max(dns_srcs, key=dns_srcs.get)
            print(f"[*] Auto-detected capture IP: {capture_ip}", flush=True)
        else:
            print("[!] Could not auto-detect capture IP; TX/RX will be best-effort", flush=True)

    # --- Pass 2: TCP traffic → domain / unmatched IP ----------------------
    stats: dict[str, DomainStats] = {}
    unmatched: dict[str, DomainStats] = {}   # keyed by remote IP
    seen_seq: set = set()

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        size = ip_pkt_size(pkt)

        # Determine domain or fall back to raw IP
        if dst in ip_to_domain:
            domain = ip_to_domain[dst]
            bucket = stats
        elif src in ip_to_domain:
            domain = ip_to_domain[src]
            bucket = stats
        else:
            # Unmatched: use the remote IP as the key
            remote_ip = dst if (capture_ip and src == capture_ip) else src
            domain = remote_ip
            bucket = unmatched

        if domain not in bucket:
            bucket[domain] = DomainStats(
                domain=domain,
                ips=domain_ips.get(domain, {domain} if bucket is unmatched else set()),
            )

        s = bucket[domain]

        if capture_ip and src == capture_ip:
            s.tx_bytes += size
            s.tx_packets += 1
        else:
            s.rx_bytes += size
            s.rx_packets += 1

        if is_handshake(pkt):
            s.handshake_packets += 1
            s.handshake_bytes += size

        if is_retransmission(pkt, seen_seq):
            s.retrans_packets += 1
            s.retrans_bytes += size

    if unmatched:
        total_u = sum(s.total_packets for s in unmatched.values())
        print(f"[!] {total_u:,} TCP packets across {len(unmatched):,} IPs with no DNS or SNI match "
              f"— shown in second table")

    return stats, unmatched


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

SORT_KEYS = {
    "tx":      lambda s: s.tx_bytes,
    "rx":      lambda s: s.rx_bytes,
    "total":   lambda s: s.total_bytes,
    "tx_pkts": lambda s: s.tx_packets,
    "rx_pkts": lambda s: s.rx_packets,
    "domain":  lambda s: s.domain,
    "retrans": lambda s: s.retrans_pct_packets,
}


IP_WRAP = 4  # max IPs per line before wrapping


def _chunk_ips(ips: list[str]) -> list[str]:
    """Split a sorted IP list into comma-joined chunks of IP_WRAP each."""
    chunks = []
    for i in range(0, max(1, len(ips)), IP_WRAP):
        chunks.append(", ".join(ips[i:i + IP_WRAP]))
    return chunks


def _render_rows(rows: list[DomainStats]) -> list[dict]:
    """Pre-render every cell to a string (ips stored as list of line-chunks)."""
    out = []
    for s in rows:
        sorted_ips = sorted(s.ips)
        out.append({
            "domain":   s.domain,
            "ips":      _chunk_ips(sorted_ips),   # list[str], one entry per printed line
            "tx":       human_bytes(s.tx_bytes),
            "rx":       human_bytes(s.rx_bytes),
            "tx_p":     f"{s.tx_packets:,}",
            "rx_p":     f"{s.rx_packets:,}",
            "hs_pkt":   f"{s.handshake_pct_packets:.1f}%",
            "hs_bw":    f"{s.handshake_pct_bytes:.1f}%",
            "rt_pkt":   f"{s.retrans_pct_packets:.1f}%",
            "rt_bw":    f"{s.retrans_pct_bytes:.1f}%",
        })
    return out


# Fixed column headers (same order as render keys)
_HEADERS = {
    "domain": "Domain",
    "ips":    "IPs",
    "tx":     "TX",
    "rx":     "RX",
    "tx_p":   "TX pkts",
    "rx_p":   "RX pkts",
    "hs_pkt": "HS% pkt",
    "hs_bw":  "HS% bw",
    "rt_pkt": "RT% pkt",
    "rt_bw":  "RT% bw",
}

# Columns that are left-aligned
_LEFT = {"domain", "ips"}


def _compute_widths(rendered: list[dict], totals_row: dict) -> dict[str, int]:
    """Compute per-column widths = max(header, all data, totals row)."""
    cols = list(_HEADERS.keys())
    widths = {c: len(_HEADERS[c]) for c in cols}
    for row in rendered + [totals_row]:
        for c in cols:
            val = row.get(c, "")
            # ips is a list of chunk strings; measure the widest chunk
            if c == "ips" and isinstance(val, list):
                for chunk in val:
                    widths[c] = max(widths[c], len(chunk))
            else:
                widths[c] = max(widths[c], len(val))
    return widths


def _print_table_from_rows(
    rendered: list[dict],
    totals_row: dict,
    title: str,
    sort_by: str,
    count: int,
):
    SEP = "  "  # 2-space gap between columns
    widths = _compute_widths(rendered, totals_row)
    cols = list(_HEADERS.keys())
    # Pre-compute the blank prefix used for IP continuation lines:
    # everything left of the ips column, padded to correct width.
    ip_col_idx = cols.index("ips")
    prefix_width = sum(widths[c] for c in cols[:ip_col_idx]) + len(SEP) * ip_col_idx

    def fmt_main(row: dict) -> str:
        """Format the first (or only) line of a row."""
        parts = []
        for c in cols:
            val = row.get(c, "")
            if c == "ips":
                # first chunk only
                first = val[0] if isinstance(val, list) and val else (val or "")
                parts.append(f"{first:<{widths[c]}}")
            elif c in _LEFT:
                parts.append(f"{val:<{widths[c]}}")
            else:
                parts.append(f"{val:>{widths[c]}}")
        return SEP.join(parts)

    def fmt_ip_continuation(chunk: str) -> str:
        """A line that is blank except for the ips column."""
        return " " * prefix_width + SEP + f"{chunk:<{widths['ips']}}"

    header_row = {c: _HEADERS[c] for c in cols}
    # header ips is just a plain string
    header_row["ips"] = _HEADERS["ips"]
    line = fmt_main(header_row)
    sep_line = "─" * len(line)

    print(f"\n{'━' * len(line)}")
    print(f" {title}  (sorted by {sort_by}, {count} rows)")
    print(sep_line)
    print(line)
    print(sep_line)

    for row in rendered:
        print(fmt_main(row))
        ip_chunks = row.get("ips", [])
        if isinstance(ip_chunks, list):
            for chunk in ip_chunks[1:]:   # continuation lines
                print(fmt_ip_continuation(chunk))

    print(sep_line)
    # totals row has ips="" (plain string)
    print(fmt_main(totals_row))
    print(f"{'━' * len(line)}")


def print_table(
    stats: dict[str, DomainStats],
    unmatched: dict[str, DomainStats],
    sort_by: str = "total",
    min_bytes: int = 0,
):
    sort_fn = SORT_KEYS.get(sort_by, SORT_KEYS["total"])
    reverse = sort_by != "domain"

    for label, bucket in [
        ("● Resolved domains", stats),
        ("○ Unmatched IPs (no DNS or SNI)", unmatched),
    ]:
        rows = [s for s in bucket.values() if s.total_bytes >= min_bytes]
        if not rows:
            if bucket is unmatched:
                print("\n[✓] No unmatched IP traffic.")
            continue

        rows.sort(key=sort_fn, reverse=reverse)
        rendered = _render_rows(rows)

        # Totals row
        total_tx  = sum(s.tx_bytes   for s in rows)
        total_rx  = sum(s.rx_bytes   for s in rows)
        total_txp = sum(s.tx_packets for s in rows)
        total_rxp = sum(s.rx_packets for s in rows)
        totals = {
            "domain": "TOTAL",
            "ips":    "",
            "tx":     human_bytes(total_tx),
            "rx":     human_bytes(total_rx),
            "tx_p":   f"{total_txp:,}",
            "rx_p":   f"{total_rxp:,}",
            "hs_pkt": "", "hs_bw": "", "rt_pkt": "", "rt_bw": "",
        }

        _print_table_from_rows(rendered, totals, label, sort_by, len(rows))


def write_csv(
    stats: dict[str, DomainStats],
    unmatched: dict[str, DomainStats],
    path: str,
    min_bytes: int = 0,
):
    all_rows = list(stats.values()) + list(unmatched.values())
    all_rows = [s for s in all_rows if s.total_bytes >= min_bytes]
    all_rows.sort(key=lambda s: s.total_bytes, reverse=True)

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "domain", "ips", "resolved",
            "tx_bytes", "rx_bytes", "total_bytes",
            "tx_packets", "rx_packets", "total_packets",
            "handshake_packets", "handshake_bytes",
            "handshake_pct_packets", "handshake_pct_bytes",
            "retrans_packets", "retrans_bytes",
            "retrans_pct_packets", "retrans_pct_bytes",
        ])
        for s in all_rows:
            resolved = s.domain not in unmatched
            writer.writerow([
                s.domain, "|".join(sorted(s.ips)), resolved,
                s.tx_bytes, s.rx_bytes, s.total_bytes,
                s.tx_packets, s.rx_packets, s.total_packets,
                s.handshake_packets, s.handshake_bytes,
                f"{s.handshake_pct_packets:.2f}", f"{s.handshake_pct_bytes:.2f}",
                s.retrans_packets, s.retrans_bytes,
                f"{s.retrans_pct_packets:.2f}", f"{s.retrans_pct_bytes:.2f}",
            ])
    print(f"[*] CSV written to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze per-domain bandwidth from a pcap (tcp/443 + DNS/53)"
    )
    parser.add_argument("pcap", help="Path to the .pcap / .pcapng file")
    parser.add_argument(
        "--sort",
        choices=list(SORT_KEYS.keys()),
        default="total",
        help="Sort column (default: total)",
    )
    parser.add_argument(
        "--min-bytes",
        type=int,
        default=0,
        metavar="N",
        help="Hide entries with less than N total bytes (default: 0)",
    )
    parser.add_argument(
        "--capture-ip",
        metavar="IP",
        default=None,
        help="IP address of the captured host (auto-detected if omitted)",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        default=None,
        help="Also write results to a CSV file",
    )
    args = parser.parse_args()

    stats, unmatched = analyze_pcap(args.pcap, capture_ip=args.capture_ip)
    print_table(stats, unmatched, sort_by=args.sort, min_bytes=args.min_bytes)

    if args.csv:
        write_csv(stats, unmatched, args.csv, min_bytes=args.min_bytes)


if __name__ == "__main__":
    main()
