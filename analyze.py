#!/usr/bin/env python3
"""
pcap_bandwidth_analyzer.py
Analyze payload vs overhead bandwidth per domain from a pcap captured with:
    tcp port 443 || port 53

  Payload  = TLS ApplicationData record bodies (encrypted content)
  Overhead = everything else: TCP/IP headers, bare ACKs, TCP+TLS handshakes,
             retransmits, RSTs, TLS record framing headers

Usage:
    python3 pcap_bandwidth_analyzer.py capture.pcap
    python3 pcap_bandwidth_analyzer.py capture.pcap --sort overhead
    python3 pcap_bandwidth_analyzer.py capture.pcap --min-bytes 1024
    python3 pcap_bandwidth_analyzer.py capture.pcap --capture-ip 192.168.1.5

Requirements:
    pip install scapy
"""

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import PcapReader, IP, TCP, DNS
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

    # TLS ApplicationData record bodies only (the actual encrypted content)
    tls_data_bytes: int = 0

    @property
    def total_packets(self):
        return self.tx_packets + self.rx_packets

    @property
    def total_bytes(self):
        return self.tx_bytes + self.rx_bytes

    @property
    def payload_bytes(self):
        """TLS ApplicationData bytes — clamped to total so overhead is never negative."""
        return min(self.tls_data_bytes, self.total_bytes)

    @property
    def overhead_bytes(self):
        return self.total_bytes - self.payload_bytes

    @property
    def payload_pct(self):
        return 100.0 * self.payload_bytes / self.total_bytes if self.total_bytes else 0.0

    @property
    def overhead_pct(self):
        return 100.0 * self.overhead_bytes / self.total_bytes if self.total_bytes else 0.0


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
    return pkt[IP].len if IP in pkt else len(pkt)


def tcp_flags(pkt) -> dict:
    if TCP not in pkt:
        return {}
    f = pkt[TCP].flags
    return {
        "SYN": bool(f & 0x02),
        "FIN": bool(f & 0x01),
        "RST": bool(f & 0x04),
    }


def extract_sni(payload: bytes) -> Optional[str]:
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        record_len = int.from_bytes(payload[3:5], "big")
        if len(payload) < 5 + record_len:
            return None
        hs = payload[5:5 + record_len]
        if hs[0] != 0x01:
            return None
        pos = 1 + 3 + 2 + 32
        sid_len = hs[pos]; pos += 1 + sid_len
        cs_len  = int.from_bytes(hs[pos:pos+2], "big"); pos += 2 + cs_len
        cm_len  = hs[pos]; pos += 1 + cm_len
        if pos + 2 > len(hs):
            return None
        ext_total = int.from_bytes(hs[pos:pos+2], "big"); pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type = int.from_bytes(hs[pos:pos+2], "big")
            ext_len  = int.from_bytes(hs[pos+2:pos+4], "big")
            pos += 4
            if ext_type == 0x0000:
                if ext_len < 5:
                    return None
                name_len = int.from_bytes(hs[pos+3:pos+5], "big")
                return hs[pos+5:pos+5+name_len].decode("ascii", errors="replace")
            pos += ext_len
    except Exception:
        pass
    return None


_TLS_APP_DATA = 0x17
_TLS_VERSIONS = {0x0300, 0x0301, 0x0302, 0x0303, 0x0304}


# ---------------------------------------------------------------------------
# Core analysis — two-pass streaming
# ---------------------------------------------------------------------------

def analyze_pcap(
    path: str,
    capture_ip: Optional[str] = None,
) -> tuple[dict[str, DomainStats], dict[str, DomainStats]]:
    """
    Pass A: DNS + SNI resolution, capture-IP detection.
    Pass B: per-packet accounting + incremental TLS reassembly.
    Peak RAM: O(live flows), not O(all packets).
    """

    # ------------------------------------------------------------------
    # Pass A
    # ------------------------------------------------------------------
    print("[*] Pass A: DNS + SNI + capture-IP …", flush=True)

    ip_to_domain: dict[str, str] = {}
    domain_ips:   dict[str, set] = defaultdict(set)
    dns_srcs:     dict[str, int] = defaultdict(int)
    pkt_count = 0

    with PcapReader(path) as reader:
        for pkt in reader:
            pkt_count += 1

            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 1 and dns.ancount > 0:
                    for i in range(dns.ancount):
                        try:
                            rr = dns.an
                            for _ in range(i):
                                rr = rr.payload
                            if rr.type in (1, 28):
                                name = rr.rrname.decode().rstrip(".")
                                ip   = rr.rdata
                                ip_to_domain[ip] = name
                                domain_ips[name].add(ip)
                        except Exception:
                            continue
                if dns.qr == 0 and IP in pkt:
                    dns_srcs[pkt[IP].src] += 1

            if IP in pkt and TCP in pkt and pkt[TCP].dport == 443:
                raw = bytes(pkt[TCP].payload)
                if raw:
                    sni = extract_sni(raw)
                    if sni:
                        server_ip = pkt[IP].dst
                        if server_ip not in ip_to_domain:
                            ip_to_domain[server_ip] = sni
                            domain_ips[sni].add(server_ip)
                        elif ip_to_domain[server_ip] != sni:
                            domain_ips[sni].add(server_ip)

    print(f"[*] {pkt_count:,} packets | "
          f"{len(ip_to_domain):,} IPs → {len(domain_ips):,} domains", flush=True)

    if capture_ip is None:
        if dns_srcs:
            capture_ip = max(dns_srcs, key=dns_srcs.get)
            print(f"[*] Capture IP: {capture_ip}", flush=True)
        else:
            print("[!] Could not auto-detect capture IP; TX/RX best-effort", flush=True)

    # ------------------------------------------------------------------
    # Pass B
    # ------------------------------------------------------------------
    print("[*] Pass B: accounting + TLS reassembly …", flush=True)

    stats:     dict[str, DomainStats] = {}
    unmatched: dict[str, DomainStats] = {}

    # (src,dst,sport,dport,seq) → retransmit guard; evicted on FIN/RST
    seen_seq: set = set()
    # fkey → [next_expected_seq, bytearray leftover]; at most ~16 KB per live flow
    tls_flow: dict[tuple, list] = {}

    with PcapReader(path) as reader:
        for pkt in reader:
            if IP not in pkt or TCP not in pkt:
                continue

            src   = pkt[IP].src
            dst   = pkt[IP].dst
            size  = ip_pkt_size(pkt)
            flags = tcp_flags(pkt)

            # Domain lookup
            if dst in ip_to_domain:
                domain, bucket = ip_to_domain[dst], stats
            elif src in ip_to_domain:
                domain, bucket = ip_to_domain[src], stats
            else:
                remote_ip      = dst if (capture_ip and src == capture_ip) else src
                domain, bucket = remote_ip, unmatched

            if domain not in bucket:
                bucket[domain] = DomainStats(
                    domain=domain,
                    ips=domain_ips.get(domain, {domain} if bucket is unmatched else set()),
                )
            s = bucket[domain]

            # RST: evict flow state, count toward TX/RX, skip TLS
            if flags.get("RST"):
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                tls_flow.pop((src, dst, sport, dport), None)
                tls_flow.pop((dst, src, dport, sport), None)
                if capture_ip and src == capture_ip:
                    s.tx_bytes += size;  s.tx_packets += 1
                else:
                    s.rx_bytes += size;  s.rx_packets += 1
                continue

            # Retransmission guard — duplicate segments are overhead,
            # count them in TX/RX but skip TLS so we don't double-count payload
            is_retransmit = False
            if len(pkt[TCP].payload) > 0:
                seq_key = (src, dst, pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].seq)
                if seq_key in seen_seq:
                    is_retransmit = True
                else:
                    seen_seq.add(seq_key)

            # TX / RX (IP-level bytes — every packet including retransmits)
            if capture_ip and src == capture_ip:
                s.tx_bytes += size;  s.tx_packets += 1
            else:
                s.rx_bytes += size;  s.rx_packets += 1

            if is_retransmit:
                continue   # skip TLS accounting for retransmits

            # FIN: evict flow state
            if flags.get("FIN"):
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                tls_flow.pop((src, dst, sport, dport), None)
                tls_flow.pop((dst, src, dport, sport), None)

            # TLS reassembly (port 443 only)
            if pkt[TCP].dport != 443 and pkt[TCP].sport != 443:
                continue
            raw = bytes(pkt[TCP].payload)
            if not raw:
                continue

            fkey = (src, dst, pkt[TCP].sport, pkt[TCP].dport)
            seq  = pkt[TCP].seq

            if fkey not in tls_flow:
                # Bind this flow to the domain stats object current at creation
                # time. If the domain mapping changes mid-capture (DNS arrives
                # late), records still drain into the right bucket.
                tls_flow[fkey] = [seq, bytearray(), s]

            state          = tls_flow[fkey]
            next_seq       = state[0]
            buf: bytearray = state[1]
            tls_s          = state[2]   # always the original domain for this flow

            if seq == next_seq:
                buf += raw;   state[0] = seq + len(raw)
            elif seq > next_seq:
                buf.clear();  buf += raw;  state[0] = seq + len(raw)
            else:
                continue   # already-seen retransmit

            # Drain complete TLS records, count only ApplicationData
            pos = 0
            while pos + 5 <= len(buf):
                ct      = buf[pos]
                version = (buf[pos+1] << 8) | buf[pos+2]
                rec_len = (buf[pos+3] << 8) | buf[pos+4]

                if version not in _TLS_VERSIONS or rec_len == 0 or rec_len > 16640:
                    buf.clear(); break

                if pos + 5 + rec_len > len(buf):
                    break   # incomplete — wait for next segment

                if ct == _TLS_APP_DATA:
                    tls_s.tls_data_bytes += rec_len

                pos += 5 + rec_len

            if pos > 0:
                del buf[:pos]

    if unmatched:
        total_u = sum(s.total_packets for s in unmatched.values())
        print(f"[!] {total_u:,} packets / {len(unmatched):,} IPs with no DNS/SNI — "
              f"shown in second table")

    return stats, unmatched


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

SORT_KEYS = {
    "tx":       lambda s: s.tx_bytes,
    "rx":       lambda s: s.rx_bytes,
    "total":    lambda s: s.total_bytes,
    "tx_pkts":  lambda s: s.tx_packets,
    "rx_pkts":  lambda s: s.rx_packets,
    "domain":   lambda s: s.domain,
    "payload":  lambda s: s.payload_bytes,
    "overhead": lambda s: s.overhead_bytes,
    "ovh_pct":  lambda s: s.overhead_pct,
}

IP_WRAP = 4

def _chunk_ips(ips: list[str]) -> list[str]:
    chunks = []
    for i in range(0, max(1, len(ips)), IP_WRAP):
        chunks.append(", ".join(ips[i:i + IP_WRAP]))
    return chunks


_HEADERS = {
    "domain":   "Domain",
    "ips":      "IPs",
    "tx":       "TX",
    "rx":       "RX",
    "tx_p":     "TX pkts",
    "rx_p":     "RX pkts",
    "payload":  "Payload",    # TLS ApplicationData bytes
    "overhead": "Overhead",   # total - payload
    "pay_pct":  "Payload%",   # payload / total IP bytes
    "ovh_pct":  "Overhead%",  # overhead / total IP bytes
}

_LEFT = {"domain", "ips"}


def _render_rows(rows: list[DomainStats]) -> list[dict]:
    out = []
    for s in rows:
        out.append({
            "domain":   s.domain,
            "ips":      _chunk_ips(sorted(s.ips)),
            "tx":       human_bytes(s.tx_bytes),
            "rx":       human_bytes(s.rx_bytes),
            "tx_p":     f"{s.tx_packets:,}",
            "rx_p":     f"{s.rx_packets:,}",
            "payload":  human_bytes(s.payload_bytes),
            "overhead": human_bytes(s.overhead_bytes),
            "pay_pct":  f"{s.payload_pct:.1f}%",
            "ovh_pct":  f"{s.overhead_pct:.1f}%",
        })
    return out


def _compute_widths(rendered: list[dict], totals_row: dict) -> dict[str, int]:
    cols   = list(_HEADERS.keys())
    widths = {c: len(_HEADERS[c]) for c in cols}
    for row in rendered + [totals_row]:
        for c in cols:
            val = row.get(c, "")
            if c == "ips" and isinstance(val, list):
                for chunk in val:
                    widths[c] = max(widths[c], len(chunk))
            else:
                widths[c] = max(widths[c], len(val))
    return widths


def _print_table(rendered, totals_row, title, sort_by, count):
    SEP    = "  "
    widths = _compute_widths(rendered, totals_row)
    cols   = list(_HEADERS.keys())

    ip_idx       = cols.index("ips")
    prefix_width = sum(widths[c] for c in cols[:ip_idx]) + len(SEP) * ip_idx

    def fmt(row: dict) -> str:
        parts = []
        for c in cols:
            val = row.get(c, "")
            if c == "ips":
                first = val[0] if isinstance(val, list) and val else (val or "")
                parts.append(f"{first:<{widths[c]}}")
            elif c in _LEFT:
                parts.append(f"{val:<{widths[c]}}")
            else:
                parts.append(f"{val:>{widths[c]}}")
        return SEP.join(parts)

    def fmt_ip_cont(chunk: str) -> str:
        return " " * prefix_width + SEP + f"{chunk:<{widths['ips']}}"

    header_row        = {c: _HEADERS[c] for c in cols}
    header_row["ips"] = _HEADERS["ips"]
    line     = fmt(header_row)
    thin_sep = "─" * len(line)

    print(f"\n{'━' * len(line)}")
    print(f" {title}  (sorted by {sort_by}, {count} rows)")
    print(thin_sep)
    print(line)
    print(thin_sep)

    for row in rendered:
        print(fmt(row))
        for chunk in (row.get("ips") or [])[1:]:
            print(fmt_ip_cont(chunk))

    print(thin_sep)
    print(fmt(totals_row))
    print(f"{'━' * len(line)}")


def print_table(stats, unmatched, sort_by="total", min_bytes=0):
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

        total_tx  = sum(s.tx_bytes       for s in rows)
        total_rx  = sum(s.rx_bytes       for s in rows)
        total_txp = sum(s.tx_packets     for s in rows)
        total_rxp = sum(s.rx_packets     for s in rows)
        total_pay = sum(s.payload_bytes  for s in rows)
        total_ovh = sum(s.overhead_bytes for s in rows)
        total_all = total_tx + total_rx

        totals = {
            "domain":   "TOTAL",
            "ips":      "",
            "tx":       human_bytes(total_tx),
            "rx":       human_bytes(total_rx),
            "tx_p":     f"{total_txp:,}",
            "rx_p":     f"{total_rxp:,}",
            "payload":  human_bytes(total_pay),
            "overhead": human_bytes(total_ovh),
            "pay_pct":  f"{100*total_pay/total_all:.1f}%" if total_all else "",
            "ovh_pct":  f"{100*total_ovh/total_all:.1f}%" if total_all else "",
        }

        _print_table(rendered, totals, label, sort_by, len(rows))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Per-domain payload vs overhead from a pcap (tcp/443 + DNS/53)"
    )
    parser.add_argument("pcap")
    parser.add_argument(
        "--sort", choices=list(SORT_KEYS.keys()), default="total",
        help="Sort column (default: total)"
    )
    parser.add_argument(
        "--min-bytes", type=int, default=0, metavar="N",
        help="Hide entries with fewer than N total bytes"
    )
    parser.add_argument(
        "--capture-ip", metavar="IP", default=None,
        help="Capture host IP (auto-detected if omitted)"
    )
    args = parser.parse_args()

    stats, unmatched = analyze_pcap(args.pcap, capture_ip=args.capture_ip)
    print_table(stats, unmatched, sort_by=args.sort, min_bytes=args.min_bytes)


if __name__ == "__main__":
    main()
