#!/usr/bin/env python3
"""
scanner.py
High-performance TCP port scanner engine (SYN + CONNECT fallback)
Requires: Python 3.8+, scapy, lxml (optional for XML output)

Install:
    pip install scapy lxml

Usage examples:
    sudo python3 scanner.py --mode syn --targets 192.168.1.0/28 --ports 22-1024 --rate 1000 --timeout 2 --out results.json
    python3 scanner.py --mode connect --targets 127.0.0.1 --ports 1-1024 --workers 200 --out results.json --dry-run
"""
import argparse
import asyncio
import ipaddress
import json
import os
import socket
import time
import threading
from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Optional

# External libs
from scapy.all import IP, TCP, send, sniff, conf, AsyncSniffer  # scapy
from lxml import etree  # for nmap-compatible xml output (optional)


@dataclass
class ScanResult:
    target: str
    port: int
    state: str  # open | closed | filtered | unknown | dry-run
    rtt: Optional[float] = None
    banner: Optional[str] = None


class TokenBucket:
    """Simple token bucket for rate limiting events/sec."""
    def __init__(self, rate: float, capacity: float = None):
        self.rate = float(rate)
        self.capacity = capacity or self.rate
        self.tokens = self.capacity
        self.timestamp = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.timestamp
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.timestamp = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    async def wait_for_token(self):
        while not self.consume(1.0):
            await asyncio.sleep(max(0.001, 1.0 / self.rate))


class PortScanner:
    def __init__(self,
                 targets: List[str],
                 ports: List[int],
                 mode: str = "syn",
                 rate: int = 1000,
                 workers: int = 300,
                 timeout: float = 2.0,
                 dry_run: bool = False,
                 whitelist: Optional[List[str]] = None):
        self.targets = targets
        self.ports = ports
        self.mode = mode
        self.rate = rate
        self.workers = workers
        self.timeout = timeout
        self.dry_run = dry_run
        self.whitelist = whitelist
        self.results: List[ScanResult] = []
        self._token_bucket = TokenBucket(rate=max(1, rate))
        self._results_lock = threading.Lock()
        conf.verb = 0  # silence scapy prints

    # -------------------------
    # Utilities
    # -------------------------
    @staticmethod
    def expand_targets(targets: List[str]) -> List[str]:
        out = []
        for t in targets:
            if '/' in t:
                net = ipaddress.ip_network(t, strict=False)
                for ip in net.hosts():
                    out.append(str(ip))
            else:
                out.append(t)
        return out

    @staticmethod
    def expand_ports(port_spec: str) -> List[int]:
        ports = set()
        for part in port_spec.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                a, b = part.split('-', 1)
                ports.update(range(int(a), int(b) + 1))
            else:
                ports.add(int(part))
        return sorted(p for p in ports if 0 < p <= 65535)

    def check_whitelist(self, ip: str) -> bool:
        if not self.whitelist:
            return True
        for w in self.whitelist:
            if '/' in w:
                net = ipaddress.ip_network(w, strict=False)
                if ipaddress.ip_address(ip) in net:
                    return True
            else:
                if ip == w:
                    return True
        return False

    # -------------------------
    # SYN mode (requires root)
    # -------------------------
    def _build_syn(self, dst_ip: str, dst_port: int, src_port: int = None):
        tcp = TCP(dport=dst_port, flags="S", sport=src_port or 12345, seq=1000)
        pkt = IP(dst=dst_ip) / tcp
        return pkt

    async def _send_syn(self, dst_ip: str, dst_port: int):
        if not self.check_whitelist(dst_ip):
            return
        if self.dry_run:
            with self._results_lock:
                self.results.append(ScanResult(dst_ip, dst_port, "dry-run"))
            return
        await self._token_bucket.wait_for_token()
        pkt = self._build_syn(dst_ip, dst_port)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: send(pkt, verbose=0))

    def _pcap_callback(self, pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip = pkt[IP]
            tcp = pkt[TCP]
            src = ip.src
            sport = tcp.sport
            flags = tcp.flags
            state = None
            if flags & 0x12 == 0x12:
                state = "open"
            elif flags & 0x14 == 0x14 or flags & 0x04 == 0x04:
                state = "closed"
            if state:
                r = ScanResult(target=src, port=sport, state=state)
                with self._results_lock:
                    self.results.append(r)

    async def run_syn(self, iface: Optional[str] = None):
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError("SYN mode requires root privileges (raw socket & pcap access).")
        targets = self.expand_targets(self.targets)

        sniffer = AsyncSniffer(prn=self._pcap_callback, iface=iface, store=False)
        sniffer.start()

        async def sender_worker():
            for ip in targets:
                for port in self.ports:
                    await self._send_syn(ip, port)

        sender = asyncio.create_task(sender_worker())
        await sender

        await asyncio.sleep(max(0.5, self.timeout / 2))
        sniffer.stop()

        with self._results_lock:
            dedup: Dict[Tuple[str, int], ScanResult] = {}
            for r in self.results:
                key = (r.target, r.port)
                prev = dedup.get(key)
                if prev is None:
                    dedup[key] = r
                else:
                    order = {"open": 3, "closed": 2, "filtered": 1, "unknown": 0, "dry-run": 0}
                    if order.get(r.state, 0) > order.get(prev.state, 0):
                        dedup[key] = r
            self.results = list(dedup.values())

    # -------------------------
    # CONNECT mode (no root)
    # -------------------------
    async def _try_connect(self, target: str, port: int):
        start = time.monotonic()
        if self.dry_run:
            with self._results_lock:
                self.results.append(ScanResult(target, port, "dry-run"))
            return
        try:
            fut = asyncio.open_connection(host=target, port=port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
            rtt = time.monotonic() - start
            with self._results_lock:
                self.results.append(ScanResult(target, port, "open", rtt=rtt))
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except (asyncio.TimeoutError, ConnectionRefusedError):
            with self._results_lock:
                self.results.append(ScanResult(target, port, "closed"))
        except Exception:
            with self._results_lock:
                self.results.append(ScanResult(target, port, "filtered"))

    async def run_connect(self):
        targets = self.expand_targets(self.targets)
        sem = asyncio.Semaphore(self.workers)

        async def worker(tgt, prt):
            async with sem:
                await self._try_connect(tgt, prt)

        tasks = []
        for t in targets:
            if not self.check_whitelist(t):
                continue
            for p in self.ports:
                tasks.append(asyncio.create_task(worker(t, p)))
        await asyncio.gather(*tasks)

    # -------------------------
    # Output
    # -------------------------
    def to_json(self, path: str):
        with self._results_lock:
            data = [asdict(r) for r in sorted(self.results, key=lambda x: (x.target, x.port))]
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({"generated": time.time(), "results": data}, f, indent=2)

    def to_nmap_xml(self, path: str, scanner_name: str = "CustomScanner"):
        root = etree.Element("nmaprun", scanner=scanner_name, startstr=str(int(time.time())))
        with self._results_lock:
            for tgt in sorted({r.target for r in self.results}):
                host = etree.SubElement(root, "host")
                etree.SubElement(host, "address", addr=tgt, addrtype="ipv4")
                ports_el = etree.SubElement(host, "ports")
                for r in sorted([x for x in self.results if x.target == tgt], key=lambda y: y.port):
                    p_el = etree.SubElement(ports_el, "port", protocol="tcp", portid=str(r.port))
                    etree.SubElement(p_el, "state", state=r.state)
                    if r.rtt:
                        etree.SubElement(p_el, "times", srtt=str(int(r.rtt * 1000)))
        tree = etree.ElementTree(root)
        tree.write(path, pretty_print=True, xml_declaration=True, encoding='utf-8')

    # -------------------------
    # Orchestration
    # -------------------------
    async def run(self, iface: Optional[str] = None):
        if self.mode == "syn":
            await self.run_syn(iface=iface)
        else:
            await self.run_connect()


# -------------------------
# CLI
# -------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="High-performance port scanner (SYN / CONNECT)")
    ap.add_argument("--mode", choices=["syn", "connect"], default="syn", help="Scan mode")
    ap.add_argument("--targets", required=True, help="Comma-separated IPs or CIDRs")
    ap.add_argument("--ports", required=True, help="Port list, e.g. 22,80,443,8000-8100")
    ap.add_argument("--rate", type=int, default=1000, help="Packets per second (approx) for SYN mode")
    ap.add_argument("--workers", type=int, default=300, help="Concurrency for connect mode")
    ap.add_argument("--timeout", type=float, default=2.0, help="Per-port timeout (seconds)")
    ap.add_argument("--iface", default=None, help="Network interface for pcap sniffing (SYN mode)")
    ap.add_argument("--out", default=None, help="Write JSON output to path")
    ap.add_argument("--xml", default=None, help="Write Nmap-compatible XML output to path")
    ap.add_argument("--dry-run", action="store_true", help="Don't actually send packets")
    ap.add_argument("--whitelist", default=None, help="Comma-separated allowed IPs/CIDRs (safety)")
    return ap.parse_args()


def main():
    args = parse_args()
    targets = [t.strip() for t in args.targets.split(',') if t.strip()]
    ports = PortScanner.expand_ports(args.ports)
    whitelist = [w.strip() for w in args.whitelist.split(',')] if args.whitelist else None

    sc = PortScanner(
        targets=targets,
        ports=ports,
        mode=args.mode,
        rate=args.rate,
        workers=args.workers,
        timeout=args.timeout,
        dry_run=args.dry_run,
        whitelist=whitelist,
    )
    try:
        asyncio.run(sc.run(iface=args.iface))
    except PermissionError as e:
        print("Permission error:", e)
        print("SYN mode requires root. Either run with sudo or use --mode connect")
        return

    if args.out:
        sc.to_json(args.out)
        print(f"Wrote JSON to {args.out}")
    else:
        print(json.dumps([asdict(r) for r in sc.results], indent=2))

    if args.xml:
        sc.to_nmap_xml(args.xml)
        print(f"Wrote Nmap-like XML to {args.xml}")


if __name__ == "__main__":
    main()
