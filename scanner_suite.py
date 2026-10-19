#!/usr/bin/env python3
"""
Custom recon scanner suite.
Chains: port scan -> service fingerprint -> banner grab -> CVE match -> ranked output.

Stdlib only. Run:
    python scanner_suite.py 192.168.1.10
    python scanner_suite.py 192.168.1.10 --timeout 0.6 -p 22,80,3306,6379,5432
"""

import socket
import struct
import argparse
import sys

# ---------------------------------------------------------------- ports
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    587, 636, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900,
    5984, 6379, 8000, 8080, 8443, 9200, 27017,
]

PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    587: "smtp-subm", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

# ---------------------------------------------------------- CVE database
# version constraints are a comma list of comparisons: >=X, <Y, ==X, <=X
CVE_DB = [
    # ssh (OpenSSH)
    {"service": "ssh", "cve": "CVE-2023-48795", "sev": "critical", "type": "rce",
     "ver": ">=8.5, <9.6p1", "desc": "regreSSHion - auth bypass to RCE via signal handling", "exp": "PoC"},
    {"service": "ssh", "cve": "CVE-2020-14145", "sev": "medium", "type": "info",
     "ver": ">=8.2", "desc": "KEX algorithm preference (downgrade)", "exp": "-"},
    {"service": "ssh", "cve": "CVE-2018-15473", "sev": "low", "type": "info",
     "ver": "<8.8", "desc": "username enumeration on auth fail", "exp": "-"},
    # http / apache
    {"service": "http", "cve": "CVE-2021-41773", "sev": "high", "type": "lfi",
     "ver": "==2.4.49, >=2.4.32, <2.4.50", "desc": "Apache path traversal -> RCE", "exp": "PoC"},
    {"service": "http", "cve": "CVE-2014-0160", "sev": "critical", "type": "rce",
     "ver": "==1.0.1e, ==1.0.1f", "desc": "OpenSSL Heartbleed (if using OpenSSL)", "exp": "PoC"},
    # redis
    {"service": "redis", "cve": "CVE-2015-8080", "sev": "high", "type": "rce",
     "ver": "<2.8.19", "desc": "Redis Lua RCE (default unauth + Lua)", "exp": "PoC"},
    {"service": "redis", "cve": "CVE-2022-0543", "sev": "critical", "type": "rce",
     "ver": "<6.2.7", "desc": "Lua sandbox escape -> arbitrary file read/write", "exp": "PoC"},
    # mysql
    {"service": "mysql", "cve": "CVE-2023-21933", "sev": "high", "type": "rce",
     "ver": ">=5.7.0, <5.7.40, >=8.0.0, <8.0.33", "desc": "deserialization RCE via plugin (UAF)", "exp": "PoC"},
    {"service": "mysql", "cve": "CVE-2016-4082", "sev": "high", "type": "rce",
     "ver": "==5.7.10, <5.7.8", "desc": "UAF -> RCE (5.7.x)", "exp": "PoC"},
    # postgresql
    {"service": "postgresql", "cve": "CVE-2019-9193", "sev": "high", "type": "priv",
     "ver": "<12.1", "desc": "permission change -> local priv-esc", "exp": "PoC"},
    # mssql
    {"service": "mssql", "cve": "CVE-2022-26980", "sev": "high", "type": "priv",
     "ver": "==2019, <14.0.3248.1", "desc": "MSSQL priv escalation (SSRF)", "exp": "PoC"},
    # mongodb
    {"service": "mongodb", "cve": "CVE-2019-0708", "sev": "high", "type": "priv",
     "ver": "<4.1.7, ==4.0.8", "desc": "JS eval priv-esc on unauth (default no-auth)", "exp": "PoC"},
    # elasticsearch
    {"service": "elasticsearch", "cve": "CVE-2014-3120", "sev": "critical", "type": "rce",
     "ver": "<1.3.6, >=0.90", "desc": "scripting engine RCE (MVEL)", "exp": "PoC"},
    # ftp
    {"service": "ftp", "cve": "CVE-2011-2523", "sev": "high", "type": "rce",
     "ver": "==3.2.1, <1.3.4", "desc": "ProFTPD mod_auth_pam RCE", "exp": "PoC"},
    # vnc
    {"service": "vnc", "cve": "CVE-2017-1000255", "sev": "high", "type": "auth",
     "ver": "<1.12.2", "desc": "TightVNC auth bypass (default creds)", "exp": "PoC"},
]

SEV_WEIGHT = {"critical": 10, "high": 8, "medium": 5, "low": 3}
TYPE_WEIGHT = {"rce": 10, "auth": 9, "priv": 7, "lfi": 8, "info": 2}

# ------------------------------------------------------------- version cmp
def parse_ver(v):
    v = v.lstrip("v").split("-")[0].split("+")[0]
    nums, i = [], 0
    for c in v:
        if c.isdigit():
            i = i * 10 + int(c)
        elif i:
            nums.append(i); i = 0
    if i:
        nums.append(i)
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums[:4])

def ver_ok(version, constraint):
    if not version or not constraint:
        return True
    v = parse_ver(version)
    for part in constraint.split(","):
        part = part.strip()
        op, val = part[:2], part[2:] if part[:2] in (">=", "<=", "==") else part[1:]
        if op == "==":
            if v[:len(parse_ver(val))] != parse_ver(val):
                return False
        elif op == ">=" and v < parse_ver(val):
            return False
        elif op == "<=" and v > parse_ver(val):
            return False
        elif op == ">" and v <= parse_ver(val):
            return False
        elif op == "<" and v >= parse_ver(val):
            return False
    return True

# ---------------------------------------------------------- banner grab
def _recv(sock, n=4096, timeout=1.0):
    sock.settimeout(timeout)
    buf = b""
    while n > 0:
        try:
            d = sock.recv(n)
            if not d:
                break
        except socket.timeout:
            break
        buf += d
        n -= len(d)
    return buf

def grab(ip, port, svc, timeout=1.0):
    """Return (service, version, banner) after a per-service probe."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return svc, None, ""
    try:
        if svc == "ssh":
            b = _recv(s, 256, timeout).decode("utf-8", "ignore").strip()
            v = b.split("SSH-2.0-")[-1].split(" ")[0] if "SSH-2.0-" in b else None
            return "ssh", v, b
        if svc in ("http", "https"):
            s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            b = _recv(s, 2048, timeout).decode("utf-8", "ignore")
            v = None
            for line in b.split("\r\n"):
                if line.lower().startswith("server:"):
                    v = line.split(":", 1)[1].strip()
            return svc, v, b.split("\r\n")[0]
        if svc == "ftp":
            b = _recv(s, 256, timeout).decode("utf-8", "ignore").strip()
            v = None
            if "ProFTPD" in b:
                v = b.split("ProFTPD")[-1].strip().split(" ")[0]
            elif "vsFTP" in b:
                v = b.split("vsFTPd")[-1].strip().split(" ")[0]
            return "ftp", v, b
        if svc == "telnet":
            b = _recv(s, 128, timeout).decode("utf-8", "ignore").strip()
            return "telnet", None, b
        if svc == "redis":
            s.sendall(b"INFO server\r\n")
            b = _recv(s, 4096, timeout).decode("utf-8", "ignore")
            v = None
            for line in b.split("\r\n"):
                if line.startswith("redis_version:"):
                    v = line.split(":")[1].strip()
            return "redis", v, "redis_version:" + (v or "?")
        if svc == "mysql":
            raw = _recv(s, 256, timeout)
            v = None
            if len(raw) > 4 and raw[3] == 0:
                i = 5
                while i < len(raw) and raw[i] != 0:
                    i += 1
                v = raw[5:i].decode("utf-8", "ignore")
            return "mysql", v, "mysql handshake"
        if svc == "postgresql":
            b = _recv(s, 128, timeout).decode("utf-8", "ignore").strip()
            return "postgresql", None, b or "postgres"
        if svc == "mongodb":
            return "mongodb", None, "mongo"
        if svc == "elasticsearch":
            s.sendall(b"GET /\r\n")
            b = _recv(s, 512, timeout).decode("utf-8", "ignore")
            for line in b.split("\r\n"):
                if line.lower().startswith("x-elastic:"):
                    return "elasticsearch", line.split("elasticsearch/")[1].split(",")[0].strip(), line
            return "elasticsearch", None, b[:80]
        if svc == "vnc":
            b = _recv(s, 16, timeout).decode("utf-8", "ignore").strip()
            v = b.replace("RFB ", "").split(" ")[0] or None
            return "vnc", v, b
        if svc == "smb":
            s.sendall(b"\xfeSMB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            b = _recv(s, 512, timeout)
            return "smb", None, "smb " + (b[:4].hex() if b else "")
        return svc, None, _recv(s, 128, timeout).decode("utf-8", "ignore")[:80]
    finally:
        s.close()

# ------------------------------------------------------------- main scan
def scan(ip, ports, timeout=0.8, quiet=False):
    results = []
    for port in ports:
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
        except OSError:
            continue
        svc = PORT_SERVICE.get(port, f"unknown-{port}")
        service, version, banner = grab(ip, port, svc, timeout)
        cves = [c for c in CVE_DB if c["service"] == service and ver_ok(version, c["ver"])]
        results.append({"port": port, "service": service, "version": version,
                        "banner": banner, "cves": cves})
        if not quiet:
            print(f"  {port:>5}  {service:<12} {str(version):<14} {len(cves)} CVE(s)")
    return results

def rank(results):
    rows = []
    for r in results:
        if not r["cves"]:
            score = 0
            top = ""
        else:
            top = max(r["cves"], key=lambda c: SEV_WEIGHT[c["sev"]] * TYPE_WEIGHT[c["type"]])
            score = SEV_WEIGHT[top["sev"]] * TYPE_WEIGHT[top["type"]]
        rows.append({**r, "score": score, "top": top})
    rows.sort(key=lambda x: (-x["score"], -SEV_WEIGHT.get(x["top"]["sev"], 0) if x["top"] else 0))
    return rows

def main():
    ap = argparse.ArgumentParser(description="Custom recon scanner suite")
    ap.add_argument("host")
    ap.add_argument("-p", "--ports", help="comma list, else top ~30")
    ap.add_argument("-t", "--timeout", type=float, default=0.8)
    args = ap.parse_args()

    ports = [int(p) for p in args.ports.split(",")] if args.ports else DEFAULT_PORTS
    print(f"[*] scanning {args.host}  ({len(ports)} ports, {args.timeout}s timeout)\n")

    open_ = scan(args.host, ports, args.timeout, quiet=True)
    if not open_:
        print("no open ports found"); return

    rows = rank(open_)
    print(f"{'RANK':<5} {'PORT':<6} {'SERVICE':<14} {'VERSION':<14} {'SCORE':<6} {'CVE':<16} {'TYPE':<7} DESCRIPTION")
    print("-" * 100)
    for i, r in enumerate(rows, 1):
        if r["top"]:
            print(f"{i:<5} {r['port']:<6} {r['service']:<14} {str(r['version']):<14} {r['score']:<6} "
                  f"{r['top']['cve']:<16} {r['top']['type']:<7} {r['top']['desc']}")
        else:
            print(f"{i:<5} {r['port']:<6} {r['service']:<14} {str(r['version']):<14} {'-':<6} {'-':<16} {'-':<7} (no known CVE, low priority)")

    hits = [r for r in rows if r["score"] >= 60]
    print(f"\n[*] {len(hits)} high-value target(s) to hit first:")
    for r in hits:
        print(f"    :{r['port']}  {r['top']['cve']}  {r['top']['exp']}")

if __name__ == "__main__":
    main()