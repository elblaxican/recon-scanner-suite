# Custom Recon Scanner Suite

A single-pass recon scanner that chains **port scan → service fingerprint → banner grab → CVE match** and prints a **ranked** list of what to hit first.

Stdlib only — no pip installs, runs anywhere Python 3 does.

## Usage

```bash
python scanner_suite.py 192.168.1.10
python scanner_suite.py 10.0.0.5 -p 22,80,3306,6379 -t 0.6
```

| Flag | Meaning |
|------|---------|
| `-p, --ports` | Comma list of ports (else ~30 common ports) |
| `-t, --timeout` | Per-port timeout in seconds (default 0.8) |

## How it ranks

Each open port is scored as `severity × exploit-type` (RCE and auth-bypass CVEs rank highest). High-value targets (score ≥ 60) are listed at the bottom as "hit first".

## Covers

SSH, HTTP/S, FTP, Telnet, Redis, MySQL, PostgreSQL, MongoDB, Elasticsearch, VNC, SMB — plus their top CVEs.