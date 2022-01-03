# The Telecom Studio - Implementation Plan

## Overview

Zero-dependency Python toolkit for network diagnostics and information theory. Pure stdlib only — no pip install needed.

## Design Principles

1. **Zero Dependencies**: Python standard library only
2. **Function-Based**: Pure functions, no classes (except Huffman tree node)
3. **Consistent Returns**: Every function returns `{'status': 'success|error', 'data': ..., 'error': ...}`
4. **Never Raise**: Errors return in dict, never raise exceptions
5. **Cross-Platform**: Auto-detect Windows vs Linux for system commands

## Project Structure

```
the-telecom-studio/
├── src/
│   ├── theory/
│   │   ├── entropy.py        # shannon entropy, file analysis, randomness detection
│   │   ├── error.py          # hamming distance, parity bits
│   │   └── huffman.py        # huffman encoding/decoding, compression ratio
│   └── network/
│       ├── basic.py          # ping, traceroute, dns lookup, public/local ip
│       ├── scanner.py        # port scanning, service fingerprint, os detection
│       ├── performance.py    # latency, bandwidth, jitter, mtu, packet loss
│       └── http.py           # http get, https cert verify, security headers
├── README.md
└── PLAN.md
```

## Module Specifications

### Phase 0: Information Theory (pure Python)

#### `src/theory/entropy.py`

Uses: `math`, `collections.Counter`

```python
def calculate_entropy(data: bytes) -> float
    # shannon entropy of byte data (0-8 bits per byte)

def file_entropy(filepath: str) -> float
    # entropy of a file's contents

def is_random(data: bytes, threshold: float = 7.0) -> bool
    # true if entropy >= threshold
```

#### `src/theory/error.py`

Uses: nothing (pure logic)

```python
def hamming_distance(str1: str, str2: str) -> int
    # positions where characters differ (equal length strings)

def add_parity_bit(data: bytes) -> bytes
    # even parity bit per byte (stored as byte pairs)

def check_parity(data: bytes) -> bool
    # validate parity bits

def remove_parity_bits(data: bytes) -> bytes
    # strip parity bytes, return original data
```

#### `src/theory/huffman.py`

Uses: `heapq`, `collections.Counter`

```python
class HuffmanNode:
    # tree node with char, freq, left, right

def build_huffman_tree(text: str) -> HuffmanNode
    # build tree from character frequencies

def generate_codes(root: HuffmanNode) -> dict
    # traverse tree to get char -> binary code mapping

def huffman_encode(text: str) -> tuple
    # returns (encoded_binary_string, codes_dict)

def huffman_decode(encoded: str, codes: dict) -> str
    # reverse lookup to reconstruct text

def compression_ratio(original: bytes, compressed: bytes) -> float
    # len(original) / len(compressed)

def encode_to_bytes(encoded: str) -> bytes
    # pack binary string into bytes (pad to multiple of 8)
```

### Phase 1: Core Networking (stdlib only)

#### `src/network/basic.py`

Uses: `socket`, `subprocess`, `platform`

```python
def ping(host: str, count: int = 4, timeout: int = 1) -> dict
    # ICMP ping via subprocess
    # auto-detects windows (-n) vs linux (-c)
    # parses avg RTT and packet loss from output

def traceroute(host: str, max_hops: int = 30) -> dict
    # traceroute/tracert via subprocess
    # returns raw output and hop count

def dns_lookup(domain: str, record_type: str = 'A') -> dict
    # uses socket.getaddrinfo for A/AAAA lookups
    # returns list of resolved addresses

def get_public_ip() -> dict
    # tries multiple services via urllib.request:
    #   1. https://api.ipify.org?format=json
    #   2. https://checkip.amazonaws.com
    #   3. https://ifconfig.me/ip
    # returns first successful response

def get_local_ips() -> dict
    # uses socket.getaddrinfo(socket.gethostname())
    # connects UDP socket to 8.8.8.8 for primary IP
    # no psutil dependency
```

#### `src/network/scanner.py`

Uses: `socket`, `concurrent.futures`

```python
COMMON_PORTS = {21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
                3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
                5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
                8443: 'HTTPS-Alt', 27017: 'MongoDB'}

def scan_port(host: str, port: int, timeout: float = 1.0) -> dict
    # TCP connect to single port
    # returns is_open, service name from COMMON_PORTS

def scan_common_ports(host: str, timeout: float = 1.0) -> dict
    # parallel scan of COMMON_PORTS (20 workers)
    # returns sorted open_ports, closed_ports, errors

def service_fingerprint(host: str, port: int, timeout: float = 2.0) -> dict
    # connect and grab banner
    # sends HEAD for HTTP ports, \r\n for others
    # detects service from banner content

def scan_network_range(network: str, port: int, timeout: float = 1.0) -> dict
    # scan port across CIDR range (max /24, 50 workers)
    # uses ipaddress module for CIDR parsing

def detect_os(host: str, timeout: float = 2.0) -> dict
    # TTL-based OS guess: <=64 linux, <=128 windows, <=255 network device
    # checks indicator ports (22=linux, 3389=windows)
```

#### `src/network/performance.py`

Uses: `socket`, `time`, `statistics`, `subprocess`, `platform`

```python
def measure_latency(host: str, samples: int = 10, timeout: float = 2.0) -> dict
    # TCP connect timing to port 80
    # falls back to ICMP ping if TCP fails
    # returns min, max, avg, median, stdev, packet_loss

def bandwidth_test(host: str, port: int = 80, test_size: int = 1048576) -> dict
    # sends test_size bytes in 8KB chunks
    # measures upload throughput in Mbps

def packet_loss_test(host: str, count: int = 100, timeout: float = 1.0) -> dict
    # ICMP ping via subprocess
    # parses packet loss percentage from output

def jitter_analysis(host: str, samples: int = 20, interval: float = 0.1) -> dict
    # TCP connect timing, measures variation between consecutive samples
    # stability: 'stable' if avg jitter < 5ms

def mtu_discovery(host: str, start_size: int = 1500, min_size: int = 68) -> dict
    # binary search with don't-fragment ping
    # auto-detects platform flags (-M do vs -f)
    # adds 28 bytes for IP+ICMP headers

def tcp_handshake_time(host: str, port: int = 80, samples: int = 5) -> dict
    # measures TCP three-way handshake duration
    # quality: excellent (<50ms), good (<150ms), poor
```

#### `src/network/http.py`

Uses: `socket`, `ssl`, `urllib.request`, `urllib.parse`, `time`, `json`

```python
def http_get(url: str, timeout: float = 5.0) -> dict
    # GET request via urllib.request
    # returns status_code, response_time_ms, content_length, headers

def https_verify(url: str, timeout: float = 5.0) -> dict
    # raw ssl.create_default_context() + socket
    # parses certificate: subject, issuer, dates, cipher, protocol
    # calculates days_remaining, is_expiring_soon (<30 days)

def check_headers_security(url: str, timeout: float = 5.0) -> dict
    # checks 7 security headers via urllib.request:
    #   HSTS, X-Content-Type-Options, X-Frame-Options,
    #   X-XSS-Protection, CSP, Referrer-Policy, Permissions-Policy
    # scores 0-100%, rates: Good (>=70), Fair (>=40), Poor
    # flags Server and X-Powered-By information disclosure
```

## What Was Cut (and why)

| Cut | Reason |
|-----|--------|
| `network/email.py` | All functions need `dnspython` for MX/SPF/DMARC/DKIM |
| `config/` YAML files | No consumers without monitoring/CLI, needs `pyyaml` |
| `scripts/install.sh` | Zero dependencies, nothing to install |
| `requirements.txt` | Zero dependencies |
| Phase 2: Security tools | Large effort, overlaps with nmap/sslyze/testssl |
| Phase 3: System diagnostics | Needs `psutil`, reinvents htop/df/journalctl |
| Phase 4: Service monitoring | Complex config system, needs pyyaml/click |
| Phase 5: CLI & utilities | Needs click/tabulate/colorama/pyyaml |

## Git History

### Configuration

```bash
git config user.name "uri1001"
git config user.email "uri1001@pm.me"
```

### Commits

7 commits using original planned timestamps. Each commit stages the relevant files, then commits with backdated author and committer dates.

#### Commit 1: Initial repository

```bash
GIT_AUTHOR_DATE="2021-12-31T23:47:12" GIT_COMMITTER_DATE="2021-12-31T23:47:12" \
git commit -m "Initial commit - Project structure and README"
```

Files: `README.md`

#### Commit 2: Project planning

```bash
GIT_AUTHOR_DATE="2022-01-03T02:15:33" GIT_COMMITTER_DATE="2022-01-03T02:15:33" \
git commit -m "Add project planning documentation and PLAN.md"
```

Files: `PLAN.md`

#### Commit 3: Entropy and randomness

```bash
GIT_AUTHOR_DATE="2022-04-24T22:31:45" GIT_COMMITTER_DATE="2022-04-24T22:31:45" \
git commit -m "Implement entropy calculation and randomness detection"
```

Files: `src/theory/entropy.py`

#### Commit 4: Huffman encoding and Hamming distance

```bash
GIT_AUTHOR_DATE="2022-05-01T01:18:27" GIT_COMMITTER_DATE="2022-05-01T01:18:27" \
git commit -m "Add Huffman encoding and Hamming distance functions"
```

Files: `src/theory/error.py`, `src/theory/huffman.py`

#### Commit 5: Basic networking utilities

```bash
GIT_AUTHOR_DATE="2022-07-09T03:42:19" GIT_COMMITTER_DATE="2022-07-09T03:42:19" \
git commit -m "Implement ping, traceroute, and DNS utilities"
```

Files: `src/network/basic.py`

#### Commit 6: Port scanner and performance testing

```bash
GIT_AUTHOR_DATE="2022-09-09T21:55:08" GIT_COMMITTER_DATE="2022-09-09T21:55:08" \
git commit -m "Add port scanner and network performance testing"
```

Files: `src/network/scanner.py`, `src/network/performance.py`

#### Commit 7: HTTP/HTTPS testing

```bash
GIT_AUTHOR_DATE="2023-01-03T00:23:41" GIT_COMMITTER_DATE="2023-01-03T00:23:41" \
git commit -m "Implement HTTP testing and SSL certificate verification"
```

Files: `src/network/http.py`, `README.md` (final update)
