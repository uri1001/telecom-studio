# The Telecom Studio

Network diagnostics and information theory toolkit. Zero external dependencies -- pure Python stdlib.

## Quick Start

```bash
python3 -c "from src.network import basic; print(basic.ping('google.com'))"
```

No install, no virtualenv. Requires Python 3.8+.

## Modules

| Module | Use | Key Functions |
|--------|-----|---------------|
| `network/basic.py` | Core diagnostics | `ping`, `traceroute`, `dns_lookup`, `get_public_ip`, `get_local_ips` |
| `network/scanner.py` | Port and service discovery | `scan_port`, `scan_common_ports`, `service_fingerprint`, `detect_os` |
| `network/performance.py` | Network metrics | `measure_latency`, `bandwidth_test`, `packet_loss_test`, `jitter_analysis`, `mtu_discovery` |
| `network/http.py` | HTTP/TLS testing | `http_get`, `https_verify`, `check_headers_security` |
| `theory/entropy.py` | Information theory | `calculate_entropy`, `file_entropy`, `is_random` |
| `theory/error.py` | Error correction | `hamming_distance`, `add_parity_bit`, `check_parity` |
| `theory/huffman.py` | Compression | `huffman_encode`, `huffman_decode`, `compression_ratio` |

## Key Behaviors

- **Multi-source fallback** -- `get_public_ip()` tries 3 services. `measure_latency()` falls back to ICMP if TCP fails.
- **Parallel scanning** -- `scan_common_ports()` uses 20 concurrent workers. `scan_network_range()` handles up to 50 hosts, capped at /24.
- **ICMP fallback** -- latency measurement retries via subprocess ping when socket-level probes fail.
- **Security scoring** -- `check_headers_security()` scores 0-100% across HSTS, CSP, X-Frame-Options, and more.
- **Cross-platform** -- ping, traceroute, and MTU discovery auto-detect Windows vs Linux flags.

## Return Format

Every function returns a consistent dict:

```python
{'status': 'success', 'host': '...', 'data': {...}}
{'status': 'error', 'error': 'description'}
```

Functions never raise -- errors are returned in the dict.

## Usage

```python
from src.network import basic, scanner, performance, http

# latency with statistics (min, max, avg, median, stdev, packet_loss)
result = performance.measure_latency('google.com', samples=10)

# port scanning with service fingerprinting
result = scanner.service_fingerprint('example.com', 22)

# TLS certificate verification (warns if cert expires in <30 days)
result = http.https_verify('https://example.com')

# security header audit
result = http.check_headers_security('https://example.com')
```

```python
from src.theory import entropy, huffman

# shannon entropy of a file
bits_per_byte = entropy.file_entropy('/path/to/file')

# huffman compression
encoded, codes = huffman.huffman_encode('hello world')
decoded = huffman.huffman_decode(encoded, codes)
```

## Security

Port scanning and network probing require authorization from the target network owner. `scan_network_range()` refuses ranges larger than /24 to prevent accidental mass scanning.

## Author

uri1001
