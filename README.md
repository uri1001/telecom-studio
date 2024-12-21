# The Telecom Studio

Network diagnostics, home networking, and security toolkit. Zero external dependencies -- pure Python stdlib.

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
| `network/home.py` | Home network tools | `discover_lan_devices`, `gateway_health`, `check_connectivity`, `dns_benchmark`, `network_summary` |
| `network/qos.py` | VoIP quality scoring | `estimate_mos`, `voip_quality_report`, `monitor_quality`, `compare_routes` |
| `network/subnet.py` | IP/subnet calculator | `subnet_info`, `vlsm_allocate`, `capacity_report`, `subnet_map`, `eui64_address` |
| `security/password.py` | Password analysis | `analyze_strength`, `estimate_crack_time`, `check_known_patterns`, `generate_passphrase` |
| `security/network.py` | Network security | `arp_table_analysis`, `rogue_dhcp_detection`, `open_port_audit`, `security_audit` |
| `theory/entropy.py` | Information theory | `calculate_entropy`, `file_entropy`, `is_random` |
| `theory/error.py` | Error correction | `hamming_distance`, `add_parity_bit`, `check_parity` |
| `theory/huffman.py` | Compression | `huffman_encode`, `huffman_decode`, `compression_ratio` |

## Key Behaviors

- **Multi-source fallback** -- `get_public_ip()` tries 3 services. `measure_latency()` falls back to ICMP if TCP fails.
- **Parallel scanning** -- `scan_common_ports()` uses 20 concurrent workers. `scan_network_range()` handles up to 50 hosts, capped at /24.
- **ICMP fallback** -- latency measurement retries via subprocess ping when socket-level probes fail.
- **Security scoring** -- `check_headers_security()` scores 0-100% across HSTS, CSP, X-Frame-Options, and more.
- **Cross-platform** -- ping, traceroute, and MTU discovery auto-detect Windows vs Linux flags.
- **Layer-by-layer diagnosis** -- `check_connectivity()` tests gateway, DNS, and internet sequentially to pinpoint failures.
- **ARP anomaly detection** -- `arp_table_analysis()` detects duplicate MACs and IP conflicts for spoofing detection.
- **Password entropy** -- `estimate_crack_time()` reports brute-force time at online, CPU, and GPU attack speeds.
- **VoIP quality scoring** -- ITU-T G.107 E-model for 7 codecs. `monitor_quality()` tracks MOS over time with threshold breach detection.
- **Subnet toolkit** -- CIDR parsing, VLSM allocation, capacity reporting, overlap detection, EUI-64 address generation, and visual subnet maps. Supports both IPv4 and IPv6.

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
from src.network import home

# one-shot connectivity diagnosis (gateway -> DNS -> internet)
result = home.check_connectivity()

# discover all devices on LAN
result = home.discover_lan_devices()

# full network overview
result = home.network_summary()

# compare DNS server speeds
result = home.dns_benchmark()
```

```python
from src.network import qos

# estimate MOS from pre-measured values
result = qos.estimate_mos(latency_ms=50, jitter_ms=5, packet_loss_pct=1.0, codec='G.711')

# full VoIP quality report
result = qos.voip_quality_report('pbx.example.com', codec='G.729')

# monitor quality over 5 minutes
result = qos.monitor_quality('pbx.example.com', duration=300, interval=30, threshold=3.5)

# compare routes in parallel
result = qos.compare_routes(['route1.example.com', 'route2.example.com'], codec='Opus')
```

```python
from src.network import subnet

# subnet information (network, broadcast, usable hosts, masks)
result = subnet.subnet_info('192.168.1.0/24')

# VLSM allocation for variable-sized subnets
result = subnet.vlsm_allocate('10.0.0.0/24', [100, 50, 25])

# check subnet overlap
result = subnet.overlap('10.0.0.0/24', '10.0.0.128/25')

# capacity report with utilization and free blocks
result = subnet.capacity_report('10.0.0.0/16', ['10.0.0.0/20', '10.0.16.0/20'])

# generate IPv6 address from prefix + MAC (EUI-64)
result = subnet.eui64_address('2001:db8::/64', '00:1A:2B:3C:4D:5E')
```

```python
from src.security import password, network

# password strength analysis
result = password.analyze_strength('MyP@ssw0rd!')
result = password.estimate_crack_time('MyP@ssw0rd!')

# generate secure passphrase
result = password.generate_passphrase(word_count=5)

# home network security audit
result = network.security_audit()

# check for ARP spoofing
result = network.arp_table_analysis()

# audit exposed ports
result = network.open_port_audit()
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

The subnet calculator operates entirely offline with no network access -- all computations use Python's `ipaddress` module.

## Author

uri1001
