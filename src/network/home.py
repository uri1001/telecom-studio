#!/usr/bin/env python3
"""
home.py - Home Network Diagnostics
Day-to-day home network troubleshooting tools using only stdlib.
"""

import re
import socket
import subprocess
import platform
import time
import ipaddress
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional


def _get_default_gateway() -> Optional[str]:
    """detect the default gateway ip."""
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(
                ['ipconfig'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        else:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def _get_primary_ip() -> Optional[str]:
    """get primary local ip via udp connect trick."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _ping_host(host: str, timeout: float = 1.0) -> Optional[float]:
    """ping a single host, return rtt in ms or None if unreachable."""
    try:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, 80))
        elapsed = (time.perf_counter() - start) * 1000
        sock.close()

        if result == 0:
            return round(elapsed, 2)

        # fallback to icmp ping
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_flag = '-w' if platform.system().lower() == 'windows' else '-W'
        cmd = ['ping', param, '1', timeout_flag, str(int(timeout)), host]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)

        if res.returncode == 0:
            for line in res.stdout.split('\n'):
                if 'time=' in line:
                    time_str = line.split('time=')[1].split()[0]
                    return float(time_str.replace('ms', ''))
        return None
    except Exception:
        return None


def discover_lan_devices(network: str = None, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Discover devices on the local network via ping sweep + reverse DNS.

    Args:
        network: CIDR notation (e.g. '192.168.1.0/24'). Auto-detects if None.
        timeout: Timeout per host in seconds.

    Returns:
        Dict with discovered devices and their hostnames.
    """
    try:
        if not network:
            primary_ip = _get_primary_ip()
            if not primary_ip:
                return {
                    'status': 'error',
                    'error': 'Could not detect local network'
                }
            network = f"{primary_ip}/24"

        net = ipaddress.ip_network(network, strict=False)

        if net.num_addresses > 256:
            return {
                'status': 'error',
                'network': network,
                'error': 'Network too large. Maximum /24 supported'
            }

        devices = []
        start_time = time.perf_counter()

        def probe_host(ip_str):
            rtt = _ping_host(ip_str, timeout)
            if rtt is not None:
                hostname = None
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except Exception:
                    pass
                return {'ip': ip_str, 'hostname': hostname, 'response_time_ms': rtt}
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(probe_host, str(ip)): str(ip)
                for ip in net.hosts()
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    devices.append(result)

        scan_time = round(time.perf_counter() - start_time, 2)
        devices.sort(key=lambda d: socket.inet_aton(d['ip']))

        return {
            'status': 'success',
            'network': network,
            'devices': devices,
            'total_found': len(devices),
            'scan_time_s': scan_time
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def gateway_health(timeout: float = 2.0) -> Dict[str, Any]:
    """
    Check default gateway reachability and admin interface.

    Args:
        timeout: Timeout for checks in seconds.

    Returns:
        Dict with gateway health status.
    """
    try:
        gateway_ip = _get_default_gateway()
        if not gateway_ip:
            return {
                'status': 'error',
                'error': 'Could not detect default gateway'
            }

        # ping gateway
        is_windows = platform.system().lower() == 'windows'
        count_flag = '-n' if is_windows else '-c'
        timeout_flag = '-w' if is_windows else '-W'
        timeout_val = str(int(timeout * 1000)) if is_windows else str(int(timeout))

        cmd = ['ping', count_flag, '4', timeout_flag, timeout_val, gateway_ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 4 + 2)

        is_reachable = result.returncode == 0
        latency_ms = None
        packet_loss = 100.0

        if is_reachable:
            for line in result.stdout.split('\n'):
                if 'avg' in line or 'Average' in line:
                    parts = line.split('/')
                    if len(parts) >= 5:
                        latency_ms = float(parts[4].split()[0])
                if 'packet loss' in line or '% loss' in line:
                    for part in line.split():
                        if '%' in part:
                            packet_loss = float(part.replace('%', '').replace(',', ''))
                            break

        # check admin interface
        admin_open = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            admin_open = sock.connect_ex((gateway_ip, 80)) == 0
            sock.close()
        except Exception:
            pass

        return {
            'status': 'success',
            'gateway_ip': gateway_ip,
            'is_reachable': is_reachable,
            'latency_ms': latency_ms,
            'packet_loss': packet_loss,
            'admin_interface_open': admin_open
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def interface_info() -> Dict[str, Any]:
    """
    List network interfaces with IP, MAC, and status.

    Returns:
        Dict with interface details and optional WiFi info.
    """
    try:
        interfaces = []

        if platform.system().lower() == 'windows':
            result = subprocess.run(
                ['ipconfig', '/all'], capture_output=True, text=True, timeout=5
            )
            current = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.endswith(':') and not line.startswith(' '):
                    if current.get('name'):
                        interfaces.append(current)
                    current = {'name': line.rstrip(':'), 'is_up': True}
                elif 'IPv4 Address' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        current['ip'] = match.group(1)
                elif 'Subnet Mask' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        current['netmask'] = match.group(1)
                elif 'Physical Address' in line:
                    match = re.search(r'([0-9A-Fa-f-]{17})', line)
                    if match:
                        current['mac'] = match.group(1).replace('-', ':')
            if current.get('name'):
                interfaces.append(current)
        else:
            result = subprocess.run(
                ['ip', 'addr'], capture_output=True, text=True, timeout=5
            )
            current = {}
            for line in result.stdout.split('\n'):
                # interface line: "2: eth0: <...> state UP ..."
                iface_match = re.match(r'\d+:\s+(\S+):', line)
                if iface_match:
                    if current.get('name'):
                        interfaces.append(current)
                    name = iface_match.group(1)
                    is_up = 'UP' in line
                    current = {'name': name, 'is_up': is_up}
                elif 'inet ' in line:
                    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if match:
                        current['ip'] = match.group(1)
                        # convert cidr to netmask
                        prefix = int(match.group(2))
                        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                        current['netmask'] = socket.inet_ntoa(mask.to_bytes(4, 'big'))
                elif 'link/ether' in line:
                    match = re.search(r'link/ether\s+([0-9a-f:]{17})', line)
                    if match:
                        current['mac'] = match.group(1)
            if current.get('name'):
                interfaces.append(current)

            # enrich wifi interfaces
            try:
                with open('/proc/net/wireless', 'r') as f:
                    lines = f.readlines()[2:]  # skip headers
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = parts[0].rstrip(':')
                        link_quality = parts[2].rstrip('.')
                        signal_level = parts[3].rstrip('.')
                        for iface in interfaces:
                            if iface['name'] == iface_name:
                                iface['wifi'] = {
                                    'link_quality': int(float(link_quality)),
                                    'signal_dbm': int(float(signal_level))
                                }
            except Exception:
                pass

        return {
            'status': 'success',
            'interfaces': interfaces,
            'total': len(interfaces)
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'interfaces': []
        }


def check_connectivity(timeout: float = 3.0) -> Dict[str, Any]:
    """
    Test gateway, DNS, and internet connectivity in sequence.

    Args:
        timeout: Timeout per check in seconds.

    Returns:
        Dict with per-layer status and overall diagnosis.
    """
    try:
        result = {
            'status': 'success',
            'gateway': {'reachable': False, 'latency_ms': None},
            'dns': {'working': False, 'resolve_time_ms': None},
            'internet': {'reachable': False, 'latency_ms': None},
            'overall': 'gateway_down'
        }

        # layer 1: gateway
        gateway_ip = _get_default_gateway()
        if gateway_ip:
            rtt = _ping_host(gateway_ip, timeout)
            if rtt is not None:
                result['gateway'] = {'reachable': True, 'latency_ms': rtt}

        if not result['gateway']['reachable']:
            result['overall'] = 'gateway_down'
            return result

        # layer 2: dns
        try:
            start = time.perf_counter()
            socket.getaddrinfo('google.com', 80)
            elapsed = (time.perf_counter() - start) * 1000
            result['dns'] = {'working': True, 'resolve_time_ms': round(elapsed, 2)}
        except Exception:
            result['overall'] = 'dns_issue'
            return result

        # layer 3: internet
        try:
            start = time.perf_counter()
            req = urllib.request.Request(
                'http://example.com',
                headers={'User-Agent': 'TelecomStudio/1.0'}
            )
            urllib.request.urlopen(req, timeout=timeout)
            elapsed = (time.perf_counter() - start) * 1000
            result['internet'] = {'reachable': True, 'latency_ms': round(elapsed, 2)}
            result['overall'] = 'all_good'
        except Exception:
            result['overall'] = 'internet_unreachable'

        return result
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def dns_benchmark(
    domains: List[str] = None,
    servers: List[str] = None,
    samples: int = 3
) -> Dict[str, Any]:
    """
    Benchmark DNS resolution speed across multiple servers.

    Args:
        domains: Domains to resolve. Defaults to popular sites.
        servers: DNS server IPs to test. Defaults to Google, Cloudflare, Quad9.
        samples: Measurements per server.

    Returns:
        Dict with per-server timing and fastest recommendation.
    """
    try:
        if not domains:
            domains = ['google.com', 'amazon.com', 'github.com']
        if not servers:
            servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

        results = []

        # benchmark system default dns
        system_times = []
        for domain in domains:
            for _ in range(samples):
                try:
                    start = time.perf_counter()
                    socket.getaddrinfo(domain, 80)
                    elapsed = (time.perf_counter() - start) * 1000
                    system_times.append(elapsed)
                except Exception:
                    pass

        system_avg = round(sum(system_times) / len(system_times), 2) if system_times else None
        results.append({
            'server': 'system',
            'avg_ms': system_avg,
            'min_ms': round(min(system_times), 2) if system_times else None,
            'max_ms': round(max(system_times), 2) if system_times else None
        })

        # benchmark each dns server via udp probe
        for server in servers:
            times = []
            for domain in domains:
                for _ in range(samples):
                    try:
                        # build minimal dns query
                        query = _build_dns_query(domain)
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(2.0)

                        start = time.perf_counter()
                        sock.sendto(query, (server, 53))
                        sock.recvfrom(512)
                        elapsed = (time.perf_counter() - start) * 1000
                        times.append(elapsed)
                        sock.close()
                    except Exception:
                        pass

            if times:
                results.append({
                    'server': server,
                    'avg_ms': round(sum(times) / len(times), 2),
                    'min_ms': round(min(times), 2),
                    'max_ms': round(max(times), 2)
                })

        # find fastest
        valid = [r for r in results if r['avg_ms'] is not None]
        fastest = min(valid, key=lambda r: r['avg_ms'])['server'] if valid else None

        return {
            'status': 'success',
            'results': results,
            'fastest_server': fastest,
            'system_dns_ms': system_avg
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def _build_dns_query(domain: str) -> bytes:
    """build a minimal dns A record query packet."""
    import struct
    import os

    # header: id, flags(standard query), qdcount=1
    tx_id = int.from_bytes(os.urandom(2), 'big')
    header = struct.pack('>HHHHHH', tx_id, 0x0100, 1, 0, 0, 0)

    # question section
    question = b''
    for part in domain.split('.'):
        question += bytes([len(part)]) + part.encode()
    question += b'\x00'
    question += struct.pack('>HH', 1, 1)  # type A, class IN

    return header + question


def network_summary() -> Dict[str, Any]:
    """
    Full home network overview in one call.

    Returns:
        Dict with local IP, gateway, public IP, interfaces, connectivity.
    """
    try:
        primary_ip = _get_primary_ip()
        gateway = _get_default_gateway()
        connectivity = check_connectivity()
        ifaces = interface_info()

        # public ip with multi-source fallback
        public_ip = None
        services = [
            ('https://api.ipify.org?format=json', 'json'),
            ('https://checkip.amazonaws.com', 'text'),
        ]
        for url, fmt in services:
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=3) as resp:
                    body = resp.read().decode('utf-8')
                    if fmt == 'json':
                        import json
                        public_ip = json.loads(body).get('ip')
                    else:
                        public_ip = body.strip()
                break
            except Exception:
                continue

        return {
            'status': 'success',
            'hostname': socket.gethostname(),
            'primary_ip': primary_ip,
            'public_ip': public_ip,
            'gateway': gateway,
            'interfaces': ifaces.get('interfaces', []),
            'connectivity': connectivity.get('overall'),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


if __name__ == '__main__':
    print("Testing home network diagnostics...")

    result = check_connectivity()
    print(f"Connectivity: {result.get('overall')}")

    result = interface_info()
    for iface in result.get('interfaces', []):
        print(f"  {iface.get('name')}: {iface.get('ip', 'no ip')}")

    result = gateway_health()
    print(f"Gateway: {result.get('gateway_ip')}, reachable={result.get('is_reachable')}")
