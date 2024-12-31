#!/usr/bin/env python3
"""
basic.py - Basic Network Utilities
Simple, clear network diagnostic functions using only stdlib.
"""

import json
import socket
import subprocess
import platform
import urllib.request
import urllib.error


def ping(host: str, count: int = 4, timeout: int = 1) -> dict:
    """Send ICMP ping to a host."""
    try:
        is_windows = platform.system().lower() == 'windows'
        count_flag = '-n' if is_windows else '-c'
        timeout_flag = '-w' if is_windows else '-W'
        # windows -w takes milliseconds, linux -W takes seconds
        timeout_value = str(timeout * 1000) if is_windows else str(timeout)

        cmd = ['ping', count_flag, str(count), timeout_flag, timeout_value, host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 2)

        output = result.stdout
        success = result.returncode == 0

        avg_rtt = None
        packet_loss = 100.0

        if success:
            if 'packet loss' in output:
                for line in output.split('\n'):
                    if 'packet loss' in line:
                        for part in line.split():
                            if '%' in part:
                                packet_loss = float(part.replace('%', ''))
                                break

            # linux ping summary: "rtt min/avg/max/mdev = ..." -- avg is 5th /-delimited field
            if 'avg' in output or 'Average' in output:
                for line in output.split('\n'):
                    if 'avg' in line or 'Average' in line:
                        parts = line.split('/')
                        if len(parts) >= 5:
                            avg_rtt = float(parts[4].split()[0])

        return {
            'status': 'success' if success else 'error',
            'host': host,
            'average_rtt': avg_rtt,
            'packet_loss': packet_loss,
            'output': output
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e),
            'average_rtt': None,
            'packet_loss': 100.0
        }


def traceroute(host: str, max_hops: int = 30) -> dict:
    """Trace route to destination."""
    try:
        if platform.system().lower() == 'windows':
            cmd = ['tracert', '-h', str(max_hops), host]
        else:
            cmd = ['traceroute', '-m', str(max_hops), host]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        output = result.stdout
        # count actual hops from output (non-empty lines after the first header line)
        lines = [l for l in output.strip().split('\n')[1:] if l.strip()]
        hop_count = len(lines)

        if result.returncode == 0:
            return {
                'status': 'success',
                'host': host,
                'output': output,
                'hops': hop_count
            }
        else:
            return {
                'status': 'error',
                'host': host,
                'error': 'Traceroute did not complete successfully',
                'output': output,
                'hops': hop_count
            }
    except subprocess.TimeoutExpired:
        return {
            'status': 'error',
            'host': host,
            'error': 'Traceroute timed out',
            'hops': 0
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e),
            'hops': 0
        }


def dns_lookup(domain: str, record_type: str = 'A') -> dict:
    """Perform DNS lookup using socket (A and AAAA only)."""
    try:
        normalized_type = record_type.upper()

        if normalized_type == 'A':
            family = socket.AF_INET
        elif normalized_type == 'AAAA':
            family = socket.AF_INET6
        else:
            return {
                'status': 'error',
                'domain': domain,
                'record_type': normalized_type,
                'error': f'Unsupported record type: {normalized_type}',
                'records': []
            }

        results = socket.getaddrinfo(domain, None, family)
        # deduplicate addresses
        records = list(dict.fromkeys(r[4][0] for r in results))

        return {
            'status': 'success',
            'domain': domain,
            'record_type': normalized_type,
            'records': records,
            'count': len(records)
        }
    except Exception as e:
        return {
            'status': 'error',
            'domain': domain,
            'record_type': record_type,
            'error': str(e),
            'records': []
        }


def get_public_ip() -> dict:
    """Get public IP address using external services."""
    services = [
        ('https://api.ipify.org?format=json', 'json'),
        ('https://checkip.amazonaws.com', 'text'),
        ('https://ifconfig.me/ip', 'text'),
    ]

    for url, fmt in services:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                body = resp.read().decode('utf-8')
                if fmt == 'json':
                    ip = json.loads(body).get('ip')
                else:
                    ip = body.strip()

            return {
                'status': 'success',
                'public_ip': ip,
                'service': url
            }
        except Exception:
            continue

    return {
        'status': 'error',
        'error': 'Could not determine public IP',
        'public_ip': None
    }


def get_local_ips() -> dict:
    """Get local IP addresses using socket."""
    try:
        # primary IP via UDP connect trick
        primary_ip = None
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            primary_ip = s.getsockname()[0]
        except Exception:
            pass
        finally:
            s.close()

        # collect additional addresses from hostname resolution
        addresses = set()
        if primary_ip:
            addresses.add(primary_ip)

        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                addr = info[4][0]
                addresses.add(addr)
        except Exception:
            pass

        return {
            'status': 'success',
            'primary_ip': primary_ip,
            'addresses': sorted(addresses)
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'primary_ip': None,
            'addresses': []
        }


if __name__ == '__main__':
    print("Testing basic network utilities...")
    result = ping('8.8.8.8', count=2)
    print(f"Ping: {result['status']}, RTT: {result.get('average_rtt')}ms")
    result = dns_lookup('google.com')
    print(f"DNS: {result.get('records', [])}")
    result = get_local_ips()
    print(f"Local IPs: primary={result.get('primary_ip')}, all={result.get('addresses', [])}")
