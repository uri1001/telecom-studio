#!/usr/bin/env python3
"""
scanner.py - Port and Service Scanner
Simple port scanning utilities following KISS principle.
"""

import socket
import struct
import platform
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common ports for quick scanning
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Check if a single port is open on a host.

    Args:
        host: Target hostname or IP
        port: Port number to check
        timeout: Connection timeout in seconds

    Returns:
        Dict with port status and service info
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        is_open = result == 0
        service = COMMON_PORTS.get(port, 'Unknown')

        return {
            'status': 'success',
            'host': host,
            'port': port,
            'is_open': is_open,
            'service': service if is_open else None,
            'state': 'open' if is_open else 'closed'
        }
    except socket.gaierror:
        return {
            'status': 'error',
            'host': host,
            'port': port,
            'error': 'Host not found',
            'is_open': False,
            'state': 'error'
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'port': port,
            'error': str(e),
            'is_open': False,
            'state': 'error'
        }


def scan_common_ports(host: str, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Scan common service ports on a host.

    Args:
        host: Target hostname or IP
        timeout: Connection timeout per port

    Returns:
        Dict with scan results for all common ports
    """
    open_ports = []
    closed_ports = []
    errors = []

    # Parallel scanning for speed
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in COMMON_PORTS.keys()
        }

        for future in as_completed(futures):
            result = future.result()
            port = futures[future]

            if result['status'] == 'error':
                errors.append({
                    'port': port,
                    'error': result.get('error', 'Unknown error')
                })
            elif result['is_open']:
                open_ports.append({
                    'port': port,
                    'service': result['service']
                })
            else:
                closed_ports.append(port)

    return {
        'status': 'success',
        'host': host,
        'open_ports': sorted(open_ports, key=lambda x: x['port']),
        'closed_ports': sorted(closed_ports),
        'errors': errors,
        'total_scanned': len(COMMON_PORTS),
        'total_open': len(open_ports)
    }


def service_fingerprint(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Identify service running on an open port by sending probe.

    Args:
        host: Target hostname or IP
        port: Port number to fingerprint
        timeout: Connection timeout

    Returns:
        Dict with service identification info
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Connect to the port
        result = sock.connect_ex((host, port))
        if result != 0:
            sock.close()
            return {
                'status': 'error',
                'host': host,
                'port': port,
                'error': 'Port is closed'
            }

        # Try to grab banner
        banner = None
        try:
            # Send a generic probe
            if port in [80, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            pass

        sock.close()

        # Identify service based on port and banner
        service_info = {
            'known_service': COMMON_PORTS.get(port, 'Unknown'),
            'banner': banner if banner else None
        }

        # Enhanced detection based on banner
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service_info['detected'] = 'SSH'
            elif 'http' in banner_lower:
                service_info['detected'] = 'HTTP'
            elif 'ftp' in banner_lower:
                service_info['detected'] = 'FTP'
            elif 'smtp' in banner_lower:
                service_info['detected'] = 'SMTP'
            elif 'mysql' in banner_lower:
                service_info['detected'] = 'MySQL'
            elif 'postgresql' in banner_lower:
                service_info['detected'] = 'PostgreSQL'

        return {
            'status': 'success',
            'host': host,
            'port': port,
            'service': service_info,
            'is_open': True
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'port': port,
            'error': str(e)
        }


def scan_network_range(network: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Scan a port across a network range.

    Args:
        network: Network in CIDR notation (e.g., '192.168.1.0/24')
        port: Port to scan
        timeout: Connection timeout per host

    Returns:
        Dict with hosts and their port status
    """
    try:
        import ipaddress
        net = ipaddress.ip_network(network, strict=False)
        hosts_up = []
        hosts_down = []

        # Limit scan to /24 or smaller for performance
        if net.num_addresses > 256:
            return {
                'status': 'error',
                'network': network,
                'error': 'Network too large. Maximum /24 supported'
            }

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(scan_port, str(ip), port, timeout): str(ip)
                for ip in net.hosts()
            }

            for future in as_completed(futures):
                result = future.result()
                ip = futures[future]

                if result.get('is_open'):
                    hosts_up.append({
                        'host': ip,
                        'service': result.get('service')
                    })
                else:
                    hosts_down.append(ip)

        return {
            'status': 'success',
            'network': network,
            'port': port,
            'hosts_up': sorted(hosts_up, key=lambda x: socket.inet_aton(x['host'])),
            'hosts_down': sorted(hosts_down, key=socket.inet_aton),
            'total_hosts': net.num_addresses - 2,  # Exclude network and broadcast
            'total_up': len(hosts_up)
        }
    except ValueError as e:
        return {
            'status': 'error',
            'network': network,
            'error': f'Invalid network format: {str(e)}'
        }
    except Exception as e:
        return {
            'status': 'error',
            'network': network,
            'error': str(e)
        }


def detect_os(host: str, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Attempt to detect operating system based on network behavior.

    Args:
        host: Target hostname or IP
        timeout: Operation timeout

    Returns:
        Dict with OS detection results
    """
    try:
        # Simple OS detection based on TTL values and open ports
        import subprocess

        # Get TTL from ping
        ttl = None
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', host]
        else:
            cmd = ['ping', '-c', '1', '-W', str(int(timeout)), host]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)

        if result.returncode == 0:
            output = result.stdout
            # Extract TTL
            for line in output.split('\n'):
                if 'ttl=' in line.lower():
                    ttl_str = line.lower().split('ttl=')[1].split()[0]
                    ttl = int(ttl_str)
                    break

        # OS detection based on TTL
        os_guess = 'Unknown'
        if ttl:
            if ttl <= 64:
                os_guess = 'Linux/Unix'
            elif ttl <= 128:
                os_guess = 'Windows'
            elif ttl <= 255:
                os_guess = 'Network Device/Other'

        # Check common ports for additional hints
        port_hints = []
        test_ports = {
            22: 'SSH (Linux/Unix likely)',
            3389: 'RDP (Windows likely)',
            445: 'SMB (Windows likely)',
            111: 'RPC (Linux/Unix likely)'
        }

        for port, hint in test_ports.items():
            result = scan_port(host, port, timeout=0.5)
            if result.get('is_open'):
                port_hints.append(hint)

        return {
            'status': 'success',
            'host': host,
            'ttl': ttl,
            'os_guess': os_guess,
            'port_hints': port_hints,
            'confidence': 'low' if not ttl else 'medium'
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e),
            'os_guess': 'Unknown'
        }


if __name__ == '__main__':
    # Simple test
    print("Testing port scanner...")

    # Test single port
    result = scan_port('google.com', 443)
    print(f"Port 443 on google.com: {result['state']}")

    # Test common ports
    result = scan_common_ports('google.com', timeout=0.5)
    print(f"Open ports on google.com: {[p['port'] for p in result['open_ports']]}")