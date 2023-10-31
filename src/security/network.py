#!/usr/bin/env python3
"""
network.py - Home Network Security Checks
Detect common security issues on a home network using only stdlib.
"""

import re
import socket
import subprocess
import platform
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional


# ports that should typically not be exposed on a home network
RISKY_HOME_PORTS = {
    21: {'service': 'FTP', 'risk': 'high', 'recommendation': 'disable FTP, use SFTP instead'},
    23: {'service': 'Telnet', 'risk': 'critical', 'recommendation': 'disable telnet immediately, use SSH'},
    25: {'service': 'SMTP', 'risk': 'medium', 'recommendation': 'close unless running a mail server'},
    53: {'service': 'DNS', 'risk': 'medium', 'recommendation': 'close unless running a local DNS resolver'},
    135: {'service': 'MS-RPC', 'risk': 'high', 'recommendation': 'close, common windows attack vector'},
    139: {'service': 'NetBIOS', 'risk': 'high', 'recommendation': 'disable netbios over tcp/ip'},
    445: {'service': 'SMB', 'risk': 'high', 'recommendation': 'restrict to LAN only, patch regularly'},
    1433: {'service': 'MSSQL', 'risk': 'critical', 'recommendation': 'never expose database ports'},
    1883: {'service': 'MQTT', 'risk': 'medium', 'recommendation': 'ensure authentication is enabled'},
    3306: {'service': 'MySQL', 'risk': 'critical', 'recommendation': 'never expose database ports'},
    3389: {'service': 'RDP', 'risk': 'critical', 'recommendation': 'use VPN instead of direct RDP exposure'},
    5432: {'service': 'PostgreSQL', 'risk': 'critical', 'recommendation': 'never expose database ports'},
    5900: {'service': 'VNC', 'risk': 'high', 'recommendation': 'use VPN or SSH tunnel for remote access'},
    6379: {'service': 'Redis', 'risk': 'critical', 'recommendation': 'never expose redis, bind to localhost'},
    8080: {'service': 'HTTP-Proxy', 'risk': 'medium', 'recommendation': 'review if intentional'},
    8443: {'service': 'HTTPS-Alt', 'risk': 'low', 'recommendation': 'review if intentional'},
    9200: {'service': 'Elasticsearch', 'risk': 'critical', 'recommendation': 'never expose, bind to localhost'},
    11211: {'service': 'Memcached', 'risk': 'critical', 'recommendation': 'never expose, bind to localhost'},
    27017: {'service': 'MongoDB', 'risk': 'critical', 'recommendation': 'never expose database ports'},
}

# common mac oui prefixes (first 3 octets) for vendor identification
COMMON_OUI = {
    '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:1c:42': 'Parallels',
    '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
    'ac:de:48': 'Apple', '00:1e:c2': 'Apple', '3c:22:fb': 'Apple',
    '78:7b:8a': 'Apple', 'a4:83:e7': 'Apple', 'f0:18:98': 'Apple',
    'dc:a6:32': 'Raspberry Pi', 'b8:27:eb': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi', '28:cd:c1': 'Raspberry Pi',
    '30:de:4b': 'TP-Link', '50:c7:bf': 'TP-Link', 'ec:08:6b': 'TP-Link',
    'b0:be:76': 'TP-Link', '98:da:c4': 'TP-Link',
    '20:e5:2a': 'Netgear', 'c4:04:15': 'Netgear', 'a4:2b:8c': 'Netgear',
    '44:94:fc': 'Netgear', '9c:3d:cf': 'Netgear',
    'f4:f5:d8': 'Google', '54:60:09': 'Google', 'a4:77:33': 'Google',
    '94:b8:6d': 'Google', '30:fd:38': 'Google',
    '50:c8:e5': 'Samsung', '40:4e:36': 'Samsung', '84:25:db': 'Samsung',
    'bc:72:b1': 'Samsung', 'c0:97:27': 'Samsung',
    'e0:d5:5e': 'Intel', '3c:97:0e': 'Intel', '8c:8d:28': 'Intel',
    '48:51:b7': 'Intel', 'a0:36:9f': 'Intel',
    '18:b4:30': 'Nest', '64:16:66': 'Nest',
    'b4:e6:2d': 'Ubiquiti', '24:5a:4c': 'Ubiquiti', '78:8a:20': 'Ubiquiti',
    '68:72:51': 'Amazon', '40:b4:cd': 'Amazon', 'a0:02:dc': 'Amazon',
    '74:c2:46': 'Amazon', 'fc:65:de': 'Amazon',
    '00:17:88': 'Philips Hue', '00:1f:33': 'Netgear',
    'b0:72:bf': 'TP-Link', 'e8:48:b8': 'Dell', '00:25:90': 'Dell',
}


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


def _get_mac_vendor(mac: str) -> str:
    """look up vendor from mac oui prefix."""
    prefix = mac[:8].lower()
    return COMMON_OUI.get(prefix, 'Unknown')


def arp_table_analysis() -> Dict[str, Any]:
    """
    Read and analyze the system ARP table for anomalies.

    Returns:
        Dict with ARP entries and detected anomalies (duplicate MACs, IP conflicts).
    """
    try:
        entries = []

        if platform.system().lower() != 'windows':
            # prefer /proc/net/arp on linux
            try:
                with open('/proc/net/arp', 'r') as f:
                    lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != '00:00:00:00:00:00':
                        entries.append({
                            'ip': parts[0],
                            'mac': parts[3],
                            'interface': parts[5] if len(parts) > 5 else None
                        })
            except FileNotFoundError:
                pass

        # fallback to arp -a
        if not entries:
            result = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                mac_match = re.search(r'([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})', line)
                if ip_match and mac_match:
                    mac = mac_match.group(1).replace('-', ':').lower()
                    if mac != 'ff:ff:ff:ff:ff:ff' and mac != '00:00:00:00:00:00':
                        entries.append({
                            'ip': ip_match.group(1),
                            'mac': mac,
                            'interface': None
                        })

        # analyze anomalies
        mac_to_ips = {}
        ip_to_macs = {}

        for entry in entries:
            mac = entry['mac']
            ip = entry['ip']

            mac_to_ips.setdefault(mac, []).append(ip)
            ip_to_macs.setdefault(ip, []).append(mac)

        anomalies = {
            'duplicate_macs': [],
            'duplicate_ips': [],
            'suspicious': []
        }

        # duplicate MACs: same mac on multiple IPs (possible arp spoofing)
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                anomalies['duplicate_macs'].append({
                    'mac': mac,
                    'ips': ips,
                    'vendor': _get_mac_vendor(mac),
                    'warning': 'same MAC on multiple IPs - possible ARP spoofing'
                })

        # duplicate IPs: same ip with multiple MACs (arp conflict)
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                anomalies['duplicate_ips'].append({
                    'ip': ip,
                    'macs': macs,
                    'warning': 'multiple MACs for same IP - ARP conflict'
                })

        # check if gateway mac looks suspicious
        gateway_ip = _get_default_gateway()
        if gateway_ip and gateway_ip in ip_to_macs:
            gateway_macs = ip_to_macs[gateway_ip]
            if len(gateway_macs) > 1:
                anomalies['suspicious'].append({
                    'type': 'gateway_mac_conflict',
                    'gateway_ip': gateway_ip,
                    'macs': gateway_macs,
                    'warning': 'gateway has multiple MAC addresses - possible MITM'
                })

        has_anomalies = any(
            anomalies[k] for k in ['duplicate_macs', 'duplicate_ips', 'suspicious']
        )
        if anomalies['suspicious']:
            risk = 'critical'
        elif anomalies['duplicate_macs'] or anomalies['duplicate_ips']:
            risk = 'warning'
        else:
            risk = 'safe'

        return {
            'status': 'success',
            'entries': entries,
            'total_entries': len(entries),
            'anomalies': anomalies,
            'has_anomalies': has_anomalies,
            'risk_level': risk
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def rogue_dhcp_detection(timeout: float = 5.0) -> Dict[str, Any]:
    """
    Detect rogue DHCP servers on the local network.

    Falls back to passive lease analysis if raw sockets unavailable.

    Args:
        timeout: Timeout for detection in seconds.

    Returns:
        Dict with detected DHCP servers and rogue status.
    """
    try:
        dhcp_servers = []
        method = 'passive'

        if platform.system().lower() != 'windows':
            # try to find dhcp server from lease files
            lease_paths = [
                '/var/lib/dhcp/dhclient.leases',
                '/var/lib/dhclient/dhclient.leases',
                '/var/lib/NetworkManager/dhclient-*.lease',
            ]

            for path in lease_paths:
                try:
                    import glob as glob_mod
                    for lease_file in glob_mod.glob(path):
                        with open(lease_file, 'r') as f:
                            content = f.read()
                        for match in re.finditer(
                            r'dhcp-server-identifier\s+(\d+\.\d+\.\d+\.\d+)', content
                        ):
                            server_ip = match.group(1)
                            if server_ip not in [s['ip'] for s in dhcp_servers]:
                                dhcp_servers.append({
                                    'ip': server_ip,
                                    'source': lease_file
                                })
                except Exception:
                    continue

            # also check systemd journal if available
            try:
                result = subprocess.run(
                    ['journalctl', '-u', 'NetworkManager', '--no-pager', '-n', '200'],
                    capture_output=True, text=True, timeout=5
                )
                for match in re.finditer(
                    r'DHCP[46]?\s+server\s+(\d+\.\d+\.\d+\.\d+)', result.stdout
                ):
                    server_ip = match.group(1)
                    if server_ip not in [s['ip'] for s in dhcp_servers]:
                        dhcp_servers.append({
                            'ip': server_ip,
                            'source': 'journalctl'
                        })
            except Exception:
                pass
        else:
            # windows: parse ipconfig for dhcp server
            try:
                result = subprocess.run(
                    ['ipconfig', '/all'], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    if 'DHCP Server' in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            server_ip = match.group(1)
                            if server_ip not in [s['ip'] for s in dhcp_servers]:
                                dhcp_servers.append({
                                    'ip': server_ip,
                                    'source': 'ipconfig'
                                })
            except Exception:
                pass

        # determine if expected gateway is the dhcp server
        gateway = _get_default_gateway()
        for server in dhcp_servers:
            server['is_expected'] = server['ip'] == gateway if gateway else None

        rogue = [s for s in dhcp_servers if s.get('is_expected') is False]

        return {
            'status': 'success',
            'dhcp_servers': dhcp_servers,
            'total_found': len(dhcp_servers),
            'rogue_detected': len(rogue) > 0,
            'rogue_servers': rogue,
            'gateway': gateway,
            'method': method
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def open_port_audit(host: str = None, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Audit for risky open ports on a host.

    Args:
        host: Target host. Defaults to localhost.
        timeout: Timeout per port.

    Returns:
        Dict with risky open ports, risk ratings, and recommendations.
    """
    try:
        if not host:
            host = '127.0.0.1'

        risky_open = []
        safe_open = []

        def check_port(port, info):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                return port, result == 0, info
            except Exception:
                return port, False, info

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(check_port, port, info): port
                for port, info in RISKY_HOME_PORTS.items()
            }

            for future in as_completed(futures):
                port, is_open, info = future.result()
                if is_open:
                    if info['risk'] in ('critical', 'high'):
                        risky_open.append({
                            'port': port,
                            'service': info['service'],
                            'risk': info['risk'],
                            'recommendation': info['recommendation']
                        })
                    else:
                        safe_open.append({
                            'port': port,
                            'service': info['service'],
                            'risk': info['risk']
                        })

        risky_open.sort(key=lambda x: x['port'])
        safe_open.sort(key=lambda x: x['port'])

        total_exposed = len(risky_open) + len(safe_open)

        if any(p['risk'] == 'critical' for p in risky_open):
            risk_level = 'critical'
        elif risky_open:
            risk_level = 'warning'
        else:
            risk_level = 'safe'

        return {
            'status': 'success',
            'host': host,
            'risky_open': risky_open,
            'safe_open': safe_open,
            'total_exposed': total_exposed,
            'risk_level': risk_level
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e)
        }


def detect_network_devices(network: str = None, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Build a device inventory with MAC vendor identification.

    Args:
        network: CIDR notation. Auto-detects if None.
        timeout: Timeout per host.

    Returns:
        Dict with device list including IP, MAC, hostname, vendor hint.
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

        # ping sweep to populate arp table
        def ping_host(ip_str):
            try:
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                timeout_flag = '-w' if platform.system().lower() == 'windows' else '-W'
                cmd = ['ping', param, '1', timeout_flag, str(int(timeout)), ip_str]
                subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=50) as executor:
            list(executor.map(ping_host, [str(ip) for ip in net.hosts()]))

        # read arp table after sweep
        arp_result = arp_table_analysis()
        arp_entries = arp_result.get('entries', [])

        # build device list with enrichment
        devices = []
        unknown_vendors = []

        for entry in arp_entries:
            ip = entry['ip']

            # only include devices in our target network
            try:
                if ipaddress.ip_address(ip) not in net:
                    continue
            except ValueError:
                continue

            mac = entry['mac']
            vendor = _get_mac_vendor(mac)

            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

            device = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor_hint': vendor
            }
            devices.append(device)

            if vendor == 'Unknown':
                unknown_vendors.append({'ip': ip, 'mac': mac})

        devices.sort(key=lambda d: socket.inet_aton(d['ip']))

        return {
            'status': 'success',
            'network': network,
            'devices': devices,
            'total_devices': len(devices),
            'unknown_vendors': unknown_vendors
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def security_audit(timeout: float = 2.0) -> Dict[str, Any]:
    """
    One-shot home network security audit.

    Runs ARP analysis, port audit, and device detection, then scores overall security.

    Args:
        timeout: Timeout for individual checks.

    Returns:
        Dict with security score (0-100), findings, and recommendations.
    """
    try:
        arp = arp_table_analysis()
        ports = open_port_audit(timeout=timeout)
        devices = detect_network_devices(timeout=timeout)
        dhcp = rogue_dhcp_detection()

        score = 100
        recommendations = []

        # arp anomalies: -20 per issue
        arp_issues = 0
        if arp.get('has_anomalies'):
            anomalies = arp.get('anomalies', {})
            arp_issues = (
                len(anomalies.get('duplicate_macs', []))
                + len(anomalies.get('duplicate_ips', []))
                + len(anomalies.get('suspicious', []))
            )
            score -= arp_issues * 20
            recommendations.append('investigate ARP table anomalies')

        # risky ports: -15 for critical, -10 for high
        for port in ports.get('risky_open', []):
            if port['risk'] == 'critical':
                score -= 15
            else:
                score -= 10
            recommendations.append(f"port {port['port']} ({port['service']}): {port['recommendation']}")

        # unknown devices: -5 each
        unknown = devices.get('unknown_vendors', [])
        if unknown:
            score -= len(unknown) * 5
            recommendations.append(f'{len(unknown)} unknown device(s) on network')

        # rogue dhcp: -30
        if dhcp.get('rogue_detected'):
            score -= 30
            recommendations.append('rogue DHCP server detected - investigate immediately')

        score = max(0, min(100, score))

        if score >= 80:
            rating = 'secure'
        elif score >= 50:
            rating = 'fair'
        else:
            rating = 'at_risk'

        return {
            'status': 'success',
            'score': score,
            'rating': rating,
            'arp_anomalies': arp_issues,
            'exposed_ports': len(ports.get('risky_open', [])),
            'unknown_devices': len(unknown),
            'rogue_dhcp': dhcp.get('rogue_detected', False),
            'total_devices': devices.get('total_devices', 0),
            'recommendations': recommendations,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


if __name__ == '__main__':
    print("Home Network Security Checks:")
    print("-" * 40)

    result = arp_table_analysis()
    print(f"ARP entries: {result.get('total_entries', 0)}, risk: {result.get('risk_level')}")

    result = open_port_audit()
    print(f"Risky ports on localhost: {len(result.get('risky_open', []))}")
    for port in result.get('risky_open', []):
        print(f"  :{port['port']} ({port['service']}) - {port['risk']}")
