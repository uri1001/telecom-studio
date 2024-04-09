#!/usr/bin/env python3
"""
subnet.py - Subnet and IP Calculator
CIDR parsing, host enumeration, and network information.
"""

import ipaddress

from typing import Any, Dict, List, Optional, Tuple


def _parse_network(cidr: str) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """Parse CIDR string into network object.

    Args:
        cidr: CIDR notation string (e.g. '192.168.1.0/24')

    Returns:
        Tuple of (network_object, error_dict) -- one is always None
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net, None
    except (ValueError, TypeError) as e:
        return None, {'status': 'error', 'error': f'invalid CIDR: {e}'}


def subnet_info(cidr: str) -> Dict[str, Any]:
    """Get comprehensive subnet information.

    Args:
        cidr: CIDR notation string (e.g. '192.168.1.0/24')

    Returns:
        Dict with network details, host range, and address counts
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        prefix = net.prefixlen
        total = net.num_addresses
        network_addr = str(net.network_address)
        broadcast_addr = str(net.broadcast_address)

        # /32 single host -- no usable range
        if (net.version == 4 and prefix == 32) or (net.version == 6 and prefix == 128):
            first_usable = network_addr
            last_usable = network_addr
            usable = 1
        # /31 point-to-point (RFC 3021)
        elif net.version == 4 and prefix == 31:
            first_usable = network_addr
            last_usable = broadcast_addr
            usable = 2
        else:
            first_usable = str(net.network_address + 1)
            last_usable = str(net.broadcast_address - 1)
            usable = net.num_addresses - 2

        return {
            'status': 'success',
            'network': network_addr,
            'broadcast': broadcast_addr,
            'netmask': str(net.netmask),
            'hostmask': str(net.hostmask),
            'prefix_length': prefix,
            'first_usable': first_usable,
            'last_usable': last_usable,
            'total_addresses': total,
            'usable_hosts': usable,
            'ip_version': net.version,
            'is_private': net.is_private,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def contains(cidr: str, ip: str) -> Dict[str, Any]:
    """Check if an IP address is within a subnet.

    Args:
        cidr: CIDR notation string
        ip: IP address to check

    Returns:
        Dict with contains boolean
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        addr = ipaddress.ip_address(ip)
        return {
            'status': 'success',
            'cidr': str(net),
            'ip': str(addr),
            'contains': addr in net,
        }
    except TypeError as e:
        # version mismatch (e.g. IPv4 addr in IPv6 net)
        return {'status': 'error', 'error': f'version mismatch: {e}'}
    except (ValueError, Exception) as e:
        return {'status': 'error', 'error': str(e)}


def nth_host(cidr: str, n: int) -> Dict[str, Any]:
    """Get the nth usable host in a subnet.

    Args:
        cidr: CIDR notation string
        n: Host number (1-based)

    Returns:
        Dict with the nth host address
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        prefix = net.prefixlen
        max_prefix = 128 if net.version == 6 else 32

        # calculate usable hosts without materializing
        if prefix == max_prefix:
            usable = 1
        elif net.version == 4 and prefix == 31:
            usable = 2
        else:
            usable = net.num_addresses - 2

        if n < 1 or n > usable:
            return {
                'status': 'error',
                'error': f'host number {n} out of range (1-{usable})',
            }

        # arithmetic: skip network address for normal subnets
        if prefix == max_prefix:
            host = net.network_address
        elif net.version == 4 and prefix == 31:
            host = ipaddress.ip_address(int(net.network_address) + n - 1)
        else:
            host = ipaddress.ip_address(int(net.network_address) + n)

        return {
            'status': 'success',
            'cidr': str(net),
            'n': n,
            'host': str(host),
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


if __name__ == '__main__':
    # basic subnet info
    result = subnet_info('192.168.1.0/24')
    assert result['status'] == 'success'
    assert result['usable_hosts'] == 254
    assert result['network'] == '192.168.1.0'
    assert result['broadcast'] == '192.168.1.255'
    print(f"subnet_info /24: {result['usable_hosts']} hosts")

    # /32 single host
    result = subnet_info('10.0.0.1/32')
    assert result['usable_hosts'] == 1
    assert result['first_usable'] == '10.0.0.1'
    print(f"subnet_info /32: {result['usable_hosts']} host")

    # /31 point-to-point
    result = subnet_info('10.0.0.0/31')
    assert result['usable_hosts'] == 2
    print(f"subnet_info /31: {result['usable_hosts']} hosts")

    # contains
    result = contains('192.168.1.0/24', '192.168.1.100')
    assert result['contains'] is True
    result = contains('192.168.1.0/24', '10.0.0.1')
    assert result['contains'] is False
    print("contains: pass")

    # nth host
    result = nth_host('10.0.0.0/24', 1)
    assert result['host'] == '10.0.0.1'
    result = nth_host('10.0.0.0/24', 254)
    assert result['host'] == '10.0.0.254'
    print("nth_host: pass")

    # error cases
    result = subnet_info('not-a-cidr')
    assert result['status'] == 'error'
    result = contains('192.168.1.0/24', '::1')
    assert result['contains'] is False
    result = nth_host('10.0.0.0/24', 0)
    assert result['status'] == 'error'
    print("error handling: pass")

    print("\nall tests passed")
