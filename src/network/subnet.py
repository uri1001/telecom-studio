#!/usr/bin/env python3
"""
subnet.py - Subnet and IP Calculator
CIDR parsing, host enumeration, IP classification, and network information.
"""

import ipaddress
import math

from typing import Any, Dict, List, Optional, Tuple


# IPv4 bogon ranges per RFC 5735/6890
BOGON_RANGES = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '255.255.255.255/32',
]


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


def _parse_address(ip: str) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """Parse IP address string into address object.

    Args:
        ip: IP address string (e.g. '192.168.1.1')

    Returns:
        Tuple of (address_object, error_dict) -- one is always None
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr, None
    except (ValueError, TypeError) as e:
        return None, {'status': 'error', 'error': f'invalid IP address: {e}'}


def is_private(ip: str) -> Dict[str, Any]:
    """Check if an IP address is in a private range.

    Args:
        ip: IP address string

    Returns:
        Dict with is_private boolean
    """
    try:
        addr, err = _parse_address(ip)
        if err:
            return err

        return {
            'status': 'success',
            'ip': str(addr),
            'is_private': addr.is_private,
            'ip_version': addr.version,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def is_reserved(ip: str) -> Dict[str, Any]:
    """Check if an IP address is in a reserved range.

    Args:
        ip: IP address string

    Returns:
        Dict with is_reserved boolean
    """
    try:
        addr, err = _parse_address(ip)
        if err:
            return err

        return {
            'status': 'success',
            'ip': str(addr),
            'is_reserved': addr.is_reserved,
            'ip_version': addr.version,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def classify_ip(ip: str) -> Dict[str, Any]:
    """Classify an IP address by type.

    Args:
        ip: IP address string

    Returns:
        Dict with classification and is_global flag
    """
    try:
        addr, err = _parse_address(ip)
        if err:
            return err

        if addr.is_unspecified:
            classification = 'unspecified'
        elif addr.is_loopback:
            classification = 'loopback'
        elif addr.is_link_local:
            classification = 'link_local'
        elif addr.is_multicast:
            classification = 'multicast'
        elif addr.is_reserved:
            classification = 'reserved'
        elif addr.is_private:
            classification = 'private'
        else:
            classification = 'public'

        return {
            'status': 'success',
            'ip': str(addr),
            'classification': classification,
            'is_global': addr.is_global,
            'ip_version': addr.version,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def is_bogon(ip: str) -> Dict[str, Any]:
    """Check if an IP address is a bogon (non-routable).

    Args:
        ip: IP address string

    Returns:
        Dict with is_bogon boolean and matched_range if applicable
    """
    try:
        addr, err = _parse_address(ip)
        if err:
            return err

        if addr.version == 4:
            for bogon_cidr in BOGON_RANGES:
                bogon_net = ipaddress.ip_network(bogon_cidr)
                if addr in bogon_net:
                    return {
                        'status': 'success',
                        'ip': str(addr),
                        'is_bogon': True,
                        'matched_range': bogon_cidr,
                        'ip_version': 4,
                    }
            return {
                'status': 'success',
                'ip': str(addr),
                'is_bogon': False,
                'ip_version': 4,
            }
        else:
            # IPv6: use is_global as proxy
            is_bogon_v6 = not addr.is_global
            return {
                'status': 'success',
                'ip': str(addr),
                'is_bogon': is_bogon_v6,
                'ip_version': 6,
            }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def split_subnet(cidr: str, new_prefix: int) -> Dict[str, Any]:
    """Split a subnet into smaller subnets.

    Args:
        cidr: CIDR notation string
        new_prefix: New prefix length (must be larger than current)

    Returns:
        Dict with list of resulting subnets
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        if new_prefix <= net.prefixlen:
            return {
                'status': 'error',
                'error': f'new prefix /{new_prefix} must be larger than current /{net.prefixlen}',
            }

        max_prefix = 128 if net.version == 6 else 32
        if new_prefix > max_prefix:
            return {
                'status': 'error',
                'error': f'prefix /{new_prefix} exceeds maximum /{max_prefix}',
            }

        # safety cap
        count = 2 ** (new_prefix - net.prefixlen)
        if count > 65536:
            return {
                'status': 'error',
                'error': f'would produce {count} subnets (max 65536)',
            }

        subnets = [str(s) for s in net.subnets(new_prefix=new_prefix)]
        return {
            'status': 'success',
            'parent': str(net),
            'subnets': subnets,
            'count': len(subnets),
            'new_prefix': new_prefix,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def overlap(cidr_a: str, cidr_b: str) -> Dict[str, Any]:
    """Check if two subnets overlap.

    Args:
        cidr_a: First CIDR notation string
        cidr_b: Second CIDR notation string

    Returns:
        Dict with overlap status and intersection details
    """
    try:
        net_a, err = _parse_network(cidr_a)
        if err:
            return err
        net_b, err = _parse_network(cidr_b)
        if err:
            return err

        overlaps = net_a.overlaps(net_b)
        result = {
            'status': 'success',
            'cidr_a': str(net_a),
            'cidr_b': str(net_b),
            'overlaps': overlaps,
        }

        if overlaps:
            # compute intersection range
            first = max(int(net_a.network_address), int(net_b.network_address))
            last = min(int(net_a.broadcast_address), int(net_b.broadcast_address))
            addr_cls = ipaddress.IPv4Address if net_a.version == 4 else ipaddress.IPv6Address
            intersection = list(
                ipaddress.summarize_address_range(addr_cls(first), addr_cls(last))
            )
            result['intersection'] = [str(n) for n in intersection]

        return result
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def adjacent(cidr_a: str, cidr_b: str) -> Dict[str, Any]:
    """Check if two subnets are adjacent (contiguous).

    Args:
        cidr_a: First CIDR notation string
        cidr_b: Second CIDR notation string

    Returns:
        Dict with adjacency status and merged CIDR if applicable
    """
    try:
        net_a, err = _parse_network(cidr_a)
        if err:
            return err
        net_b, err = _parse_network(cidr_b)
        if err:
            return err

        bcast_a = int(net_a.broadcast_address)
        net_b_int = int(net_b.network_address)
        bcast_b = int(net_b.broadcast_address)
        net_a_int = int(net_a.network_address)

        is_adjacent = (bcast_a + 1 == net_b_int) or (bcast_b + 1 == net_a_int)

        result = {
            'status': 'success',
            'cidr_a': str(net_a),
            'cidr_b': str(net_b),
            'adjacent': is_adjacent,
        }

        if is_adjacent:
            merged = list(ipaddress.collapse_addresses([net_a, net_b]))
            result['merged'] = [str(n) for n in merged]

        return result
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def vlsm_allocate(cidr: str, requirements: List[int]) -> Dict[str, Any]:
    """Allocate subnets using VLSM for variable host requirements.

    Args:
        cidr: Parent CIDR notation string
        requirements: List of required host counts per subnet

    Returns:
        Dict with allocation list, per-subnet waste, and total utilization
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        if not requirements:
            return {'status': 'error', 'error': 'empty requirements list'}

        max_prefix = 128 if net.version == 6 else 32

        # sort largest first for optimal packing
        sorted_reqs = sorted(enumerate(requirements), key=lambda x: x[1], reverse=True)

        allocations = []
        current_addr = int(net.network_address)
        parent_end = int(net.broadcast_address)
        total_allocated = 0

        for orig_idx, hosts_needed in sorted_reqs:
            if hosts_needed < 1:
                return {'status': 'error', 'error': f'requirement must be >= 1, got {hosts_needed}'}

            # calculate prefix: need hosts + network + broadcast
            prefix = max_prefix - math.ceil(math.log2(hosts_needed + 2))
            prefix = max(0, min(max_prefix, prefix))

            subnet_size = 2 ** (max_prefix - prefix)

            # align to subnet boundary
            if current_addr % subnet_size != 0:
                current_addr = ((current_addr // subnet_size) + 1) * subnet_size

            subnet_end = current_addr + subnet_size - 1

            if subnet_end > parent_end:
                return {
                    'status': 'error',
                    'error': f'insufficient space for {hosts_needed} hosts at /{prefix}',
                }

            addr_cls = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
            subnet_cidr = f'{addr_cls(current_addr)}/{prefix}'
            usable = subnet_size - 2 if prefix < max_prefix else 1
            waste = usable - hosts_needed

            allocations.append({
                'original_index': orig_idx,
                'hosts_requested': hosts_needed,
                'subnet': subnet_cidr,
                'prefix': prefix,
                'usable_hosts': usable,
                'waste': waste,
            })

            total_allocated += subnet_size
            current_addr = subnet_end + 1

        # restore original order
        allocations.sort(key=lambda x: x['original_index'])

        total_parent = net.num_addresses
        utilization_pct = round((total_allocated / total_parent) * 100, 2)

        return {
            'status': 'success',
            'parent': str(net),
            'allocations': allocations,
            'total_allocated': total_allocated,
            'total_available': total_parent,
            'utilization_pct': utilization_pct,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def summarize(cidrs: List[str]) -> Dict[str, Any]:
    """Summarize a list of CIDRs into the smallest set of covering networks.

    Args:
        cidrs: List of CIDR notation strings

    Returns:
        Dict with summarized CIDR list and reduction count
    """
    try:
        if not cidrs:
            return {'status': 'error', 'error': 'empty CIDR list'}

        v4_nets = []
        v6_nets = []
        for cidr in cidrs:
            net, err = _parse_network(cidr)
            if err:
                return err
            if net.version == 4:
                v4_nets.append(net)
            else:
                v6_nets.append(net)

        collapsed = []
        if v4_nets:
            collapsed.extend(ipaddress.collapse_addresses(v4_nets))
        if v6_nets:
            collapsed.extend(ipaddress.collapse_addresses(v6_nets))

        summary = [str(n) for n in collapsed]
        return {
            'status': 'success',
            'input_count': len(cidrs),
            'summary': summary,
            'output_count': len(summary),
            'reduction': len(cidrs) - len(summary),
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def wildcard_mask(cidr: str) -> Dict[str, Any]:
    """Get the wildcard (inverse) mask for a CIDR.

    Args:
        cidr: CIDR notation string

    Returns:
        Dict with wildcard mask (Cisco ACL format)
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        return {
            'status': 'success',
            'cidr': str(net),
            'netmask': str(net.netmask),
            'wildcard_mask': str(net.hostmask),
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def supernet(cidr: str, new_prefix: int) -> Dict[str, Any]:
    """Get the supernet for a CIDR.

    Args:
        cidr: CIDR notation string
        new_prefix: New prefix length (must be smaller than current)

    Returns:
        Dict with supernet CIDR
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        if new_prefix >= net.prefixlen:
            return {
                'status': 'error',
                'error': f'new prefix /{new_prefix} must be smaller than current /{net.prefixlen}',
            }

        if new_prefix < 0:
            return {'status': 'error', 'error': f'invalid prefix /{new_prefix}'}

        parent = net.supernet(new_prefix=new_prefix)
        return {
            'status': 'success',
            'cidr': str(net),
            'supernet': str(parent),
            'new_prefix': new_prefix,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def exclude(cidr: str, exclude_cidr: str) -> Dict[str, Any]:
    """Exclude a subnet from a larger network.

    Args:
        cidr: Parent CIDR notation string
        exclude_cidr: CIDR to exclude

    Returns:
        Dict with remaining subnets after exclusion
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err
        exclude_net, err = _parse_network(exclude_cidr)
        if err:
            return err

        remaining = [str(n) for n in net.address_exclude(exclude_net)]
        return {
            'status': 'success',
            'parent': str(net),
            'excluded': str(exclude_net),
            'remaining': remaining,
            'count': len(remaining),
        }
    except ValueError as e:
        return {'status': 'error', 'error': str(e)}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def cidr_to_range(cidr: str) -> Dict[str, Any]:
    """Convert a CIDR to its IP range.

    Args:
        cidr: CIDR notation string

    Returns:
        Dict with first_ip, last_ip, and total_addresses
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        return {
            'status': 'success',
            'cidr': str(net),
            'first_ip': str(net.network_address),
            'last_ip': str(net.broadcast_address),
            'total_addresses': net.num_addresses,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def range_to_cidrs(start_ip: str, end_ip: str) -> Dict[str, Any]:
    """Convert an IP range to a list of CIDRs.

    Args:
        start_ip: Start IP address
        end_ip: End IP address

    Returns:
        Dict with list of covering CIDRs
    """
    try:
        start, err = _parse_address(start_ip)
        if err:
            return err
        end, err = _parse_address(end_ip)
        if err:
            return err

        cidrs = [str(n) for n in ipaddress.summarize_address_range(start, end)]
        return {
            'status': 'success',
            'start_ip': str(start),
            'end_ip': str(end),
            'cidrs': cidrs,
            'count': len(cidrs),
        }
    except ValueError as e:
        return {'status': 'error', 'error': str(e)}
    except TypeError as e:
        return {'status': 'error', 'error': f'version mismatch: {e}'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def _mac_to_eui64(mac: str) -> Tuple[Optional[str], Optional[str]]:
    """Convert MAC address to EUI-64 interface identifier.

    Args:
        mac: MAC address string (various formats)

    Returns:
        Tuple of (eui64_hex, error_string) -- one is always None
    """
    # strip common separators
    cleaned = mac.replace(':', '').replace('-', '').replace('.', '').lower()

    if len(cleaned) != 12 or not all(c in '0123456789abcdef' for c in cleaned):
        return None, f'invalid MAC address: {mac}'

    # insert ff:fe in the middle
    oui = cleaned[:6]
    nic = cleaned[6:]
    eui64 = oui[:2] + oui[2:4] + oui[4:6] + 'fffe' + nic

    # flip bit 7 (universal/local bit) in the first byte
    first_byte = int(eui64[:2], 16) ^ 0x02
    eui64 = f'{first_byte:02x}' + eui64[2:]

    # format as colon-separated groups of 4
    formatted = ':'.join(eui64[i:i+4] for i in range(0, 16, 4))
    return formatted, None


def expand_ipv6(address: str) -> Dict[str, Any]:
    """Expand an IPv6 address to its full form.

    Args:
        address: IPv6 address string

    Returns:
        Dict with expanded (exploded) IPv6 address
    """
    try:
        addr, err = _parse_address(address)
        if err:
            return err

        if addr.version != 6:
            return {'status': 'error', 'error': f'not an IPv6 address: {address}'}

        return {
            'status': 'success',
            'input': address,
            'expanded': addr.exploded,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def compress_ipv6(address: str) -> Dict[str, Any]:
    """Compress an IPv6 address to its shortest form.

    Args:
        address: IPv6 address string

    Returns:
        Dict with compressed IPv6 address
    """
    try:
        addr, err = _parse_address(address)
        if err:
            return err

        if addr.version != 6:
            return {'status': 'error', 'error': f'not an IPv6 address: {address}'}

        return {
            'status': 'success',
            'input': address,
            'compressed': str(addr),
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def eui64_address(prefix: str, mac: str) -> Dict[str, Any]:
    """Generate an IPv6 address from a /64 prefix and MAC address using EUI-64.

    Args:
        prefix: IPv6 /64 prefix in CIDR notation
        mac: MAC address string

    Returns:
        Dict with generated IPv6 address
    """
    try:
        net, err = _parse_network(prefix)
        if err:
            return err

        if net.version != 6:
            return {'status': 'error', 'error': 'prefix must be IPv6'}

        if net.prefixlen != 64:
            return {'status': 'error', 'error': f'prefix must be /64, got /{net.prefixlen}'}

        eui64_hex, mac_err = _mac_to_eui64(mac)
        if mac_err:
            return {'status': 'error', 'error': mac_err}

        # combine upper 64 bits of prefix with eui-64 interface id
        prefix_int = int(net.network_address) & (((1 << 64) - 1) << 64)
        iid_clean = eui64_hex.replace(':', '')
        iid_int = int(iid_clean, 16)
        full_addr = ipaddress.IPv6Address(prefix_int | iid_int)

        return {
            'status': 'success',
            'prefix': str(net),
            'mac': mac,
            'eui64_iid': eui64_hex,
            'address': str(full_addr),
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def link_local(mac: str) -> Dict[str, Any]:
    """Generate a link-local IPv6 address from a MAC address.

    Args:
        mac: MAC address string

    Returns:
        Dict with link-local IPv6 address
    """
    return eui64_address('fe80::/64', mac)


def ptr_record(ip: str) -> Dict[str, Any]:
    """Get the reverse DNS PTR record name for an IP address.

    Args:
        ip: IP address string

    Returns:
        Dict with PTR record name (.in-addr.arpa or .ip6.arpa)
    """
    try:
        addr, err = _parse_address(ip)
        if err:
            return err

        return {
            'status': 'success',
            'ip': str(addr),
            'ptr': addr.reverse_pointer,
            'ip_version': addr.version,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def arpa_zone(cidr: str) -> Dict[str, Any]:
    """Get reverse DNS zone(s) for a CIDR block.

    Args:
        cidr: CIDR notation string

    Returns:
        Dict with reverse DNS zone name(s)
    """
    try:
        net, err = _parse_network(cidr)
        if err:
            return err

        zones = []

        if net.version == 4:
            prefix = net.prefixlen
            octets = str(net.network_address).split('.')

            if prefix >= 24:
                # single zone from first 3 octets
                zone = f'{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa'
                zones.append(zone)
            elif prefix == 16:
                zone = f'{octets[1]}.{octets[0]}.in-addr.arpa'
                zones.append(zone)
            elif prefix > 16:
                num_third_octets = 2 ** (24 - prefix)
                base_third = int(octets[2])
                for i in range(num_third_octets):
                    zone = f'{base_third + i}.{octets[1]}.{octets[0]}.in-addr.arpa'
                    zones.append(zone)
            elif prefix >= 8:
                # zone from first 1-2 octets
                zone = f'{octets[1]}.{octets[0]}.in-addr.arpa'
                zones.append(zone)
            else:
                zone = f'{octets[0]}.in-addr.arpa'
                zones.append(zone)
        else:
            # IPv6: nibble-based zones
            expanded = net.network_address.exploded.replace(':', '')
            # number of nibbles determined by prefix (4 bits per nibble)
            nibble_count = net.prefixlen // 4
            nibbles = expanded[:nibble_count]
            zone = '.'.join(reversed(nibbles)) + '.ip6.arpa'
            zones.append(zone)

        return {
            'status': 'success',
            'cidr': str(net),
            'zones': zones,
            'zone_count': len(zones),
            'ip_version': net.version,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def _find_free_blocks(
    parent_net: Any, allocated_nets: List[Any]
) -> List[Any]:
    """Find free address blocks within a parent network.

    Args:
        parent_net: Parent network object
        allocated_nets: List of allocated network objects (must be within parent)

    Returns:
        List of free network objects
    """
    # sort allocations by network address
    sorted_allocs = sorted(allocated_nets, key=lambda n: int(n.network_address))

    # iteratively exclude allocated blocks from parent
    free = [parent_net]
    for alloc in sorted_allocs:
        new_free = []
        for block in free:
            if block.overlaps(alloc):
                try:
                    new_free.extend(block.address_exclude(alloc))
                except ValueError:
                    new_free.append(block)
            else:
                new_free.append(block)
        free = new_free

    # collapse adjacent free blocks
    if free:
        free = list(ipaddress.collapse_addresses(free))

    return free


def capacity_report(parent_cidr: str, allocated_cidrs: List[str]) -> Dict[str, Any]:
    """Generate a capacity report for a network with allocations.

    Args:
        parent_cidr: Parent CIDR notation string
        allocated_cidrs: List of allocated subnet CIDRs

    Returns:
        Dict with utilization metrics and free block analysis
    """
    try:
        parent, err = _parse_network(parent_cidr)
        if err:
            return err

        alloc_nets = []
        for cidr in allocated_cidrs:
            net, err = _parse_network(cidr)
            if err:
                return err
            if not parent.overlaps(net):
                return {
                    'status': 'error',
                    'error': f'{cidr} is not within {parent_cidr}',
                }
            alloc_nets.append(net)

        total = parent.num_addresses
        allocated = sum(n.num_addresses for n in alloc_nets)

        free_blocks = _find_free_blocks(parent, alloc_nets)
        free_list = [str(b) for b in free_blocks]
        free_addresses = sum(b.num_addresses for b in free_blocks)

        # largest free block
        largest_free = max(free_blocks, key=lambda b: b.num_addresses) if free_blocks else None
        largest_free_str = str(largest_free) if largest_free else None
        largest_free_size = largest_free.num_addresses if largest_free else 0

        # fragmentation index: 1 - (largest_free / total_free)
        if free_addresses > 0:
            fragmentation = round(1 - (largest_free_size / free_addresses), 2)
        else:
            fragmentation = 0.0

        utilization_pct = round((allocated / total) * 100, 2) if total > 0 else 0.0

        return {
            'status': 'success',
            'parent': str(parent),
            'total_addresses': total,
            'allocated_addresses': allocated,
            'free_addresses': free_addresses,
            'utilization_pct': utilization_pct,
            'free_blocks': free_list,
            'free_block_count': len(free_list),
            'fragmentation_index': fragmentation,
            'largest_free_block': largest_free_str,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def subnet_diff(old_cidrs: List[str], new_cidrs: List[str]) -> Dict[str, Any]:
    """Compare two sets of CIDRs and find differences.

    Args:
        old_cidrs: Previous list of CIDRs
        new_cidrs: Current list of CIDRs

    Returns:
        Dict with added, removed, and unchanged CIDRs
    """
    try:
        old_nets = []
        for cidr in old_cidrs:
            net, err = _parse_network(cidr)
            if err:
                return err
            old_nets.append(net)

        new_nets = []
        for cidr in new_cidrs:
            net, err = _parse_network(cidr)
            if err:
                return err
            new_nets.append(net)

        old_set = set(str(n) for n in old_nets)
        new_set = set(str(n) for n in new_nets)

        added = sorted(new_set - old_set)
        removed = sorted(old_set - new_set)
        unchanged = sorted(old_set & new_set)

        return {
            'status': 'success',
            'added': added,
            'removed': removed,
            'unchanged': unchanged,
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def find_free_subnets(parent_cidr: str, allocated_cidrs: List[str]) -> Dict[str, Any]:
    """Find unallocated subnets within a parent network.

    Args:
        parent_cidr: Parent CIDR notation string
        allocated_cidrs: List of allocated subnet CIDRs

    Returns:
        Dict with free subnets and statistics
    """
    try:
        parent, err = _parse_network(parent_cidr)
        if err:
            return err

        alloc_nets = []
        for cidr in allocated_cidrs:
            net, err = _parse_network(cidr)
            if err:
                return err
            alloc_nets.append(net)

        free_blocks = _find_free_blocks(parent, alloc_nets)
        free_list = [str(b) for b in free_blocks]
        free_addresses = sum(b.num_addresses for b in free_blocks)
        largest = max(free_blocks, key=lambda b: b.num_addresses) if free_blocks else None

        return {
            'status': 'success',
            'parent': str(parent),
            'free_subnets': free_list,
            'free_count': len(free_list),
            'free_addresses': free_addresses,
            'largest_free': str(largest) if largest else None,
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

    # ip classification
    result = classify_ip('192.168.1.1')
    assert result['classification'] == 'private'
    result = classify_ip('8.8.8.8')
    assert result['classification'] == 'public'
    result = classify_ip('127.0.0.1')
    assert result['classification'] == 'loopback'
    result = classify_ip('169.254.1.1')
    assert result['classification'] == 'link_local'
    print("classify_ip: pass")

    # bogon detection
    result = is_bogon('10.0.0.1')
    assert result['is_bogon'] is True
    assert result['matched_range'] == '10.0.0.0/8'
    result = is_bogon('8.8.8.8')
    assert result['is_bogon'] is False
    result = is_bogon('192.168.1.1')
    assert result['is_bogon'] is True
    print("is_bogon: pass")

    # private / reserved
    result = is_private('10.0.0.1')
    assert result['is_private'] is True
    result = is_reserved('240.0.0.1')
    assert result['is_reserved'] is True
    print("is_private/is_reserved: pass")

    # subnet splitting
    result = split_subnet('10.0.0.0/24', 26)
    assert result['count'] == 4
    assert result['subnets'][0] == '10.0.0.0/26'
    result = split_subnet('10.0.0.0/24', 20)
    assert result['status'] == 'error'
    print("split_subnet: pass")

    # overlap detection
    result = overlap('10.0.0.0/24', '10.0.0.128/25')
    assert result['overlaps'] is True
    result = overlap('10.0.0.0/24', '10.0.1.0/24')
    assert result['overlaps'] is False
    print("overlap: pass")

    # adjacency
    result = adjacent('10.0.0.0/24', '10.0.1.0/24')
    assert result['adjacent'] is True
    result = adjacent('10.0.0.0/24', '10.0.2.0/24')
    assert result['adjacent'] is False
    print("adjacent: pass")

    # vlsm allocation
    result = vlsm_allocate('10.0.0.0/24', [100, 50, 25])
    assert result['status'] == 'success'
    assert len(result['allocations']) == 3
    # largest gets /25 (126 usable), medium gets /26 (62 usable), smallest /27 (30 usable)
    for alloc in result['allocations']:
        assert alloc['usable_hosts'] >= alloc['hosts_requested']
    print(f"vlsm_allocate: {result['utilization_pct']}% utilization")

    # summarization
    result = summarize(['10.0.0.0/24', '10.0.1.0/24'])
    assert '10.0.0.0/23' in result['summary']
    assert result['reduction'] == 1
    print("summarize: pass")

    # wildcard mask
    result = wildcard_mask('192.168.1.0/24')
    assert result['wildcard_mask'] == '0.0.0.255'
    print("wildcard_mask: pass")

    # supernet
    result = supernet('10.0.0.0/24', 16)
    assert result['supernet'] == '10.0.0.0/16'
    result = supernet('10.0.0.0/24', 28)
    assert result['status'] == 'error'
    print("supernet: pass")

    # exclusion
    result = exclude('10.0.0.0/24', '10.0.0.0/25')
    assert '10.0.0.128/25' in result['remaining']
    print("exclude: pass")

    # cidr to range
    result = cidr_to_range('192.168.0.0/24')
    assert result['first_ip'] == '192.168.0.0'
    assert result['last_ip'] == '192.168.0.255'
    assert result['total_addresses'] == 256
    print("cidr_to_range: pass")

    # range to cidrs
    result = range_to_cidrs('192.168.0.0', '192.168.1.255')
    assert '192.168.0.0/23' in result['cidrs']
    print("range_to_cidrs: pass")

    # ipv6 expand/compress
    result = expand_ipv6('2001:db8::1')
    assert result['expanded'] == '2001:0db8:0000:0000:0000:0000:0000:0001'
    result = compress_ipv6('2001:0db8:0000:0000:0000:0000:0000:0001')
    assert result['compressed'] == '2001:db8::1'
    result = expand_ipv6('192.168.1.1')
    assert result['status'] == 'error'
    print("expand/compress_ipv6: pass")

    # eui-64
    result = eui64_address('2001:db8::/64', '00:1A:2B:3C:4D:5E')
    assert result['status'] == 'success'
    assert 'address' in result
    print(f"eui64_address: {result['address']}")

    # link-local
    result = link_local('00:1A:2B:3C:4D:5E')
    assert result['status'] == 'success'
    assert result['address'].startswith('fe80::')
    print(f"link_local: {result['address']}")

    # ptr record
    result = ptr_record('192.168.1.1')
    assert result['ptr'] == '1.1.168.192.in-addr.arpa'
    result = ptr_record('2001:db8::1')
    assert result['ptr'].endswith('.ip6.arpa')
    print("ptr_record: pass")

    # arpa zone
    result = arpa_zone('192.168.1.0/24')
    assert '1.168.192.in-addr.arpa' in result['zones']
    result = arpa_zone('10.0.0.0/23')
    assert result['zone_count'] == 2
    print("arpa_zone: pass")

    # capacity report
    result = capacity_report('10.0.0.0/24', ['10.0.0.0/25'])
    assert result['status'] == 'success'
    assert result['utilization_pct'] == 50.0
    assert result['free_addresses'] == 128
    assert '10.0.0.128/25' in result['free_blocks']
    print(f"capacity_report: {result['utilization_pct']}% used")

    # capacity with multiple allocations
    result = capacity_report('10.0.0.0/24', ['10.0.0.0/26', '10.0.0.128/26'])
    assert result['utilization_pct'] == 50.0
    print("capacity_report multi: pass")

    # subnet diff
    result = subnet_diff(
        ['10.0.0.0/24', '10.0.2.0/24'],
        ['10.0.0.0/24', '10.0.3.0/24'],
    )
    assert '10.0.3.0/24' in result['added']
    assert '10.0.2.0/24' in result['removed']
    assert '10.0.0.0/24' in result['unchanged']
    print("subnet_diff: pass")

    # find free subnets
    result = find_free_subnets('10.0.0.0/24', ['10.0.0.0/25'])
    assert '10.0.0.128/25' in result['free_subnets']
    assert result['free_addresses'] == 128
    print("find_free_subnets: pass")

    print("\nall tests passed")
