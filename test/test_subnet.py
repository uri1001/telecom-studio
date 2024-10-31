#!/usr/bin/env python3
"""
test_subnet.py - Comprehensive test suite for subnet.py
"""

import os
import sys
import ipaddress
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.network.subnet import (
    subnet_info,
    contains,
    nth_host,
    classify_ip,
    is_bogon,
    is_private,
    is_reserved,
    split_subnet,
    overlap,
    adjacent,
    vlsm_allocate,
    summarize,
    wildcard_mask,
    supernet,
    exclude,
    cidr_to_range,
    range_to_cidrs,
    expand_ipv6,
    compress_ipv6,
    eui64_address,
    link_local,
    ptr_record,
    arpa_zone,
    capacity_report,
)


class TestSubnetInfo(unittest.TestCase):
    """tests for subnet_info()"""

    def test_slash24_usable_hosts(self):
        result = subnet_info('192.168.1.0/24')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['usable_hosts'], 254)

    def test_slash24_network_address(self):
        result = subnet_info('192.168.1.0/24')
        self.assertEqual(result['network'], '192.168.1.0')

    def test_slash24_broadcast_address(self):
        result = subnet_info('192.168.1.0/24')
        self.assertEqual(result['broadcast'], '192.168.1.255')

    def test_slash24_netmask(self):
        result = subnet_info('192.168.1.0/24')
        self.assertEqual(result['netmask'], '255.255.255.0')

    def test_slash32_single_host(self):
        result = subnet_info('10.0.0.1/32')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['usable_hosts'], 1)
        self.assertEqual(result['first_usable'], '10.0.0.1')
        self.assertEqual(result['last_usable'], '10.0.0.1')

    def test_slash31_rfc3021(self):
        result = subnet_info('10.0.0.0/31')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['usable_hosts'], 2)
        self.assertEqual(result['first_usable'], '10.0.0.0')
        self.assertEqual(result['last_usable'], '10.0.0.1')

    def test_slash16(self):
        result = subnet_info('172.16.0.0/16')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['usable_hosts'], 65534)
        self.assertEqual(result['total_addresses'], 65536)

    def test_ipv6_slash64(self):
        result = subnet_info('2001:db8::/64')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['ip_version'], 6)
        self.assertEqual(result['prefix_length'], 64)

    def test_invalid_cidr_returns_error(self):
        result = subnet_info('not-a-cidr')
        self.assertEqual(result['status'], 'error')
        self.assertIn('error', result)

    def test_is_private_flag(self):
        result = subnet_info('192.168.0.0/16')
        self.assertTrue(result['is_private'])

    def test_public_network_not_private(self):
        result = subnet_info('8.8.8.0/24')
        self.assertFalse(result['is_private'])


class TestContains(unittest.TestCase):
    """tests for contains()"""

    def test_ip_inside_subnet(self):
        result = contains('192.168.1.0/24', '192.168.1.100')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['contains'])

    def test_ip_outside_subnet(self):
        result = contains('192.168.1.0/24', '10.0.0.1')
        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['contains'])

    def test_network_address_boundary(self):
        result = contains('192.168.1.0/24', '192.168.1.0')
        self.assertTrue(result['contains'])

    def test_broadcast_address_boundary(self):
        result = contains('192.168.1.0/24', '192.168.1.255')
        self.assertTrue(result['contains'])

    def test_ipv4_in_ipv6_net(self):
        # ipv4 address checked against ipv6 network returns contains=False
        result = contains('192.168.1.0/24', '::1')
        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['contains'])

    def test_invalid_ip(self):
        result = contains('192.168.1.0/24', 'not-an-ip')
        self.assertEqual(result['status'], 'error')

    def test_invalid_cidr(self):
        result = contains('bad-cidr', '192.168.1.1')
        self.assertEqual(result['status'], 'error')


class TestNthHost(unittest.TestCase):
    """tests for nth_host()"""

    def test_first_usable_host(self):
        result = nth_host('10.0.0.0/24', 1)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['host'], '10.0.0.1')

    def test_last_usable_host_slash24(self):
        result = nth_host('10.0.0.0/24', 254)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['host'], '10.0.0.254')

    def test_n_zero_returns_error(self):
        result = nth_host('10.0.0.0/24', 0)
        self.assertEqual(result['status'], 'error')

    def test_n_exceeds_usable_returns_error(self):
        result = nth_host('10.0.0.0/24', 255)
        self.assertEqual(result['status'], 'error')

    def test_slash31_first(self):
        result = nth_host('10.0.0.0/31', 1)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['host'], '10.0.0.0')

    def test_slash31_second(self):
        result = nth_host('10.0.0.0/31', 2)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['host'], '10.0.0.1')

    def test_slash32_first(self):
        result = nth_host('10.0.0.5/32', 1)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['host'], '10.0.0.5')

    def test_slash32_n2_error(self):
        result = nth_host('10.0.0.5/32', 2)
        self.assertEqual(result['status'], 'error')


class TestClassifyIp(unittest.TestCase):
    """tests for classify_ip()"""

    def test_loopback(self):
        result = classify_ip('127.0.0.1')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['classification'], 'loopback')

    def test_private_192(self):
        result = classify_ip('192.168.1.1')
        self.assertEqual(result['classification'], 'private')

    def test_private_10(self):
        result = classify_ip('10.0.0.1')
        self.assertEqual(result['classification'], 'private')

    def test_public(self):
        result = classify_ip('8.8.8.8')
        self.assertEqual(result['classification'], 'public')
        self.assertTrue(result['is_global'])

    def test_link_local(self):
        result = classify_ip('169.254.1.1')
        self.assertEqual(result['classification'], 'link_local')

    def test_multicast(self):
        result = classify_ip('224.0.0.1')
        self.assertEqual(result['classification'], 'multicast')

    def test_unspecified(self):
        result = classify_ip('0.0.0.0')
        self.assertEqual(result['classification'], 'unspecified')

    def test_reserved(self):
        result = classify_ip('240.0.0.1')
        self.assertEqual(result['classification'], 'reserved')

    def test_invalid_ip_returns_error(self):
        result = classify_ip('not-an-ip')
        self.assertEqual(result['status'], 'error')

    def test_ipv6_loopback(self):
        result = classify_ip('::1')
        self.assertEqual(result['classification'], 'loopback')
        self.assertEqual(result['ip_version'], 6)


class TestIsBogon(unittest.TestCase):
    """tests for is_bogon()"""

    def test_10_is_bogon(self):
        result = is_bogon('10.0.0.1')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['is_bogon'])
        self.assertEqual(result['matched_range'], '10.0.0.0/8')

    def test_8888_not_bogon(self):
        result = is_bogon('8.8.8.8')
        self.assertFalse(result['is_bogon'])

    def test_192168_is_bogon(self):
        result = is_bogon('192.168.1.1')
        self.assertTrue(result['is_bogon'])
        self.assertEqual(result['matched_range'], '192.168.0.0/16')

    def test_ipv6_global_not_bogon(self):
        result = is_bogon('2001:4860:4860::8888')
        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['is_bogon'])
        self.assertEqual(result['ip_version'], 6)

    def test_127_is_bogon(self):
        result = is_bogon('127.0.0.1')
        self.assertTrue(result['is_bogon'])
        self.assertEqual(result['matched_range'], '127.0.0.0/8')

    def test_ipv6_link_local_is_bogon(self):
        result = is_bogon('fe80::1')
        self.assertTrue(result['is_bogon'])


class TestIsPrivate(unittest.TestCase):
    """tests for is_private()"""

    def test_10_network(self):
        result = is_private('10.0.0.1')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['is_private'])

    def test_172_16_network(self):
        result = is_private('172.16.0.1')
        self.assertTrue(result['is_private'])

    def test_192_168_network(self):
        result = is_private('192.168.0.1')
        self.assertTrue(result['is_private'])

    def test_public_not_private(self):
        result = is_private('8.8.8.8')
        self.assertFalse(result['is_private'])

    def test_invalid_ip_returns_error(self):
        result = is_private('invalid')
        self.assertEqual(result['status'], 'error')


class TestIsReserved(unittest.TestCase):
    """tests for is_reserved()"""

    def test_240_is_reserved(self):
        result = is_reserved('240.0.0.1')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['is_reserved'])

    def test_public_not_reserved(self):
        result = is_reserved('8.8.8.8')
        self.assertFalse(result['is_reserved'])

    def test_invalid_ip_returns_error(self):
        result = is_reserved('bad')
        self.assertEqual(result['status'], 'error')


class TestSplitSubnet(unittest.TestCase):
    """tests for split_subnet()"""

    def test_slash24_into_slash26(self):
        result = split_subnet('10.0.0.0/24', 26)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['count'], 4)
        self.assertEqual(result['subnets'][0], '10.0.0.0/26')
        self.assertEqual(result['subnets'][3], '10.0.0.192/26')

    def test_new_prefix_smaller_than_current_error(self):
        result = split_subnet('10.0.0.0/24', 20)
        self.assertEqual(result['status'], 'error')

    def test_new_prefix_equal_to_current_error(self):
        result = split_subnet('10.0.0.0/24', 24)
        self.assertEqual(result['status'], 'error')

    def test_prefix_exceeds_32_error(self):
        result = split_subnet('10.0.0.0/24', 33)
        self.assertEqual(result['status'], 'error')

    def test_safety_cap_65536(self):
        # /8 into /25 = 2^17 = 131072 > 65536
        result = split_subnet('10.0.0.0/8', 25)
        self.assertEqual(result['status'], 'error')
        self.assertIn('65536', result['error'])

    def test_slash24_into_slash25(self):
        result = split_subnet('10.0.0.0/24', 25)
        self.assertEqual(result['count'], 2)


class TestOverlap(unittest.TestCase):
    """tests for overlap()"""

    def test_overlapping_subnets(self):
        result = overlap('10.0.0.0/24', '10.0.0.128/25')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['overlaps'])
        self.assertIn('intersection', result)

    def test_non_overlapping_subnets(self):
        result = overlap('10.0.0.0/24', '10.0.1.0/24')
        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['overlaps'])
        self.assertNotIn('intersection', result)

    def test_identical_subnets_overlap(self):
        result = overlap('10.0.0.0/24', '10.0.0.0/24')
        self.assertTrue(result['overlaps'])
        self.assertEqual(result['intersection'], ['10.0.0.0/24'])

    def test_invalid_cidr_error(self):
        result = overlap('bad', '10.0.0.0/24')
        self.assertEqual(result['status'], 'error')


class TestAdjacent(unittest.TestCase):
    """tests for adjacent()"""

    def test_adjacent_subnets(self):
        result = adjacent('10.0.0.0/24', '10.0.1.0/24')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['adjacent'])
        self.assertIn('merged', result)
        self.assertEqual(result['merged'], ['10.0.0.0/23'])

    def test_non_adjacent_subnets(self):
        result = adjacent('10.0.0.0/24', '10.0.2.0/24')
        self.assertFalse(result['adjacent'])
        self.assertNotIn('merged', result)

    def test_reversed_order_still_adjacent(self):
        result = adjacent('10.0.1.0/24', '10.0.0.0/24')
        self.assertTrue(result['adjacent'])

    def test_same_subnet_not_adjacent(self):
        result = adjacent('10.0.0.0/24', '10.0.0.0/24')
        self.assertFalse(result['adjacent'])


class TestVlsmAllocate(unittest.TestCase):
    """tests for vlsm_allocate()"""

    def test_basic_allocation(self):
        result = vlsm_allocate('10.0.0.0/24', [100, 50, 25])
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['allocations']), 3)

    def test_each_allocation_has_enough_hosts(self):
        result = vlsm_allocate('10.0.0.0/24', [100, 50, 25])
        for alloc in result['allocations']:
            self.assertGreaterEqual(alloc['usable_hosts'], alloc['hosts_requested'])

    def test_utilization_present(self):
        result = vlsm_allocate('10.0.0.0/24', [100, 50, 25])
        self.assertIn('utilization_pct', result)
        self.assertGreater(result['utilization_pct'], 0)

    def test_empty_requirements_error(self):
        result = vlsm_allocate('10.0.0.0/24', [])
        self.assertEqual(result['status'], 'error')

    def test_zero_hosts_error(self):
        result = vlsm_allocate('10.0.0.0/24', [0])
        self.assertEqual(result['status'], 'error')

    def test_insufficient_space_error(self):
        result = vlsm_allocate('10.0.0.0/28', [100])
        self.assertEqual(result['status'], 'error')

    def test_original_order_preserved(self):
        result = vlsm_allocate('10.0.0.0/24', [10, 100, 50])
        self.assertEqual(result['allocations'][0]['hosts_requested'], 10)
        self.assertEqual(result['allocations'][1]['hosts_requested'], 100)
        self.assertEqual(result['allocations'][2]['hosts_requested'], 50)


class TestSummarize(unittest.TestCase):
    """tests for summarize()"""

    def test_two_contiguous_slash24s(self):
        result = summarize(['10.0.0.0/24', '10.0.1.0/24'])
        self.assertEqual(result['status'], 'success')
        self.assertIn('10.0.0.0/23', result['summary'])
        self.assertEqual(result['reduction'], 1)

    def test_empty_list_error(self):
        result = summarize([])
        self.assertEqual(result['status'], 'error')

    def test_single_cidr_no_reduction(self):
        result = summarize(['10.0.0.0/24'])
        self.assertEqual(result['reduction'], 0)
        self.assertEqual(result['summary'], ['10.0.0.0/24'])

    def test_non_contiguous_no_reduction(self):
        result = summarize(['10.0.0.0/24', '10.0.2.0/24'])
        self.assertEqual(result['output_count'], 2)
        self.assertEqual(result['reduction'], 0)


class TestWildcardMask(unittest.TestCase):
    """tests for wildcard_mask()"""

    def test_slash24(self):
        result = wildcard_mask('192.168.1.0/24')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['wildcard_mask'], '0.0.0.255')

    def test_slash32(self):
        result = wildcard_mask('10.0.0.1/32')
        self.assertEqual(result['wildcard_mask'], '0.0.0.0')

    def test_slash16(self):
        result = wildcard_mask('10.0.0.0/16')
        self.assertEqual(result['wildcard_mask'], '0.0.255.255')

    def test_invalid_cidr(self):
        result = wildcard_mask('invalid')
        self.assertEqual(result['status'], 'error')


class TestSupernet(unittest.TestCase):
    """tests for supernet()"""

    def test_slash24_to_slash16(self):
        result = supernet('10.0.0.0/24', 16)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['supernet'], '10.0.0.0/16')

    def test_prefix_gte_current_error(self):
        result = supernet('10.0.0.0/24', 28)
        self.assertEqual(result['status'], 'error')

    def test_prefix_equal_current_error(self):
        result = supernet('10.0.0.0/24', 24)
        self.assertEqual(result['status'], 'error')

    def test_negative_prefix_error(self):
        result = supernet('10.0.0.0/24', -1)
        self.assertEqual(result['status'], 'error')

    def test_slash24_to_slash23(self):
        result = supernet('10.0.0.0/24', 23)
        self.assertEqual(result['supernet'], '10.0.0.0/23')


class TestExclude(unittest.TestCase):
    """tests for exclude()"""

    def test_exclude_slash25_from_slash24(self):
        result = exclude('192.168.1.0/24', '192.168.1.0/25')
        self.assertEqual(result['status'], 'success')
        self.assertIn('192.168.1.128/25', result['remaining'])
        self.assertEqual(result['count'], 1)

    def test_exclude_produces_multiple_remainders(self):
        result = exclude('10.0.0.0/24', '10.0.0.64/26')
        self.assertEqual(result['status'], 'success')
        self.assertGreater(result['count'], 1)

    def test_exclude_non_contained_error(self):
        result = exclude('192.168.1.0/24', '10.0.0.0/24')
        self.assertEqual(result['status'], 'error')


class TestCidrToRange(unittest.TestCase):
    """tests for cidr_to_range()"""

    def test_slash24_range(self):
        result = cidr_to_range('192.168.1.0/24')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['first_ip'], '192.168.1.0')
        self.assertEqual(result['last_ip'], '192.168.1.255')
        self.assertEqual(result['total_addresses'], 256)

    def test_slash32_range(self):
        result = cidr_to_range('10.0.0.5/32')
        self.assertEqual(result['first_ip'], '10.0.0.5')
        self.assertEqual(result['last_ip'], '10.0.0.5')
        self.assertEqual(result['total_addresses'], 1)

    def test_invalid_cidr(self):
        result = cidr_to_range('bad')
        self.assertEqual(result['status'], 'error')


class TestRangeToCidrs(unittest.TestCase):
    """tests for range_to_cidrs()"""

    def test_contiguous_range_to_slash23(self):
        result = range_to_cidrs('192.168.0.0', '192.168.1.255')
        self.assertEqual(result['status'], 'success')
        self.assertIn('192.168.0.0/23', result['cidrs'])

    def test_single_ip_range(self):
        result = range_to_cidrs('10.0.0.1', '10.0.0.1')
        self.assertEqual(result['cidrs'], ['10.0.0.1/32'])

    def test_invalid_start_ip(self):
        result = range_to_cidrs('bad', '10.0.0.1')
        self.assertEqual(result['status'], 'error')

    def test_reversed_range_error(self):
        result = range_to_cidrs('10.0.0.10', '10.0.0.1')
        self.assertEqual(result['status'], 'error')


class TestExpandIpv6(unittest.TestCase):
    """tests for expand_ipv6()"""

    def test_compressed_address(self):
        result = expand_ipv6('2001:db8::1')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['expanded'], '2001:0db8:0000:0000:0000:0000:0000:0001')

    def test_ipv4_returns_error(self):
        result = expand_ipv6('192.168.1.1')
        self.assertEqual(result['status'], 'error')

    def test_full_address_unchanged(self):
        full = '2001:0db8:0000:0000:0000:0000:0000:0001'
        result = expand_ipv6(full)
        self.assertEqual(result['expanded'], full)

    def test_invalid_address(self):
        result = expand_ipv6('not-ipv6')
        self.assertEqual(result['status'], 'error')


class TestCompressIpv6(unittest.TestCase):
    """tests for compress_ipv6()"""

    def test_full_form_compressed(self):
        result = compress_ipv6('2001:0db8:0000:0000:0000:0000:0000:0001')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['compressed'], '2001:db8::1')

    def test_already_compressed(self):
        result = compress_ipv6('::1')
        self.assertEqual(result['compressed'], '::1')

    def test_ipv4_returns_error(self):
        result = compress_ipv6('10.0.0.1')
        self.assertEqual(result['status'], 'error')


class TestEui64Address(unittest.TestCase):
    """tests for eui64_address()"""

    def test_valid_mac_and_prefix(self):
        result = eui64_address('2001:db8::/64', '00:1A:2B:3C:4D:5E')
        self.assertEqual(result['status'], 'success')
        self.assertIn('address', result)
        # result should start with 2001:db8::
        self.assertTrue(result['address'].startswith('2001:db8::'))

    def test_non_slash64_error(self):
        result = eui64_address('2001:db8::/48', '00:1A:2B:3C:4D:5E')
        self.assertEqual(result['status'], 'error')
        self.assertIn('/64', result['error'])

    def test_non_ipv6_prefix_error(self):
        result = eui64_address('192.168.1.0/24', '00:1A:2B:3C:4D:5E')
        self.assertEqual(result['status'], 'error')

    def test_invalid_mac_error(self):
        result = eui64_address('2001:db8::/64', 'ZZZZ')
        self.assertEqual(result['status'], 'error')

    def test_hyphen_mac_format(self):
        result = eui64_address('2001:db8::/64', '00-1A-2B-3C-4D-5E')
        self.assertEqual(result['status'], 'success')

    def test_dot_mac_format(self):
        result = eui64_address('2001:db8::/64', '001A.2B3C.4D5E')
        self.assertEqual(result['status'], 'success')


class TestLinkLocal(unittest.TestCase):
    """tests for link_local()"""

    def test_valid_mac_gives_fe80_prefix(self):
        result = link_local('00:1A:2B:3C:4D:5E')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['address'].startswith('fe80::'))

    def test_invalid_mac_error(self):
        result = link_local('invalid-mac')
        self.assertEqual(result['status'], 'error')

    def test_different_mac(self):
        result = link_local('AA:BB:CC:DD:EE:FF')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['address'].startswith('fe80::'))


class TestPtrRecord(unittest.TestCase):
    """tests for ptr_record()"""

    def test_ipv4_ptr(self):
        result = ptr_record('192.168.1.1')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['ptr'], '1.1.168.192.in-addr.arpa')

    def test_ipv6_ptr(self):
        result = ptr_record('2001:db8::1')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['ptr'].endswith('.ip6.arpa'))

    def test_invalid_ip(self):
        result = ptr_record('bad')
        self.assertEqual(result['status'], 'error')

    def test_loopback_ptr(self):
        result = ptr_record('127.0.0.1')
        self.assertEqual(result['ptr'], '1.0.0.127.in-addr.arpa')


class TestArpaZone(unittest.TestCase):
    """tests for arpa_zone()"""

    def test_slash24_single_zone(self):
        result = arpa_zone('192.168.1.0/24')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['zone_count'], 1)
        self.assertEqual(result['zones'][0], '1.168.192.in-addr.arpa')

    def test_slash23_gives_2_zones(self):
        result = arpa_zone('192.168.0.0/23')
        self.assertEqual(result['zone_count'], 2)
        self.assertIn('0.168.192.in-addr.arpa', result['zones'])
        self.assertIn('1.168.192.in-addr.arpa', result['zones'])

    def test_ipv6_zone(self):
        result = arpa_zone('2001:db8::/32')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['ip_version'], 6)
        self.assertTrue(result['zones'][0].endswith('.ip6.arpa'))

    def test_slash16_zone(self):
        result = arpa_zone('10.0.0.0/16')
        self.assertEqual(result['zone_count'], 1)
        self.assertEqual(result['zones'][0], '0.10.in-addr.arpa')

    def test_invalid_cidr(self):
        result = arpa_zone('bad')
        self.assertEqual(result['status'], 'error')


class TestCapacityReport(unittest.TestCase):
    """tests for capacity_report()"""

    def test_half_allocated(self):
        result = capacity_report('192.168.0.0/24', ['192.168.0.0/25'])
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['utilization_pct'], 50.0)
        self.assertEqual(result['free_addresses'], 128)
        self.assertEqual(result['allocated_addresses'], 128)

    def test_fully_allocated(self):
        result = capacity_report('10.0.0.0/24', ['10.0.0.0/24'])
        self.assertEqual(result['utilization_pct'], 100.0)
        self.assertEqual(result['free_addresses'], 0)

    def test_no_allocations(self):
        result = capacity_report('10.0.0.0/24', [])
        self.assertEqual(result['utilization_pct'], 0.0)
        self.assertEqual(result['free_addresses'], 256)

    def test_allocation_outside_parent_error(self):
        result = capacity_report('10.0.0.0/24', ['192.168.0.0/24'])
        self.assertEqual(result['status'], 'error')

    def test_fragmentation_index(self):
        # two small allocations leaving fragmented free space
        result = capacity_report('10.0.0.0/24', ['10.0.0.0/26', '10.0.0.128/26'])
        self.assertEqual(result['status'], 'success')
        self.assertIn('fragmentation_index', result)



if __name__ == '__main__':
    unittest.main()
