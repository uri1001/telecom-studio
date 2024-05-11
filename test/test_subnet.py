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



if __name__ == '__main__':
    unittest.main()
