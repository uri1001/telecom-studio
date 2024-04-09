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



if __name__ == '__main__':
    unittest.main()
