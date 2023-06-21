#!/usr/bin/env python3
"""tests for src/network/home.py"""

import os
import sys
import struct
import socket
import unittest
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.network.home import (
    _get_default_gateway,
    _get_primary_ip,
    _ping_host,
    discover_lan_devices,
    gateway_health,
    interface_info,
    check_connectivity,
    dns_benchmark,
    _build_dns_query,
)


class TestGetDefaultGateway(unittest.TestCase):
    """tests for _get_default_gateway function."""

    @patch('src.network.home.platform.system', return_value='Linux')
    @patch('src.network.home.subprocess.run')
    def test_linux_gateway(self, mock_run, mock_platform):
        """parse 'ip route show default' output on linux."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='default via 192.168.1.1 dev eth0 proto dhcp metric 100\n',
        )

        result = _get_default_gateway()
        self.assertEqual(result, '192.168.1.1')

    @patch('src.network.home.platform.system', return_value='Windows')
    @patch('src.network.home.subprocess.run')
    def test_windows_gateway(self, mock_run, mock_platform):
        """parse 'ipconfig' output on windows."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                'Ethernet adapter:\n'
                '   Connection-specific DNS Suffix  . :\n'
                '   Default Gateway . . . . . . . . . : 10.0.0.1\n'
            ),
        )

        result = _get_default_gateway()
        self.assertEqual(result, '10.0.0.1')

    @patch('src.network.home.platform.system', return_value='Linux')
    @patch('src.network.home.subprocess.run')
    def test_no_gateway_returns_none(self, mock_run, mock_platform):
        """no default route -> returns None."""
        mock_run.return_value = MagicMock(returncode=0, stdout='')

        result = _get_default_gateway()
        self.assertIsNone(result)

    @patch('src.network.home.platform.system', return_value='Linux')
    @patch('src.network.home.subprocess.run')
    def test_exception_returns_none(self, mock_run, mock_platform):
        """subprocess failure returns None."""
        mock_run.side_effect = Exception('command not found')

        result = _get_default_gateway()
        self.assertIsNone(result)


class TestGetPrimaryIp(unittest.TestCase):
    """tests for _get_primary_ip function."""

    @patch('src.network.home.socket.socket')
    def test_returns_ip(self, mock_sock_cls):
        """udp connect trick returns local ip."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ('192.168.1.50', 0)
        mock_sock_cls.return_value = mock_sock

        result = _get_primary_ip()
        self.assertEqual(result, '192.168.1.50')
        mock_sock.connect.assert_called_once_with(('8.8.8.8', 80))
        mock_sock.close.assert_called_once()

    @patch('src.network.home.socket.socket')
    def test_exception_returns_none(self, mock_sock_cls):
        """network error returns None."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError('Network unreachable')
        mock_sock_cls.return_value = mock_sock

        result = _get_primary_ip()
        self.assertIsNone(result)


class TestBuildDnsQuery(unittest.TestCase):
    """tests for _build_dns_query function."""

    def test_returns_bytes(self):
        """query is a bytes object."""
        query = _build_dns_query('example.com')
        self.assertIsInstance(query, bytes)

    def test_header_is_12_bytes(self):
        """dns header is always 12 bytes."""
        query = _build_dns_query('example.com')
        # first 12 bytes are header
        self.assertGreaterEqual(len(query), 12)

    def test_contains_domain_labels(self):
        """query contains length-prefixed domain labels."""
        query = _build_dns_query('example.com')
        # 'example' = 7 chars, so \x07example should be in the query
        self.assertIn(b'\x07example', query)
        # 'com' = 3 chars, so \x03com should be in the query
        self.assertIn(b'\x03com', query)

    def test_ends_with_type_and_class(self):
        """question section ends with type A (1) and class IN (1)."""
        query = _build_dns_query('test.org')
        # after null terminator, type=1, class=1 -> \x00\x01\x00\x01
        self.assertTrue(query.endswith(b'\x00\x01\x00\x01'))


class TestCheckConnectivity(unittest.TestCase):
    """tests for check_connectivity function."""

    @patch('src.network.home.urllib.request.urlopen')
    @patch('src.network.home.socket.getaddrinfo')
    @patch('src.network.home._ping_host')
    @patch('src.network.home._get_default_gateway')
    @patch('src.network.home.time.perf_counter')
    def test_all_good(self, mock_perf, mock_gw, mock_ping, mock_dns, mock_urlopen):
        """gateway + dns + internet all pass -> 'all_good'."""
        mock_gw.return_value = '192.168.1.1'
        mock_ping.return_value = 1.5
        mock_dns.return_value = [('AF_INET', 1, 6, '', ('142.250.80.46', 80))]
        mock_perf.side_effect = [0.0, 0.005, 0.0, 0.050]
        mock_urlopen.return_value = MagicMock()

        result = check_connectivity()

        self.assertEqual(result['overall'], 'all_good')
        self.assertTrue(result['gateway']['reachable'])
        self.assertTrue(result['dns']['working'])
        self.assertTrue(result['internet']['reachable'])

    @patch('src.network.home._ping_host')
    @patch('src.network.home._get_default_gateway')
    def test_gateway_down(self, mock_gw, mock_ping):
        """gateway unreachable -> 'gateway_down'."""
        mock_gw.return_value = '192.168.1.1'
        mock_ping.return_value = None

        result = check_connectivity()

        self.assertEqual(result['overall'], 'gateway_down')
        self.assertFalse(result['gateway']['reachable'])

    @patch('src.network.home.socket.getaddrinfo')
    @patch('src.network.home._ping_host')
    @patch('src.network.home._get_default_gateway')
    @patch('src.network.home.time.perf_counter')
    def test_dns_issue(self, mock_perf, mock_gw, mock_ping, mock_dns):
        """gateway up but dns fails -> 'dns_issue'."""
        mock_gw.return_value = '192.168.1.1'
        mock_ping.return_value = 1.0
        mock_dns.side_effect = socket.gaierror('DNS resolution failed')
        mock_perf.side_effect = [0.0, 0.001]

        result = check_connectivity()

        self.assertEqual(result['overall'], 'dns_issue')

    @patch('src.network.home.urllib.request.urlopen')
    @patch('src.network.home.socket.getaddrinfo')
    @patch('src.network.home._ping_host')
    @patch('src.network.home._get_default_gateway')
    @patch('src.network.home.time.perf_counter')
    def test_internet_unreachable(
        self, mock_perf, mock_gw, mock_ping, mock_dns, mock_urlopen
    ):
        """gateway + dns ok but http fails -> 'internet_unreachable'."""
        mock_gw.return_value = '192.168.1.1'
        mock_ping.return_value = 1.0
        mock_dns.return_value = [('AF_INET', 1, 6, '', ('93.184.216.34', 80))]
        mock_perf.side_effect = [0.0, 0.001, 0.0, 0.001]
        mock_urlopen.side_effect = Exception('connection refused')

        result = check_connectivity()

        self.assertEqual(result['overall'], 'internet_unreachable')


class TestInterfaceInfo(unittest.TestCase):
    """tests for interface_info function."""

    @patch('src.network.home.platform.system', return_value='Linux')
    @patch('src.network.home.subprocess.run')
    def test_parse_ip_addr_output(self, mock_run, mock_platform):
        """parse 'ip addr' output to get interface names and IPs."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n'
                '    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n'
                '    inet 127.0.0.1/8 scope host lo\n'
                '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n'
                '    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n'
                '    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n'
            ),
        )

        # mock open for /proc/net/wireless to avoid FileNotFoundError
        with patch('builtins.open', side_effect=FileNotFoundError):
            result = interface_info()

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['total'], 2)

        names = [iface['name'] for iface in result['interfaces']]
        self.assertIn('lo', names)
        self.assertIn('eth0', names)

        eth0 = next(i for i in result['interfaces'] if i['name'] == 'eth0')
        self.assertEqual(eth0['ip'], '192.168.1.100')
        self.assertEqual(eth0['mac'], 'aa:bb:cc:dd:ee:ff')
        self.assertTrue(eth0['is_up'])


class TestGatewayHealth(unittest.TestCase):
    """tests for gateway_health function."""

    @patch('src.network.home.socket.socket')
    @patch('src.network.home.subprocess.run')
    @patch('src.network.home._get_default_gateway')
    @patch('src.network.home.platform.system', return_value='Linux')
    def test_gateway_reachable(self, mock_platform, mock_gw, mock_run, mock_sock_cls):
        """gateway responds to ping and has admin port open."""
        mock_gw.return_value = '192.168.1.1'

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                '--- 192.168.1.1 ping statistics ---\n'
                '4 packets transmitted, 4 received, 0% packet loss\n'
                'rtt min/avg/max/mdev = 0.5/1.0/1.5/0.3 ms\n'
            ),
        )

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        result = gateway_health()

        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['is_reachable'])
        self.assertEqual(result['gateway_ip'], '192.168.1.1')


if __name__ == '__main__':
    unittest.main()
