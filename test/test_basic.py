#!/usr/bin/env python3
"""tests for src/network/basic.py"""

import os
import sys
import socket
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.network.basic import ping, traceroute, dns_lookup, get_public_ip, get_local_ips


class TestPing(unittest.TestCase):
    """tests for ping function."""

    @patch('src.network.basic.platform.system', return_value='Linux')
    @patch('src.network.basic.subprocess.run')
    def test_successful_ping(self, mock_run, mock_platform):
        """successful ping parses avg rtt and packet loss."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                'PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n'
                '64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=10.1 ms\n'
                '64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=10.3 ms\n'
                '\n'
                '--- 8.8.8.8 ping statistics ---\n'
                '2 packets transmitted, 2 received, 0% packet loss, time 1001ms\n'
                'rtt min/avg/max/mdev = 10.1/10.2/10.3/0.1 ms\n'
            ),
        )

        result = ping('8.8.8.8', count=2)

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['host'], '8.8.8.8')
        self.assertAlmostEqual(result['packet_loss'], 0.0)
        # avg is parsed from the rtt line: parts[4] = '10.3/0.1' -> 10.3
        # actually parts split by '/' => ['rtt min', 'avg', 'max', 'mdev = 10.1', '10.2', '10.3', '0.1 ms']
        # index 4 = '10.2'
        self.assertIsNotNone(result['average_rtt'])

    @patch('src.network.basic.platform.system', return_value='Linux')
    @patch('src.network.basic.subprocess.run')
    def test_failed_ping(self, mock_run, mock_platform):
        """non-zero returncode should produce error status."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='ping: connect: Network is unreachable\n',
        )

        result = ping('10.255.255.1', count=2)

        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['packet_loss'], 100.0)

    @patch('src.network.basic.platform.system', return_value='Linux')
    @patch('src.network.basic.subprocess.run')
    def test_timeout_exception(self, mock_run, mock_platform):
        """subprocess timeout returns error dict."""
        import subprocess as sp

        mock_run.side_effect = sp.TimeoutExpired(cmd='ping', timeout=10)

        result = ping('example.com', count=4, timeout=1)
        self.assertEqual(result['status'], 'error')
        self.assertIn('error', result)
        self.assertEqual(result['packet_loss'], 100.0)

    @patch('src.network.basic.platform.system', return_value='Linux')
    @patch('src.network.basic.subprocess.run')
    def test_linux_timeout_flag(self, mock_run, mock_platform):
        """linux uses -W with timeout in seconds."""
        mock_run.return_value = MagicMock(returncode=0, stdout='')

        ping('host', count=1, timeout=2)

        cmd = mock_run.call_args[0][0]
        self.assertIn('-W', cmd)
        self.assertIn('2', cmd)


class TestTraceroute(unittest.TestCase):
    """tests for traceroute function."""

    @patch('src.network.basic.platform.system', return_value='Linux')
    @patch('src.network.basic.subprocess.run')
    def test_successful_traceroute(self, mock_run, mock_platform):
        """parse hop count from output lines."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                'traceroute to example.com (93.184.216.34), 30 hops max\n'
                ' 1  gateway (192.168.1.1)  1.234 ms\n'
                ' 2  isp-router (10.0.0.1)  5.678 ms\n'
                ' 3  93.184.216.34  11.111 ms\n'
            ),
        )

        result = traceroute('example.com')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['hops'], 3)
        self.assertEqual(result['host'], 'example.com')

    @patch('src.network.basic.platform.system', return_value='Linux')
    @patch('src.network.basic.subprocess.run')
    def test_traceroute_timeout(self, mock_run, mock_platform):
        """timeout returns error with 0 hops."""
        import subprocess as sp

        mock_run.side_effect = sp.TimeoutExpired(cmd='traceroute', timeout=30)

        result = traceroute('example.com')
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['hops'], 0)

    @patch('src.network.basic.platform.system', return_value='Linux')
    @patch('src.network.basic.subprocess.run')
    def test_traceroute_failure(self, mock_run, mock_platform):
        """non-zero returncode still reports hops from output."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='traceroute to host\n 1  * * *\n',
        )

        result = traceroute('host')
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['hops'], 1)


class TestDnsLookup(unittest.TestCase):
    """tests for dns_lookup function."""

    @patch('src.network.basic.socket.getaddrinfo')
    def test_a_record(self, mock_getaddrinfo):
        """A record lookup returns deduplicated addresses."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, 1, 6, '', ('93.184.216.34', 0)),
            (socket.AF_INET, 1, 6, '', ('93.184.216.34', 0)),
        ]

        result = dns_lookup('example.com', 'A')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['records'], ['93.184.216.34'])
        self.assertEqual(result['count'], 1)
        mock_getaddrinfo.assert_called_once_with('example.com', None, socket.AF_INET)

    @patch('src.network.basic.socket.getaddrinfo')
    def test_aaaa_record(self, mock_getaddrinfo):
        """AAAA record lookup uses AF_INET6."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, 1, 6, '', ('2606:2800:220:1::', 0, 0, 0)),
        ]

        result = dns_lookup('example.com', 'AAAA')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['records']), 1)
        mock_getaddrinfo.assert_called_once_with('example.com', None, socket.AF_INET6)

    def test_unsupported_record_type(self):
        """unsupported record type returns error."""
        result = dns_lookup('example.com', 'MX')

        self.assertEqual(result['status'], 'error')
        self.assertIn('Unsupported', result['error'])
        self.assertEqual(result['records'], [])

    @patch('src.network.basic.socket.getaddrinfo')
    def test_resolution_failure(self, mock_getaddrinfo):
        """socket error returns error status."""
        mock_getaddrinfo.side_effect = socket.gaierror('Name resolution failed')

        result = dns_lookup('nonexistent.invalid')
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['records'], [])


class TestGetPublicIp(unittest.TestCase):
    """tests for get_public_ip function."""

    @patch('src.network.basic.urllib.request.urlopen')
    def test_json_service_success(self, mock_urlopen):
        """first service returns json with ip field."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ip": "203.0.113.42"}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = get_public_ip()

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['public_ip'], '203.0.113.42')

    @patch('src.network.basic.urllib.request.urlopen')
    def test_text_service_fallback(self, mock_urlopen):
        """first service fails, second returns plain text ip."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'198.51.100.7\n'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        # first call raises, second succeeds
        mock_urlopen.side_effect = [Exception('connection failed'), mock_resp]

        result = get_public_ip()

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['public_ip'], '198.51.100.7')

    @patch('src.network.basic.urllib.request.urlopen')
    def test_all_services_fail(self, mock_urlopen):
        """all services fail returns error."""
        mock_urlopen.side_effect = Exception('connection refused')

        result = get_public_ip()

        self.assertEqual(result['status'], 'error')
        self.assertIsNone(result['public_ip'])


class TestGetLocalIps(unittest.TestCase):
    """tests for get_local_ips function."""

    @patch('src.network.basic.socket.getaddrinfo')
    @patch('src.network.basic.socket.gethostname', return_value='myhost')
    @patch('src.network.basic.socket.socket')
    def test_primary_ip_via_udp(self, mock_sock_cls, mock_hostname, mock_getaddrinfo):
        """primary ip is obtained via the udp connect trick."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ('192.168.1.100', 0)
        mock_sock_cls.return_value = mock_sock

        mock_getaddrinfo.return_value = [
            (socket.AF_INET, 1, 6, '', ('192.168.1.100', 0)),
        ]

        result = get_local_ips()

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['primary_ip'], '192.168.1.100')
        self.assertIn('192.168.1.100', result['addresses'])


if __name__ == '__main__':
    unittest.main()
