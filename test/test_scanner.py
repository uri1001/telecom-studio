#!/usr/bin/env python3
"""tests for src/network/scanner.py"""

import os
import sys
import socket
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.network.scanner import (
    scan_port,
    scan_common_ports,
    service_fingerprint,
    scan_network_range,
    detect_os,
    COMMON_PORTS,
)


class TestCommonPorts(unittest.TestCase):
    """tests for COMMON_PORTS constant."""

    def test_expected_ports_present(self):
        """critical ports are mapped to expected service names."""
        self.assertEqual(COMMON_PORTS[22], 'SSH')
        self.assertEqual(COMMON_PORTS[80], 'HTTP')
        self.assertEqual(COMMON_PORTS[443], 'HTTPS')
        self.assertEqual(COMMON_PORTS[3306], 'MySQL')
        self.assertEqual(COMMON_PORTS[5432], 'PostgreSQL')
        self.assertEqual(COMMON_PORTS[6379], 'Redis')
        self.assertEqual(COMMON_PORTS[27017], 'MongoDB')

    def test_ports_are_integers(self):
        """all keys should be integers."""
        for port in COMMON_PORTS:
            self.assertIsInstance(port, int)


class TestScanPort(unittest.TestCase):
    """tests for scan_port function."""

    @patch('src.network.scanner.socket.socket')
    def test_open_port(self, mock_sock_cls):
        """connect_ex returns 0 -> port is open."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        result = scan_port('example.com', 80)

        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['is_open'])
        self.assertEqual(result['state'], 'open')
        self.assertEqual(result['service'], 'HTTP')

    @patch('src.network.scanner.socket.socket')
    def test_closed_port(self, mock_sock_cls):
        """connect_ex returns non-zero -> port is closed."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111
        mock_sock_cls.return_value = mock_sock

        result = scan_port('example.com', 80)

        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['is_open'])
        self.assertEqual(result['state'], 'closed')
        self.assertIsNone(result['service'])

    @patch('src.network.scanner.socket.socket')
    def test_gaierror_host_not_found(self, mock_sock_cls):
        """gaierror returns host not found error."""
        mock_sock_cls.side_effect = socket.gaierror('Name resolution failed')

        result = scan_port('invalid.host', 80)

        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['error'], 'Host not found')
        self.assertFalse(result['is_open'])
        self.assertEqual(result['state'], 'error')

    @patch('src.network.scanner.socket.socket')
    def test_unknown_service_port(self, mock_sock_cls):
        """port not in COMMON_PORTS shows 'Unknown' when open."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        result = scan_port('example.com', 9999)

        self.assertTrue(result['is_open'])
        self.assertEqual(result['service'], 'Unknown')


class TestScanCommonPorts(unittest.TestCase):
    """tests for scan_common_ports function."""

    @patch('src.network.scanner.scan_port')
    def test_open_and_closed_ports(self, mock_scan_port):
        """verify open_ports and closed_ports structure."""
        def fake_scan(host, port, timeout=1.0):
            if port in (80, 443):
                return {
                    'status': 'success',
                    'host': host,
                    'port': port,
                    'is_open': True,
                    'service': COMMON_PORTS.get(port, 'Unknown'),
                    'state': 'open',
                }
            return {
                'status': 'success',
                'host': host,
                'port': port,
                'is_open': False,
                'service': None,
                'state': 'closed',
            }

        mock_scan_port.side_effect = fake_scan

        result = scan_common_ports('example.com')

        self.assertEqual(result['status'], 'success')
        open_port_numbers = [p['port'] for p in result['open_ports']]
        self.assertIn(80, open_port_numbers)
        self.assertIn(443, open_port_numbers)
        self.assertEqual(result['total_open'], 2)
        self.assertEqual(result['total_scanned'], len(COMMON_PORTS))

    @patch('src.network.scanner.scan_port')
    def test_all_closed(self, mock_scan_port):
        """no open ports -> empty open_ports list."""
        mock_scan_port.return_value = {
            'status': 'success',
            'host': 'h',
            'port': 80,
            'is_open': False,
            'service': None,
            'state': 'closed',
        }

        result = scan_common_ports('example.com')
        self.assertEqual(result['total_open'], 0)
        self.assertEqual(len(result['open_ports']), 0)


class TestScanNetworkRange(unittest.TestCase):
    """tests for scan_network_range function."""

    def test_network_too_large(self):
        """network larger than /24 returns error."""
        result = scan_network_range('10.0.0.0/16', port=80)

        self.assertEqual(result['status'], 'error')
        self.assertIn('too large', result['error'])

    @patch('src.network.scanner.scan_port')
    def test_valid_small_network(self, mock_scan_port):
        """valid /28 scan returns hosts_up/hosts_down."""
        def fake_scan(host, port, timeout=1.0):
            # only .1 is open
            return {
                'status': 'success',
                'host': host,
                'port': port,
                'is_open': host.endswith('.1'),
                'service': 'HTTP' if host.endswith('.1') else None,
                'state': 'open' if host.endswith('.1') else 'closed',
            }

        mock_scan_port.side_effect = fake_scan

        result = scan_network_range('192.168.1.0/28', port=80)

        self.assertEqual(result['status'], 'success')
        self.assertGreater(len(result['hosts_up']), 0)
        self.assertIn('192.168.1.1', [h['host'] for h in result['hosts_up']])


class TestDetectOs(unittest.TestCase):
    """tests for detect_os function."""

    @patch('src.network.scanner.scan_port')
    @patch('src.network.scanner.subprocess.run')
    @patch('src.network.scanner.platform.system', return_value='Linux')
    def test_linux_ttl(self, mock_platform, mock_run, mock_scan):
        """TTL <= 64 should guess Linux/Unix."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                'PING host (192.168.1.1) 56(84) bytes of data.\n'
                '64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.5 ms\n'
            ),
        )

        mock_scan.return_value = {'is_open': False}

        result = detect_os('192.168.1.1')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['ttl'], 64)
        self.assertEqual(result['os_guess'], 'Linux/Unix')

    @patch('src.network.scanner.scan_port')
    @patch('src.network.scanner.subprocess.run')
    @patch('src.network.scanner.platform.system', return_value='Linux')
    def test_windows_ttl(self, mock_platform, mock_run, mock_scan):
        """TTL <= 128 (and > 64) should guess Windows."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='Reply from 10.0.0.5: bytes=32 time=1ms TTL=128\n',
        )

        mock_scan.return_value = {'is_open': False}

        result = detect_os('10.0.0.5')

        self.assertEqual(result['ttl'], 128)
        self.assertEqual(result['os_guess'], 'Windows')

    @patch('src.network.scanner.scan_port')
    @patch('src.network.scanner.subprocess.run')
    @patch('src.network.scanner.platform.system', return_value='Linux')
    def test_no_ttl_returns_unknown(self, mock_platform, mock_run, mock_scan):
        """when ping fails, os_guess is 'Unknown'."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='',
        )

        mock_scan.return_value = {'is_open': False}

        result = detect_os('10.0.0.5')

        self.assertIsNone(result['ttl'])
        self.assertEqual(result['os_guess'], 'Unknown')
        self.assertEqual(result['confidence'], 'low')


class TestServiceFingerprint(unittest.TestCase):
    """tests for service_fingerprint function."""

    @patch('src.network.scanner.socket.socket')
    def test_closed_port_returns_error(self, mock_sock_cls):
        """port closed -> error."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        mock_sock_cls.return_value = mock_sock

        result = service_fingerprint('host', 22)
        self.assertEqual(result['status'], 'error')
        self.assertIn('closed', result['error'])


if __name__ == '__main__':
    unittest.main()
