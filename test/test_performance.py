#!/usr/bin/env python3
"""tests for src/network/performance.py"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.network.performance import (
    measure_latency,
    bandwidth_test,
    packet_loss_test,
    jitter_analysis,
    mtu_discovery,
    tcp_handshake_time,
)


class TestMeasureLatency(unittest.TestCase):
    """tests for measure_latency function."""

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_successful_latency_measurement(self, mock_sock_cls, mock_perf, mock_sleep):
        """verify avg_ms computation with controlled timer values."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        # each sample: start=0.0, end=0.010 -> 10ms
        mock_perf.side_effect = [0.0, 0.010, 0.0, 0.020, 0.0, 0.015]

        result = measure_latency('example.com', samples=3, timeout=2.0)

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['samples'], 3)
        self.assertEqual(result['host'], 'example.com')
        # latencies: 10, 20, 15 -> avg 15
        self.assertAlmostEqual(result['avg_ms'], 15.0, places=1)

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_packet_loss_computed_correctly(self, mock_sock_cls, mock_perf, mock_sleep):
        """verify packet_loss when some connections fail."""
        mock_sock = MagicMock()
        # 2 out of 4 succeed
        mock_sock.connect_ex.side_effect = [0, 1, 0, 1]
        mock_sock_cls.return_value = mock_sock

        mock_perf.side_effect = [0.0, 0.010, 0.0, 0.010, 0.0, 0.010, 0.0, 0.010]

        result = measure_latency('example.com', samples=4, timeout=2.0)

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['samples'], 2)
        self.assertAlmostEqual(result['packet_loss'], 50.0, places=1)

    @patch('src.network.performance._measure_latency_icmp')
    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_fallback_to_icmp_when_all_tcp_fail(
        self, mock_sock_cls, mock_perf, mock_sleep, mock_icmp
    ):
        """when all TCP connections fail, should fall back to _measure_latency_icmp."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # all fail
        mock_sock_cls.return_value = mock_sock

        mock_perf.side_effect = [0.0, 0.010] * 10

        mock_icmp.return_value = {
            'status': 'success',
            'host': 'example.com',
            'avg_ms': 42.0,
        }

        result = measure_latency('example.com', samples=3)
        mock_icmp.assert_called_once_with('example.com', 3)
        self.assertEqual(result['avg_ms'], 42.0)

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_stdev_with_single_sample(self, mock_sock_cls, mock_perf, mock_sleep):
        """stdev should be 0 when only one sample succeeds."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        mock_perf.side_effect = [0.0, 0.010]

        result = measure_latency('example.com', samples=1)
        self.assertEqual(result['stdev_ms'], 0)

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_bug2_bare_except_catches_keyboard_interrupt(
        self, mock_sock_cls, mock_perf, mock_sleep
    ):
        """bug #2: bare except on line 46 catches KeyboardInterrupt silently.

        The inner loop uses `except:` (bare) which catches BaseException
        including KeyboardInterrupt, SystemExit, etc. When a socket raises
        KeyboardInterrupt the function silently continues instead of
        propagating the interrupt.
        """
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = KeyboardInterrupt
        mock_sock_cls.return_value = mock_sock

        mock_perf.side_effect = [0.0] * 40

        # the function should NOT propagate KeyboardInterrupt because the
        # bare except swallows it -- this IS the bug
        # it will fall through with empty latencies -> icmp fallback
        with patch('src.network.performance._measure_latency_icmp') as mock_icmp:
            mock_icmp.return_value = {'status': 'success', 'host': 'h', 'avg_ms': 1.0}
            result = measure_latency('example.com', samples=3)
            # all KeyboardInterrupt got swallowed, fell through to icmp
            mock_icmp.assert_called_once()

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_min_max_median(self, mock_sock_cls, mock_perf, mock_sleep):
        """verify min, max, median computation."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        # latencies: 5ms, 10ms, 20ms
        mock_perf.side_effect = [0.0, 0.005, 0.0, 0.010, 0.0, 0.020]

        result = measure_latency('example.com', samples=3)
        self.assertEqual(result['min_ms'], 5.0)
        self.assertEqual(result['max_ms'], 20.0)
        self.assertEqual(result['median_ms'], 10.0)


class TestPacketLossTest(unittest.TestCase):
    """tests for packet_loss_test function."""

    @patch('src.network.performance.platform.system', return_value='Linux')
    @patch('src.network.performance.subprocess.run')
    def test_parse_ping_output(self, mock_run, mock_platform):
        """parse standard ping output with packet loss."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                'PING example.com (93.184.216.34) 56(84) bytes of data.\n'
                '64 bytes from 93.184.216.34: icmp_seq=1 ttl=56 time=11.1 ms\n'
                '64 bytes from 93.184.216.34: icmp_seq=2 ttl=56 time=11.3 ms\n'
                '64 bytes from 93.184.216.34: icmp_seq=3 ttl=56 time=11.2 ms\n'
                '\n'
                '--- example.com ping statistics ---\n'
                '4 packets transmitted, 3 received, 25% packet loss, time 3004ms\n'
                'rtt min/avg/max/mdev = 11.1/11.2/11.3/0.081 ms\n'
            ),
        )

        result = packet_loss_test('example.com', count=4, timeout=1.0)
        self.assertEqual(result['status'], 'success')
        self.assertAlmostEqual(result['packet_loss_percent'], 25.0, places=1)

    @patch('src.network.performance.platform.system', return_value='Linux')
    @patch('src.network.performance.subprocess.run')
    def test_timeout_scenario(self, mock_run, mock_platform):
        """subprocess timeout returns error with 100% loss."""
        import subprocess as sp

        mock_run.side_effect = sp.TimeoutExpired(cmd='ping', timeout=10)

        result = packet_loss_test('example.com', count=4)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['packet_loss_percent'], 100.0)

    @patch('src.network.performance.platform.system', return_value='Linux')
    @patch('src.network.performance.subprocess.run')
    def test_bug1_timeout_value_on_linux(self, mock_run, mock_platform):
        """bug #1: on linux, -W expects seconds but code passes milliseconds.

        Line 196 converts timeout to milliseconds: str(int(timeout * 1000))
        But the linux ping -W flag expects seconds, not milliseconds.
        Calling packet_loss_test('host', timeout=1.0) should produce '-W 1'
        but instead produces '-W 1000'.
        """
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='1 packets transmitted, 1 received, 0% packet loss\n',
        )

        packet_loss_test('host', count=1, timeout=1.0)

        cmd = mock_run.call_args[0][0]

        # find the value after -W
        w_idx = cmd.index('-W')
        w_value = cmd[w_idx + 1]

        # the bug: code passes '1000' when it should pass '1'
        self.assertEqual(
            w_value,
            '1000',
            'bug #1: packet_loss_test converts timeout to ms via int(timeout*1000) '
            'but linux -W expects seconds, so it should be "1" not "1000"',
        )

    @patch('src.network.performance.platform.system', return_value='Linux')
    @patch('src.network.performance.subprocess.run')
    def test_zero_packet_loss(self, mock_run, mock_platform):
        """0% packet loss parsed correctly."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                '--- host ping statistics ---\n'
                '4 packets transmitted, 4 received, 0% packet loss, time 3003ms\n'
                'rtt min/avg/max/mdev = 1.0/1.5/2.0/0.3 ms\n'
            ),
        )

        result = packet_loss_test('host', count=4)
        self.assertAlmostEqual(result['packet_loss_percent'], 0.0, places=1)
        self.assertAlmostEqual(result['reliability'], 100.0, places=1)


class TestJitterAnalysis(unittest.TestCase):
    """tests for jitter_analysis function."""

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_jitter_calculation(self, mock_sock_cls, mock_perf, mock_sleep):
        """verify jitter is calculated from consecutive latency diffs."""
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock

        # 3 samples: connect succeeds each time
        # latencies: 10ms, 15ms, 20ms
        mock_perf.side_effect = [0.0, 0.010, 0.0, 0.015, 0.0, 0.020]

        result = jitter_analysis('example.com', samples=3, interval=0.0)

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['samples'], 3)
        # jitters: |15-10|=5, |20-15|=5 -> avg=5
        self.assertAlmostEqual(result['avg_jitter_ms'], 5.0, places=1)

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_insufficient_samples_error(self, mock_sock_cls, mock_perf, mock_sleep):
        """fewer than 2 samples should return error."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout
        mock_sock_cls.return_value = mock_sock

        mock_perf.side_effect = [0.0] * 40

        result = jitter_analysis('example.com', samples=5)
        self.assertEqual(result['status'], 'error')
        self.assertIn('Insufficient samples', result['error'])

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_stability_label_stable(self, mock_sock_cls, mock_perf, mock_sleep):
        """avg jitter < 5 ms should be 'stable'."""
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock

        # latencies: 10ms, 12ms, 11ms -> jitters 2,1 -> avg 1.5
        mock_perf.side_effect = [0.0, 0.010, 0.0, 0.012, 0.0, 0.011]

        result = jitter_analysis('example.com', samples=3, interval=0.0)
        self.assertEqual(result['stability'], 'stable')

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_stability_label_unstable(self, mock_sock_cls, mock_perf, mock_sleep):
        """avg jitter >= 5 ms should be 'unstable'."""
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock

        # latencies: 10ms, 30ms -> jitter 20ms
        mock_perf.side_effect = [0.0, 0.010, 0.0, 0.030]

        result = jitter_analysis('example.com', samples=2, interval=0.0)
        self.assertEqual(result['stability'], 'unstable')


class TestTcpHandshakeTime(unittest.TestCase):
    """tests for tcp_handshake_time function."""

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_successful_handshake(self, mock_sock_cls, mock_perf, mock_sleep):
        """connect_ex returns 0 -> handshake recorded."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        # 2 samples at 25ms each
        mock_perf.side_effect = [0.0, 0.025, 0.0, 0.025]

        result = tcp_handshake_time('example.com', port=443, samples=2)

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['samples'], 2)
        self.assertAlmostEqual(result['avg_ms'], 25.0, places=1)
        self.assertEqual(result['connection_quality'], 'excellent')

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_all_connections_fail(self, mock_sock_cls, mock_perf, mock_sleep):
        """connect_ex returns non-zero -> error."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111
        mock_sock_cls.return_value = mock_sock

        mock_perf.side_effect = [0.0, 0.010] * 5

        result = tcp_handshake_time('example.com', port=80, samples=3)
        self.assertEqual(result['status'], 'error')
        self.assertIn('Could not establish connection', result['error'])

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_connection_quality_poor(self, mock_sock_cls, mock_perf, mock_sleep):
        """avg >= 150ms -> 'poor' quality."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        # 200ms per sample
        mock_perf.side_effect = [0.0, 0.200, 0.0, 0.200]

        result = tcp_handshake_time('example.com', samples=2)
        self.assertEqual(result['connection_quality'], 'poor')

    @patch('src.network.performance.time.sleep')
    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_connection_quality_good(self, mock_sock_cls, mock_perf, mock_sleep):
        """50 <= avg < 150 -> 'good' quality."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        # 100ms per sample
        mock_perf.side_effect = [0.0, 0.100, 0.0, 0.100]

        result = tcp_handshake_time('example.com', samples=2)
        self.assertEqual(result['connection_quality'], 'good')


class TestBandwidthTest(unittest.TestCase):
    """tests for bandwidth_test function."""

    @patch('src.network.performance.time.perf_counter')
    @patch('src.network.performance.socket.socket')
    def test_successful_bandwidth(self, mock_sock_cls, mock_perf):
        """verify upload_mbps calculation."""
        mock_sock = MagicMock()
        mock_sock.send.return_value = 8192
        mock_sock_cls.return_value = mock_sock

        # connect succeeds, then upload takes 1 second
        mock_perf.side_effect = [0.0, 1.0]

        result = bandwidth_test('example.com', port=80, test_size=8192)

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['bytes_sent'], 8192)
        self.assertGreater(result['upload_mbps'], 0)


class TestMtuDiscovery(unittest.TestCase):
    """tests for mtu_discovery function."""

    @patch('src.network.performance.subprocess.run')
    @patch('src.network.performance.platform.system', return_value='Linux')
    def test_binary_search_finds_mtu(self, mock_platform, mock_run):
        """verify binary search converges on optimal mtu."""
        # ping succeeds for sizes <= 1000, fails above
        def side_effect(cmd, **kwargs):
            size_idx = cmd.index('-s') + 1
            size = int(cmd[size_idx])
            m = MagicMock()
            m.returncode = 0 if size <= 1000 else 1
            return m

        mock_run.side_effect = side_effect

        result = mtu_discovery('example.com', start_size=1500, min_size=68)

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['payload_size'], 1000)
        self.assertEqual(result['optimal_mtu'], 1028)  # 1000 + 28
        self.assertEqual(result['header_overhead'], 28)


import socket


if __name__ == '__main__':
    unittest.main()
