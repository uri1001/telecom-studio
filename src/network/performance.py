#!/usr/bin/env python3
"""
performance.py - Network Performance Measurement
Simple network performance testing utilities following KISS principle.
"""

import socket
import time
import statistics
import struct
import subprocess
import platform
from typing import Dict, List, Optional, Any, Tuple


def measure_latency(host: str, samples: int = 10, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Measure network latency to a host using multiple samples.

    Args:
        host: Target hostname or IP
        samples: Number of measurements to take
        timeout: Timeout per measurement

    Returns:
        Dict with latency statistics
    """
    try:
        latencies = []

        for _ in range(samples):
            try:
                start = time.perf_counter()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                # Try port 80 for measurement
                result = sock.connect_ex((host, 80))
                end = time.perf_counter()
                sock.close()

                if result == 0:
                    latency = (end - start) * 1000  # Convert to ms
                    latencies.append(latency)
                time.sleep(0.1)  # Small delay between samples
            except:
                continue

        if not latencies:
            # Fallback to ICMP ping if TCP fails
            return _measure_latency_icmp(host, samples)

        return {
            'status': 'success',
            'host': host,
            'samples': len(latencies),
            'min_ms': round(min(latencies), 2),
            'max_ms': round(max(latencies), 2),
            'avg_ms': round(statistics.mean(latencies), 2),
            'median_ms': round(statistics.median(latencies), 2),
            'stdev_ms': round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0,
            'packet_loss': round((1 - len(latencies) / samples) * 100, 2)
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e)
        }


def _measure_latency_icmp(host: str, samples: int) -> Dict[str, Any]:
    """Helper function to measure latency using ICMP ping."""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        cmd = ['ping', param, str(samples), host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=samples * 2)

        if result.returncode != 0:
            return {
                'status': 'error',
                'host': host,
                'error': 'Host unreachable'
            }

        # Parse ping output for latency values
        latencies = []
        for line in result.stdout.split('\n'):
            if 'time=' in line:
                time_str = line.split('time=')[1].split()[0]
                latencies.append(float(time_str.replace('ms', '')))

        if latencies:
            return {
                'status': 'success',
                'host': host,
                'samples': len(latencies),
                'min_ms': round(min(latencies), 2),
                'max_ms': round(max(latencies), 2),
                'avg_ms': round(statistics.mean(latencies), 2),
                'median_ms': round(statistics.median(latencies), 2),
                'stdev_ms': round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0,
                'packet_loss': round((1 - len(latencies) / samples) * 100, 2)
            }
        else:
            return {
                'status': 'error',
                'host': host,
                'error': 'No valid measurements'
            }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e)
        }


def bandwidth_test(host: str, port: int = 80, test_size: int = 1048576, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Measure bandwidth by sending/receiving data.

    Args:
        host: Target hostname or IP
        port: Port to use for test
        test_size: Size of test data in bytes (default 1MB)
        timeout: Test timeout

    Returns:
        Dict with bandwidth measurements
    """
    try:
        # Generate test data
        test_data = b'X' * test_size

        # Measure upload bandwidth
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        start = time.perf_counter()
        bytes_sent = 0

        # Send in chunks
        chunk_size = 8192
        for i in range(0, len(test_data), chunk_size):
            chunk = test_data[i:i + chunk_size]
            sent = sock.send(chunk)
            bytes_sent += sent

        upload_time = time.perf_counter() - start
        upload_mbps = (bytes_sent * 8) / (upload_time * 1000000)

        sock.close()

        return {
            'status': 'success',
            'host': host,
            'port': port,
            'bytes_sent': bytes_sent,
            'upload_time_s': round(upload_time, 3),
            'upload_mbps': round(upload_mbps, 2),
            'test_size': test_size
        }
    except socket.timeout:
        return {
            'status': 'error',
            'host': host,
            'error': 'Connection timeout'
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e)
        }


def packet_loss_test(host: str, count: int = 100, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Test packet loss rate to a host.

    Args:
        host: Target hostname or IP
        count: Number of packets to send
        timeout: Timeout per packet

    Returns:
        Dict with packet loss statistics
    """
    try:
        # Use ICMP ping for packet loss testing
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'

        cmd = ['ping', param, str(count), timeout_param, str(int(timeout * 1000)), host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout + 5)

        output = result.stdout
        packets_sent = count
        packets_received = 0
        packet_loss = 100.0

        # Parse packet statistics
        for line in output.split('\n'):
            if 'packet' in line.lower() and 'loss' in line.lower():
                # Extract packet loss percentage
                parts = line.split()
                for i, part in enumerate(parts):
                    if '%' in part:
                        packet_loss = float(part.replace('%', '').replace(',', ''))
                    if 'received' in line.lower():
                        for j, p in enumerate(parts):
                            if p.isdigit() and j > 0:
                                if 'transmitted' in parts[j - 1].lower():
                                    packets_sent = int(p)
                                elif 'received' in parts[j - 1].lower():
                                    packets_received = int(p)

        return {
            'status': 'success',
            'host': host,
            'packets_sent': packets_sent,
            'packets_received': packets_sent - int(packets_sent * packet_loss / 100),
            'packet_loss_percent': packet_loss,
            'reliability': round(100 - packet_loss, 2)
        }
    except subprocess.TimeoutExpired:
        return {
            'status': 'error',
            'host': host,
            'error': 'Test timeout',
            'packet_loss_percent': 100.0
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e)
        }


def jitter_analysis(host: str, samples: int = 20, interval: float = 0.1) -> Dict[str, Any]:
    """
    Analyze network jitter (latency variation).

    Args:
        host: Target hostname or IP
        samples: Number of measurements
        interval: Interval between measurements

    Returns:
        Dict with jitter analysis
    """
    try:
        latencies = []

        # Collect latency samples
        for _ in range(samples):
            start = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)

            try:
                sock.connect((host, 80))
                end = time.perf_counter()
                latency = (end - start) * 1000
                latencies.append(latency)
                sock.close()
            except:
                pass

            time.sleep(interval)

        if len(latencies) < 2:
            return {
                'status': 'error',
                'host': host,
                'error': 'Insufficient samples for jitter analysis'
            }

        # Calculate jitter (difference between consecutive samples)
        jitters = []
        for i in range(1, len(latencies)):
            jitter = abs(latencies[i] - latencies[i - 1])
            jitters.append(jitter)

        return {
            'status': 'success',
            'host': host,
            'samples': len(latencies),
            'avg_latency_ms': round(statistics.mean(latencies), 2),
            'min_jitter_ms': round(min(jitters), 2),
            'max_jitter_ms': round(max(jitters), 2),
            'avg_jitter_ms': round(statistics.mean(jitters), 2),
            'jitter_stdev_ms': round(statistics.stdev(jitters), 2) if len(jitters) > 1 else 0,
            'stability': 'stable' if statistics.mean(jitters) < 5 else 'unstable'
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e)
        }


def mtu_discovery(host: str, start_size: int = 1500, min_size: int = 68) -> Dict[str, Any]:
    """
    Discover Maximum Transmission Unit (MTU) to a host.

    Args:
        host: Target hostname or IP
        start_size: Starting MTU size to test
        min_size: Minimum MTU size

    Returns:
        Dict with MTU information
    """
    try:
        current_size = start_size
        last_working = min_size
        attempts = 0
        max_attempts = 20

        # Binary search for optimal MTU
        high = start_size
        low = min_size

        while low <= high and attempts < max_attempts:
            attempts += 1
            mid = (low + high) // 2

            # Test this MTU size with don't fragment flag
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-l', str(mid), '-f', host]
            else:
                cmd = ['ping', '-c', '1', '-M', 'do', '-s', str(mid), host]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    last_working = mid
                    low = mid + 1
                else:
                    high = mid - 1
            except:
                high = mid - 1

        # Account for IP and ICMP headers (28 bytes)
        optimal_mtu = last_working + 28

        return {
            'status': 'success',
            'host': host,
            'optimal_mtu': optimal_mtu,
            'payload_size': last_working,
            'header_overhead': 28,
            'attempts': attempts,
            'fragmentation_needed': optimal_mtu > 1500
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'error': str(e),
            'optimal_mtu': None
        }


def tcp_handshake_time(host: str, port: int = 80, samples: int = 5) -> Dict[str, Any]:
    """
    Measure TCP three-way handshake time.

    Args:
        host: Target hostname or IP
        port: Port to connect to
        samples: Number of measurements

    Returns:
        Dict with handshake timing
    """
    try:
        handshake_times = []

        for _ in range(samples):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)

            start = time.perf_counter()
            try:
                result = sock.connect_ex((host, port))
                end = time.perf_counter()

                if result == 0:
                    handshake_time = (end - start) * 1000
                    handshake_times.append(handshake_time)

                sock.close()
            except:
                sock.close()

            time.sleep(0.1)

        if not handshake_times:
            return {
                'status': 'error',
                'host': host,
                'port': port,
                'error': 'Could not establish connection'
            }

        return {
            'status': 'success',
            'host': host,
            'port': port,
            'samples': len(handshake_times),
            'min_ms': round(min(handshake_times), 2),
            'max_ms': round(max(handshake_times), 2),
            'avg_ms': round(statistics.mean(handshake_times), 2),
            'median_ms': round(statistics.median(handshake_times), 2),
            'connection_quality': 'excellent' if statistics.mean(handshake_times) < 50 else 'good' if statistics.mean(handshake_times) < 150 else 'poor'
        }
    except Exception as e:
        return {
            'status': 'error',
            'host': host,
            'port': port,
            'error': str(e)
        }


if __name__ == '__main__':
    # Simple test
    print("Testing network performance...")

    # Test latency
    result = measure_latency('google.com', samples=5)
    print(f"Latency to google.com: {result.get('avg_ms')}ms")

    # Test packet loss
    result = packet_loss_test('8.8.8.8', count=10)
    print(f"Packet loss to 8.8.8.8: {result.get('packet_loss_percent')}%")

    # Test TCP handshake
    result = tcp_handshake_time('google.com', 443, samples=3)
    print(f"TCP handshake time: {result.get('avg_ms')}ms")