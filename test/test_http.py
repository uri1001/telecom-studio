#!/usr/bin/env python3
"""tests for src/network/http.py"""

import os
import sys
import socket
import ssl
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from http.client import HTTPMessage
from email.message import EmailMessage
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.network.http import http_get, https_verify, check_headers_security


class TestHttpGet(unittest.TestCase):
    """tests for http_get function."""

    @patch('src.network.http.time.perf_counter')
    @patch('src.network.http.urllib.request.urlopen')
    def test_successful_get(self, mock_urlopen, mock_perf):
        """200 response returns status, timing, content_length."""
        mock_perf.side_effect = [0.0, 0.050, 0.050]  # start, after urlopen, after read

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'Hello World'
        mock_resp.url = 'http://example.com'
        mock_resp.headers = EmailMessage()
        mock_resp.headers['Content-Type'] = 'text/html'
        mock_resp.headers.get_content_charset = MagicMock(return_value='utf-8')
        mock_urlopen.return_value = mock_resp

        result = http_get('http://example.com')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['status_code'], 200)
        self.assertEqual(result['content_length'], 11)
        self.assertGreater(result['response_time_ms'], 0)

    @patch('src.network.http.time.perf_counter')
    @patch('src.network.http.urllib.request.urlopen')
    def test_http_error(self, mock_urlopen, mock_perf):
        """HTTPError returns status_code from error."""
        mock_perf.side_effect = [0.0, 0.050]

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url='http://example.com',
            code=404,
            msg='Not Found',
            hdrs={},
            fp=None,
        )

        result = http_get('http://example.com')

        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['status_code'], 404)

    @patch('src.network.http.time.perf_counter')
    @patch('src.network.http.urllib.request.urlopen')
    def test_url_error(self, mock_urlopen, mock_perf):
        """URLError returns connection failed message."""
        mock_perf.side_effect = [0.0]

        mock_urlopen.side_effect = urllib.error.URLError('Connection refused')

        result = http_get('http://example.com')

        self.assertEqual(result['status'], 'error')
        self.assertIn('Connection failed', result['error'])

    @patch('src.network.http.time.perf_counter')
    @patch('src.network.http.urllib.request.urlopen')
    def test_socket_timeout(self, mock_urlopen, mock_perf):
        """socket.timeout returns timeout error with calculated ms."""
        mock_perf.side_effect = [0.0]

        mock_urlopen.side_effect = socket.timeout

        result = http_get('http://example.com', timeout=5.0)

        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['error'], 'Request timeout')
        self.assertEqual(result['response_time_ms'], 5000.0)


class TestHttpsVerify(unittest.TestCase):
    """tests for https_verify function."""

    @patch('src.network.http.ssl.create_default_context')
    @patch('src.network.http.socket.create_connection')
    def test_valid_certificate(self, mock_create_conn, mock_ssl_ctx):
        """valid cert returns is_valid=True and days_remaining."""
        mock_raw_sock = MagicMock()
        mock_create_conn.return_value.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_create_conn.return_value.__exit__ = MagicMock(return_value=False)

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('organizationName', 'Let\'s Encrypt'),),),
            'notBefore': 'Jan  1 00:00:00 2025 GMT',
            'notAfter': 'Dec 31 23:59:59 2027 GMT',
            'subjectAltName': (('DNS', 'example.com'),),
        }
        mock_ssock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        mock_ssock.version.return_value = 'TLSv1.3'

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ssl_ctx.return_value = mock_ctx

        result = https_verify('https://example.com')

        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['is_valid'])
        self.assertGreater(result['days_remaining'], 0)
        self.assertFalse(result['is_expiring_soon'])
        self.assertEqual(result['common_name'], 'example.com')
        self.assertEqual(result['protocol'], 'TLSv1.3')
        self.assertEqual(result['cipher'], 'TLS_AES_256_GCM_SHA384')

    @patch('src.network.http.ssl.create_default_context')
    @patch('src.network.http.socket.create_connection')
    def test_expiring_soon_certificate(self, mock_create_conn, mock_ssl_ctx):
        """cert expiring within 30 days sets is_expiring_soon=True."""
        import datetime

        soon = datetime.datetime.now() + datetime.timedelta(days=15)
        not_after = soon.strftime('%b %d %H:%M:%S %Y GMT')
        past = datetime.datetime.now() - datetime.timedelta(days=300)
        not_before = past.strftime('%b %d %H:%M:%S %Y GMT')

        mock_raw_sock = MagicMock()
        mock_create_conn.return_value.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_create_conn.return_value.__exit__ = MagicMock(return_value=False)

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('organizationName', 'CA'),),),
            'notBefore': not_before,
            'notAfter': not_after,
            'subjectAltName': (),
        }
        mock_ssock.cipher.return_value = ('AES', 'TLSv1.2', 128)
        mock_ssock.version.return_value = 'TLSv1.2'

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ssl_ctx.return_value = mock_ctx

        result = https_verify('https://example.com')

        self.assertTrue(result['is_valid'])
        self.assertTrue(result['is_expiring_soon'])
        self.assertLess(result['days_remaining'], 30)

    @patch('src.network.http.ssl.create_default_context')
    @patch('src.network.http.socket.create_connection')
    def test_ssl_error(self, mock_create_conn, mock_ssl_ctx):
        """SSLError returns is_valid=False."""
        mock_raw_sock = MagicMock()
        mock_create_conn.return_value.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_create_conn.return_value.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(
            side_effect=ssl.SSLError('certificate verify failed')
        )
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ssl_ctx.return_value = mock_ctx

        result = https_verify('https://example.com')

        self.assertEqual(result['status'], 'error')
        self.assertFalse(result['is_valid'])
        self.assertIn('SSL Error', result['error'])

    @patch('src.network.http.socket.create_connection')
    def test_connection_timeout(self, mock_create_conn):
        """socket.timeout returns error."""
        mock_create_conn.side_effect = socket.timeout

        result = https_verify('https://example.com')

        self.assertEqual(result['status'], 'error')
        self.assertFalse(result['is_valid'])


class TestCheckHeadersSecurity(unittest.TestCase):
    """tests for check_headers_security function."""

    @patch('src.network.http.urllib.request.urlopen')
    def test_all_headers_present(self, mock_urlopen):
        """all 7 security headers present -> score 100, recommendation 'Good'."""
        mock_resp = MagicMock()
        headers = EmailMessage()
        headers['Strict-Transport-Security'] = 'max-age=31536000'
        headers['X-Content-Type-Options'] = 'nosniff'
        headers['X-Frame-Options'] = 'DENY'
        headers['X-XSS-Protection'] = '1; mode=block'
        headers['Content-Security-Policy'] = "default-src 'self'"
        headers['Referrer-Policy'] = 'no-referrer'
        headers['Permissions-Policy'] = 'camera=()'
        headers['Server'] = 'nginx'
        mock_resp.headers = headers
        mock_urlopen.return_value = mock_resp

        result = check_headers_security('https://example.com')

        self.assertEqual(result['status'], 'success')
        self.assertAlmostEqual(result['security_score'], 100.0, places=1)
        self.assertEqual(len(result['missing_headers']), 0)
        self.assertEqual(result['recommendation'], 'Good')

    @patch('src.network.http.urllib.request.urlopen')
    def test_no_headers_present(self, mock_urlopen):
        """no security headers -> score 0, recommendation 'Poor'."""
        mock_resp = MagicMock()
        headers = EmailMessage()
        mock_resp.headers = headers
        mock_urlopen.return_value = mock_resp

        result = check_headers_security('https://example.com')

        self.assertEqual(result['status'], 'success')
        self.assertAlmostEqual(result['security_score'], 0.0, places=1)
        self.assertEqual(len(result['missing_headers']), 7)
        self.assertEqual(result['recommendation'], 'Poor')

    @patch('src.network.http.urllib.request.urlopen')
    def test_partial_headers_fair(self, mock_urlopen):
        """3 out of 7 headers -> ~42.86%, recommendation 'Fair'."""
        mock_resp = MagicMock()
        headers = EmailMessage()
        headers['Strict-Transport-Security'] = 'max-age=31536000'
        headers['X-Content-Type-Options'] = 'nosniff'
        headers['X-Frame-Options'] = 'DENY'
        mock_resp.headers = headers
        mock_urlopen.return_value = mock_resp

        result = check_headers_security('https://example.com')

        self.assertAlmostEqual(result['security_score'], (3 / 7) * 100, places=1)
        self.assertEqual(result['recommendation'], 'Fair')
        self.assertEqual(len(result['missing_headers']), 4)

    @patch('src.network.http.urllib.request.urlopen')
    def test_five_headers_good(self, mock_urlopen):
        """5 out of 7 headers -> ~71.43%, recommendation 'Good'."""
        mock_resp = MagicMock()
        headers = EmailMessage()
        headers['Strict-Transport-Security'] = 'max-age=31536000'
        headers['X-Content-Type-Options'] = 'nosniff'
        headers['X-Frame-Options'] = 'DENY'
        headers['X-XSS-Protection'] = '1; mode=block'
        headers['Content-Security-Policy'] = "default-src 'self'"
        mock_resp.headers = headers
        mock_urlopen.return_value = mock_resp

        result = check_headers_security('https://example.com')

        self.assertGreaterEqual(result['security_score'], 70)
        self.assertEqual(result['recommendation'], 'Good')

    @patch('src.network.http.urllib.request.urlopen')
    def test_uses_https_flag(self, mock_urlopen):
        """uses_https reflects whether url starts with https."""
        mock_resp = MagicMock()
        mock_resp.headers = EmailMessage()
        mock_urlopen.return_value = mock_resp

        result = check_headers_security('https://example.com')
        self.assertTrue(result['uses_https'])

        result = check_headers_security('http://example.com')
        self.assertFalse(result['uses_https'])

    @patch('src.network.http.urllib.request.urlopen')
    def test_server_info_extraction(self, mock_urlopen):
        """server header and x-powered-by are extracted."""
        mock_resp = MagicMock()
        headers = EmailMessage()
        headers['Server'] = 'Apache/2.4.41'
        headers['X-Powered-By'] = 'PHP/7.4'
        mock_resp.headers = headers
        mock_urlopen.return_value = mock_resp

        result = check_headers_security('https://example.com')

        self.assertEqual(result['server_info'], 'Apache/2.4.41')
        self.assertEqual(result['powered_by'], 'PHP/7.4')

    @patch('src.network.http.urllib.request.urlopen')
    def test_exception_returns_zero_score(self, mock_urlopen):
        """exception returns error with security_score 0."""
        mock_urlopen.side_effect = Exception('network error')

        result = check_headers_security('https://example.com')

        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['security_score'], 0)


if __name__ == '__main__':
    unittest.main()
