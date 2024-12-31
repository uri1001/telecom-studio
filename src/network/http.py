#!/usr/bin/env python3
"""
http.py - HTTP/HTTPS Testing Utilities
Simple HTTP testing functions following KISS principle.
"""

import json
import time
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime


def http_get(url: str, timeout: float = 5.0) -> dict:
    """perform HTTP GET request with timing information."""
    try:
        start = time.perf_counter()

        req = urllib.request.Request(url, headers={'User-Agent': 'TelecomStudio/1.0'})
        response = urllib.request.urlopen(req, timeout=timeout)

        elapsed = (time.perf_counter() - start) * 1000
        body = response.read()

        return {
            'status': 'success',
            'url': url,
            'status_code': response.status,
            'response_time_ms': round(elapsed, 2),
            'content_length': len(body),
            'headers': dict(response.headers),
            'final_url': response.url,
            'encoding': response.headers.get_content_charset()
        }
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000
        return {
            'status': 'error',
            'url': url,
            'status_code': e.code,
            'error': str(e.reason),
            'response_time_ms': round(elapsed, 2)
        }
    except urllib.error.URLError as e:
        return {
            'status': 'error',
            'url': url,
            'error': f'Connection failed: {e.reason}'
        }
    except socket.timeout:
        return {
            'status': 'error',
            'url': url,
            'error': 'Request timeout',
            'response_time_ms': timeout * 1000
        }
    except Exception as e:
        return {
            'status': 'error',
            'url': url,
            'error': str(e)
        }


def https_verify(url: str, timeout: float = 5.0) -> dict:
    """verify HTTPS certificate and connection."""
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port = parsed.port if parsed.port else 443

        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])

        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_remaining = (not_after - datetime.now()).days

        is_valid = days_remaining > 0
        is_expiring_soon = days_remaining < 30

        return {
            'status': 'success',
            'url': url,
            'hostname': hostname,
            'is_valid': is_valid,
            'days_remaining': days_remaining,
            'is_expiring_soon': is_expiring_soon,
            'common_name': subject.get('commonName'),
            'issuer': issuer.get('organizationName'),
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'protocol': version,
            'cipher': cipher[0] if cipher else None,
            'san': cert.get('subjectAltName', [])
        }
    except ssl.SSLError as e:
        return {
            'status': 'error',
            'url': url,
            'error': f'SSL Error: {str(e)}',
            'is_valid': False
        }
    except socket.timeout:
        return {
            'status': 'error',
            'url': url,
            'error': 'Connection timeout',
            'is_valid': False
        }
    except Exception as e:
        return {
            'status': 'error',
            'url': url,
            'error': str(e),
            'is_valid': False
        }


def check_headers_security(url: str, timeout: float = 5.0) -> dict:
    """check HTTP security headers."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'TelecomStudio/1.0'})
        response = urllib.request.urlopen(req, timeout=timeout)
        headers = response.headers

        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'Content Type Options',
            'X-Frame-Options': 'Frame Options',
            'X-XSS-Protection': 'XSS Protection',
            'Content-Security-Policy': 'CSP',
            'Referrer-Policy': 'Referrer Policy',
            'Permissions-Policy': 'Permissions Policy'
        }

        present = {}
        missing = []

        for header, name in security_headers.items():
            value = headers.get(header)
            if value:
                present[name] = value
            else:
                missing.append(name)

        score = (len(present) / len(security_headers)) * 100

        server_info = headers.get('Server', 'Not disclosed')
        powered_by = headers.get('X-Powered-By', 'Not disclosed')

        return {
            'status': 'success',
            'url': url,
            'security_score': round(score, 2),
            'present_headers': present,
            'missing_headers': missing,
            'server_info': server_info,
            'powered_by': powered_by,
            'uses_https': url.startswith('https'),
            'recommendation': 'Good' if score >= 70 else 'Fair' if score >= 40 else 'Poor'
        }
    except Exception as e:
        return {
            'status': 'error',
            'url': url,
            'error': str(e),
            'security_score': 0
        }


if __name__ == '__main__':
    print("Testing HTTP utilities...")

    result = http_get('http://example.com')
    print(f"HTTP GET example.com: {result.get('status_code')}, Time: {result.get('response_time_ms')}ms")

    result = check_headers_security('https://example.com')
    print(f"Security score for example.com: {result.get('security_score')}%")
