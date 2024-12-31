"""Shared network utility helpers."""

import re
import socket
import subprocess
import platform
from typing import Optional


def get_default_gateway() -> Optional[str]:
    """detect the default gateway ip."""
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(
                ['ipconfig'], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        else:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def get_primary_ip() -> Optional[str]:
    """get primary local ip via udp connect trick."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()
