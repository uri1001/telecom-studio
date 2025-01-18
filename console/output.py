"""output formatting for telecom-studio console"""

import json
import sys


# ansi colors — auto-disabled when stdout is not a tty
_IS_TTY = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

RESET = '\033[0m' if _IS_TTY else ''
BOLD = '\033[1m' if _IS_TTY else ''
DIM = '\033[2m' if _IS_TTY else ''
GREEN = '\033[32m' if _IS_TTY else ''
YELLOW = '\033[33m' if _IS_TTY else ''
RED = '\033[31m' if _IS_TTY else ''
CYAN = '\033[36m' if _IS_TTY else ''
WHITE = '\033[37m' if _IS_TTY else ''

ICON_OK = f'{GREEN}[+]{RESET}'
ICON_WARN = f'{YELLOW}[!]{RESET}'
ICON_ERR = f'{RED}[-]{RESET}'
ICON_INFO = f'{CYAN}[*]{RESET}'


def print_header(title):
    line = '=' * (len(title) + 6)
    print(f'\n{BOLD}{CYAN}{line}{RESET}')
    print(f'{BOLD}{CYAN}   {title}   {RESET}')
    print(f'{BOLD}{CYAN}{line}{RESET}\n')


def print_success(msg):
    print(f'  {ICON_OK} {msg}')


def print_warning(msg):
    print(f'  {ICON_WARN} {msg}')


def print_error(msg):
    print(f'  {ICON_ERR} {msg}')


def print_info(msg):
    print(f'  {ICON_INFO} {msg}')


def print_kv(key, value, indent=0):
    pad = '  ' * (indent + 1)
    label = humanize_key(key)
    formatted = format_value(value, indent)
    print(f'{pad}{DIM}{label}:{RESET} {formatted}')


def humanize_key(key):
    """avg_rtt -> Avg RTT, dns_servers -> DNS Servers"""
    words = str(key).replace('_', ' ').replace('-', ' ').split()
    result = []
    # acronyms that should stay uppercase
    acronyms = {'ip', 'dns', 'tcp', 'udp', 'http', 'https', 'tls', 'ssl',
                'rtt', 'mtu', 'mos', 'ttl', 'arp', 'mac', 'os', 'cidr',
                'vlsm', 'icmp', 'url', 'ms', 'avg', 'min', 'max', 'ipv4',
                'ipv6', 'ptr', 'mx', 'ns', 'txt', 'soa', 'qos', 'voip'}
    for w in words:
        if w.lower() in acronyms:
            result.append(w.upper())
        else:
            result.append(w.capitalize())
    return ' '.join(result)


def format_value(value, indent=0):
    if isinstance(value, bool):
        return f'{GREEN}yes{RESET}' if value else f'{RED}no{RESET}'
    if isinstance(value, float):
        return f'{WHITE}{value:.4g}{RESET}'
    if isinstance(value, dict):
        return ''  # handled by recursive rendering
    if isinstance(value, list):
        return ''  # handled by recursive rendering
    return f'{WHITE}{value}{RESET}'


def render_dict(data, indent=0):
    """recursively render a dict with aligned key-value pairs"""
    # skip 'status' key at top level — we show it via header icon
    skip_keys = {'status'} if indent == 0 else set()
    for key, value in data.items():
        if key in skip_keys:
            continue
        if isinstance(value, dict):
            pad = '  ' * (indent + 1)
            print(f'{pad}{BOLD}{humanize_key(key)}:{RESET}')
            render_dict(value, indent + 1)
        elif isinstance(value, list):
            pad = '  ' * (indent + 1)
            if not value:
                print(f'{pad}{DIM}{humanize_key(key)}:{RESET} {DIM}(none){RESET}')
            elif isinstance(value[0], dict):
                print(f'{pad}{BOLD}{humanize_key(key)}:{RESET}')
                for i, item in enumerate(value):
                    render_dict(item, indent + 1)
                    if i < len(value) - 1:
                        print()
            else:
                items = ', '.join(str(v) for v in value)
                print(f'{pad}{DIM}{humanize_key(key)}:{RESET} {WHITE}{items}{RESET}')
        else:
            print_kv(key, value, indent)


def render_result(result, json_mode=False):
    """main entry point: render a function result dict"""
    if json_mode:
        print(json.dumps(result, indent=2, default=str))
        return

    status = result.get('status', 'unknown')
    if status == 'success':
        print_success('OK')
    elif status == 'error':
        msg = result.get('error', result.get('message', 'unknown error'))
        print_error(str(msg))
    else:
        print_info(status)

    render_dict(result)
    print()
