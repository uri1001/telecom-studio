"""command registry for telecom-studio console"""

import importlib


# command registry: module -> action -> {func, args, opts, help}
# func: "package.module:function" — lazy imported at call time
# args: positional arguments [(name, type, help)]
# opts: optional arguments [(flag, type, default, help)]
COMMANDS = {
    'net': {
        '_help': 'network basics and home diagnostics',
        'ping': {
            'func': 'src.network.basic:ping',
            'args': [('host', str, 'target host')],
            'opts': [('--count', int, 4, 'number of pings')],
            'help': 'ICMP ping',
        },
        'trace': {
            'func': 'src.network.basic:traceroute',
            'args': [('host', str, 'target host')],
            'opts': [],
            'help': 'traceroute to host',
        },
        'dns': {
            'func': 'src.network.basic:dns_lookup',
            'args': [('domain', str, 'domain to resolve')],
            'opts': [('--type', str, 'A', 'record type (A, AAAA, MX, NS, TXT)')],
            'param_map': {'type': 'record_type'},
            'help': 'DNS lookup',
        },
        'ip': {
            'func': '_composite:cmd_net_ip',
            'args': [],
            'opts': [],
            'help': 'show public and local IPs',
        },
        'summary': {
            'func': 'src.network.home:network_summary',
            'args': [],
            'opts': [],
            'help': 'full network overview',
        },
        'connectivity': {
            'func': 'src.network.home:check_connectivity',
            'args': [],
            'opts': [],
            'help': 'layer-by-layer connectivity diagnosis',
        },
        'devices': {
            'func': 'src.network.home:discover_lan_devices',
            'args': [],
            'opts': [],
            'help': 'discover LAN devices',
        },
        'dns-bench': {
            'func': 'src.network.home:dns_benchmark',
            'args': [],
            'opts': [],
            'help': 'DNS server speed comparison',
        },
    },
    'scan': {
        '_help': 'port scanning and service detection',
        'ports': {
            'func': 'src.network.scanner:scan_common_ports',
            'args': [('host', str, 'target host')],
            'opts': [],
            'help': 'scan common ports',
        },
        'port': {
            'func': 'src.network.scanner:check_port',
            'args': [('host', str, 'target host'), ('port', int, 'port number')],
            'opts': [],
            'help': 'check single port',
        },
        'fingerprint': {
            'func': 'src.network.scanner:service_fingerprint',
            'args': [('host', str, 'target host'), ('port', int, 'port number')],
            'opts': [],
            'help': 'identify service on port',
        },
        'os': {
            'func': 'src.network.scanner:detect_os',
            'args': [('host', str, 'target host')],
            'opts': [],
            'help': 'detect remote OS',
        },
    },
    'perf': {
        '_help': 'network performance measurement',
        'latency': {
            'func': 'src.network.performance:measure_latency',
            'args': [('host', str, 'target host')],
            'opts': [('--samples', int, 10, 'number of samples')],
            'help': 'latency statistics',
        },
        'jitter': {
            'func': 'src.network.performance:jitter_analysis',
            'args': [('host', str, 'target host')],
            'opts': [],
            'help': 'jitter analysis',
        },
        'loss': {
            'func': 'src.network.performance:packet_loss_test',
            'args': [('host', str, 'target host')],
            'opts': [('--count', int, 100, 'number of packets')],
            'help': 'packet loss test',
        },
        'mtu': {
            'func': 'src.network.performance:mtu_discovery',
            'args': [('host', str, 'target host')],
            'opts': [],
            'help': 'MTU path discovery',
        },
        'handshake': {
            'func': 'src.network.performance:tcp_handshake_time',
            'args': [('host', str, 'target host')],
            'opts': [('--port', int, 80, 'target port')],
            'help': 'TCP handshake timing',
        },
    },
    'http': {
        '_help': 'HTTP and TLS tools',
        'get': {
            'func': 'src.network.http:http_get',
            'args': [('url', str, 'target URL')],
            'opts': [],
            'help': 'HTTP GET with timing',
        },
        'cert': {
            'func': 'src.network.http:https_verify',
            'args': [('url', str, 'target URL or hostname')],
            'opts': [],
            'help': 'TLS certificate check',
        },
        'headers': {
            'func': 'src.network.http:check_headers_security',
            'args': [('url', str, 'target URL')],
            'opts': [],
            'help': 'security header audit',
        },
    },
    'subnet': {
        '_help': 'IP/subnet calculator (offline)',
        'info': {
            'func': 'src.network.subnet:subnet_info',
            'args': [('cidr', str, 'CIDR notation (e.g. 192.168.1.0/24)')],
            'opts': [],
            'help': 'subnet details',
        },
        'split': {
            'func': 'src.network.subnet:split_subnet',
            'args': [('cidr', str, 'CIDR to split'), ('prefix', int, 'new prefix length')],
            'opts': [],
            'help': 'split subnet into smaller subnets',
        },
        'contains': {
            'func': 'src.network.subnet:contains',
            'args': [('cidr', str, 'CIDR notation'), ('ip', str, 'IP address to check')],
            'opts': [],
            'help': 'check if IP is in subnet',
        },
        'classify': {
            'func': 'src.network.subnet:classify_ip',
            'args': [('ip', str, 'IP address')],
            'opts': [],
            'help': 'classify IP address',
        },
        'vlsm': {
            'func': 'src.network.subnet:vlsm_allocate',
            'args': [('cidr', str, 'parent CIDR')],
            'opts': [('--sizes', int, None, 'host counts per subnet (space-separated)')],
            'help': 'VLSM subnet allocation',
        },
    },
    'security': {
        '_help': 'password and network security',
        'password': {
            'func': '_composite:cmd_security_password',
            'args': [('pw', str, 'password to analyze')],
            'opts': [],
            'help': 'password strength + crack time',
        },
        'passphrase': {
            'func': 'src.security.password:generate_passphrase',
            'args': [],
            'opts': [('--words', int, 4, 'number of words')],
            'param_map': {'words': 'word_count'},
            'help': 'generate secure passphrase',
        },
        'audit': {
            'func': 'src.security.network:security_audit',
            'args': [],
            'opts': [],
            'help': 'full network security audit',
        },
        'ports': {
            'func': 'src.security.network:open_port_audit',
            'args': [],
            'opts': [],
            'help': 'risky open port scan',
        },
        'arp': {
            'func': 'src.security.network:arp_table_analysis',
            'args': [],
            'opts': [],
            'help': 'ARP table analysis',
        },
    },
    'qos': {
        '_help': 'VoIP quality of service',
        'mos': {
            'func': 'src.network.qos:estimate_mos',
            'args': [
                ('latency', float, 'latency in ms'),
                ('jitter', float, 'jitter in ms'),
                ('loss', float, 'packet loss %'),
            ],
            'opts': [('--codec', str, 'G.711', 'codec (G.711, G.729, Opus)')],
            'help': 'estimate MOS score',
        },
        'report': {
            'func': 'src.network.qos:voip_quality_report',
            'args': [('host', str, 'target host')],
            'opts': [('--codec', str, 'G.711', 'codec (G.711, G.729, Opus)')],
            'help': 'full VoIP quality report',
        },
    },
}


def resolve_func(ref):
    """resolve 'package.module:function' to callable"""
    if ref.startswith('_composite:'):
        name = ref.split(':')[1]
        return globals()[name]
    module_path, func_name = ref.rsplit(':', 1)
    module = importlib.import_module(module_path)
    return getattr(module, func_name)


def build_parser(commands):
    """build argparse tree from command registry"""
    import argparse

    parser = argparse.ArgumentParser(
        prog='telecom-studio',
        description='network diagnostics toolkit',
        epilog='global flags: --json (raw JSON output), --no-color (disable colors)',
    )

    module_sub = parser.add_subparsers(dest='module', help='module')

    for module_name, actions in commands.items():
        module_help = actions.get('_help', '')
        module_parser = module_sub.add_parser(module_name, help=module_help)
        action_sub = module_parser.add_subparsers(dest='action', help='action')

        for action_name, spec in actions.items():
            if action_name.startswith('_'):
                continue
            action_parser = action_sub.add_parser(action_name, help=spec['help'])

            for arg_name, arg_type, arg_help in spec['args']:
                action_parser.add_argument(arg_name, type=arg_type, help=arg_help)

            for opt in spec['opts']:
                flag, opt_type, default, opt_help = opt
                # vlsm --sizes uses nargs
                if flag == '--sizes':
                    action_parser.add_argument(
                        flag, type=opt_type, nargs='+', default=default,
                        metavar='N', help=opt_help,
                    )
                # --type conflicts with argparse internal, use dest
                elif flag == '--type':
                    action_parser.add_argument(
                        flag, type=opt_type, default=default,
                        dest='record_type', help=opt_help,
                    )
                else:
                    action_parser.add_argument(
                        flag, type=opt_type, default=default, help=opt_help,
                    )

    return parser


# composite commands

def cmd_net_ip():
    """show public and local IPs"""
    from src.network.basic import get_public_ip, get_local_ips
    pub = get_public_ip()
    local = get_local_ips()
    return {
        'status': 'success',
        'public_ip': pub.get('ip', pub.get('error', 'unknown')),
        'local_ips': local.get('interfaces', local.get('error', 'unknown')),
    }


def cmd_security_password(pw):
    """password strength + crack time estimate"""
    from src.security.password import analyze_strength, estimate_crack_time
    strength = analyze_strength(pw)
    crack = estimate_crack_time(pw)
    return {
        'status': 'success',
        'strength': strength,
        'crack_time': crack,
    }
