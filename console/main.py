#!/usr/bin/env python3
"""telecom-studio console — network diagnostics from the terminal"""

import os
import sys

# ensure src/ is importable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from console.commands import COMMANDS, build_parser, resolve_func
from console.output import print_header, render_result


def _extract_global_flags():
    """pull --json and --no-color from argv so they work anywhere"""
    json_mode = '--json' in sys.argv
    no_color = '--no-color' in sys.argv
    sys.argv = [a for a in sys.argv if a not in ('--json', '--no-color')]
    return json_mode, no_color


def _map_args(spec, parsed):
    """extract kwargs for the target function from parsed args"""
    kwargs = {}
    param_map = spec.get('param_map', {})

    for arg_name, _, _ in spec['args']:
        kwargs[arg_name] = getattr(parsed, arg_name)

    for opt in spec['opts']:
        flag = opt[0].lstrip('-').replace('-', '_')
        # --type is stored as record_type in argparse
        attr = 'record_type' if opt[0] == '--type' else flag
        val = getattr(parsed, attr, opt[2])
        # map CLI flag name to function parameter name
        param_name = param_map.get(flag, flag)
        kwargs[param_name] = val

    # vlsm: --sizes maps to 'requirements' parameter
    if 'sizes' in kwargs:
        kwargs['requirements'] = kwargs.pop('sizes')

    return kwargs


def _disable_colors():
    import console.output as out
    for attr in ('RESET', 'BOLD', 'DIM', 'GREEN', 'YELLOW', 'RED', 'CYAN', 'WHITE'):
        setattr(out, attr, '')
    out.ICON_OK = '[+]'
    out.ICON_WARN = '[!]'
    out.ICON_ERR = '[-]'
    out.ICON_INFO = '[*]'


def main():
    json_mode, no_color = _extract_global_flags()

    if no_color:
        _disable_colors()

    parser = build_parser(COMMANDS)
    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(0)

    if not args.action:
        parser.parse_args([args.module, '--help'])
        sys.exit(0)

    spec = COMMANDS[args.module][args.action]
    func = resolve_func(spec['func'])
    kwargs = _map_args(spec, args)

    if not json_mode:
        print_header(f'{args.module} {args.action}')

    try:
        result = func(**kwargs)
    except Exception as exc:
        result = {'status': 'error', 'error': str(exc)}

    render_result(result, json_mode=json_mode)
    sys.exit(0 if result.get('status') == 'success' else 1)


if __name__ == '__main__':
    main()
