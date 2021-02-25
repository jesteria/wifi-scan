#!/usr/bin/env python3
"""Scan & report on visible access points (iwlist scan)."""
import argparse
import pathlib
import re
import subprocess

from terminaltables import AsciiTable


__version__ = '0.0.1'


COLUMNS = ('cell', 'channel', 'frequency', 'quality', 'essid')

INTERFACE_FILE = pathlib.Path('/proc/net/wireless')

INTERFACE_PATTERN = re.compile(r'^([^ :]+): ', re.MULTILINE)

SCAN_PATTERN = re.compile(
    r'Cell (\d+) - Address.+?Channel:(\d+).+?Frequency:([^ ]+) .+?Quality=([\d/]+) .+?ESSID:(?:"([^"]+)")?',
    re.DOTALL | re.MULTILINE
)


def guess_interface():
    try:
        output = INTERFACE_FILE.read_text()
    except FileNotFoundError:
        pass
    else:
        if interface_match := INTERFACE_PATTERN.search(output):
            return interface_match.group(1)

    return None


def perform_scan(interface):
    result = subprocess.run(
        ['iwlist', interface, 'scan'],
        stdout=subprocess.PIPE,
        check=True,
        text=True,
    )
    return result.stdout


def extract(item):
    if quality_match := re.fullmatch(r'(\d+)/(\d+)', item):
        (value0, value1) = quality_match.groups()
        return int(100 * int(value0) / int(value1))

    return int(item) if item.isdigit() else item


def parse_data(inp):
    try:
        reader = inp.read
    except AttributeError:
        data = inp
    else:
        data = reader()

    for row in SCAN_PATTERN.findall(data):
        yield [extract(item) for item in row]


def output_parsed(parsed, sort_keys=()):
    if sort_keys:
        row_indices = [COLUMNS.index(key) for key in sort_keys]
        output_data = sorted(parsed, key=lambda row: [row[index] for index in row_indices])
    else:
        output_data = parsed

    output = [COLUMNS]
    output.extend(output_data)

    table = AsciiTable(output)
    print(table.table)


def main(argv=None):
    default_interface = guess_interface()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('-k', '--sort', dest='sort_keys', action='append', choices=COLUMNS,
                        help="key(s) by which to sort result")
    parser.add_argument('-f', '--file', type=argparse.FileType('r'),
                        help='read wifi data from file ("-" to indicate stdin)')
    parser.add_argument('interface', nargs='?', default=default_interface,
                        help=f"interface thru which to scan (default: {default_interface})")

    args = parser.parse_args(argv)

    if args.file is None:
        try:
            data_file = perform_scan(args.interface)
        except subprocess.CalledProcessError as exc:
            raise SystemExit(exc.returncode)
    else:
        data_file = args.file

    parsed = parse_data(data_file)
    output_parsed(parsed, args.sort_keys)


if __name__ == '__main__':
    main()
