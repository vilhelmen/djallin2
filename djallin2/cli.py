#!/usr/bin/env python3

import argparse
import logging
import sys
from pathlib import Path

import pkg_resources

from . import twitch

logger = logging.getLogger(__name__)


def run_argparse():
    def path_check_file_exists(value):
        try:
            path = Path(value)
        except:
            raise argparse.ArgumentTypeError(f'Could not parse path "{value}"')
        if not path.is_file():
            raise argparse.ArgumentTypeError(f'"{value}" does not exist or is not a file')
        return path

    parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
    parser.add_argument('--config', type=path_check_file_exists, default='config.txt', help='Configuration file')
    parser.add_argument('--quiet', action='store_true', help='Suppress startup sound')
    parser.add_argument('--debug', action='store_true', help='Extra logging')
    parser.add_argument('--version', action='version',
                        version='%(prog)s ' + pkg_resources.get_distribution(__package__).version)

    return vars(parser.parse_args())


def boot():
    # Just for reference for now
    bundled = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')

    args = run_argparse()

    logging.basicConfig(level=logging.DEBUG if args['debug'] else logging.INFO,
                        format='%(levelname)s:%(threadName)s:%(message)s')
    logger.setLevel(logging.DEBUG if args['debug'] else logging.INFO)

    twitch.launch_system(args['config'], args['quiet'], args['debug'], bundled)
