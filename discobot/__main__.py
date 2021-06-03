#!/usr/bin/env python3

# TODO: this is 3.7+ only
import logging
import argparse
import numpy  # this apparently will make websocket run faster
import secrets
import dateutil.parser
import tomlkit
import queue
import threading
import typing
from pathlib import Path
from . import twitch

logger = logging.getLogger(__name__)


# time.sleep is bad >:C
sleep_event = threading.Event()

# FIXME: queue.get() will do a blocking sleep on windows because of course it would
sound_queue = queue.PriorityQueue()


def sound_loop():
    pass


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
    # FIXME: rename/update .gitignore
    parser.add_argument('--config', type=path_check_file_exists, default='creds.toml', help='Configuration file')
    parser.add_argument('--debug', action='store_true')

    return vars(parser.parse_args())


if __name__ == '__main__':
    args = run_argparse()

    logging.basicConfig(level=logging.DEBUG if args['debug'] else logging.INFO,
                        format='%(levelname)s:%(threadName)s:%(message)s')
    logger.setLevel(logging.DEBUG if args['debug'] else logging.INFO)

    twitch.launch_system(args['config'])
