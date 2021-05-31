#!/usr/bin/env python3

import argparse
from pathlib import Path
import tomlkit
import logging

# FIXME: switch loggers to __name__, etc


def load_config():
    # Slightly less invasive than the discord listener/etc
    # FIXME: configurable >:C
    config_file = Path('creds.toml')
    try:
        config = tomlkit.loads(config_file.read_text())
    except Exception as err:
        logging.critical('Error loading configuration file: %s', err)
        raise

if __name__ == '__main__':
    conf = load_config()