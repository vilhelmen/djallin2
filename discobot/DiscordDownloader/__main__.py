#!/usr/bin/env python3

import argparse
from pathlib import Path
from .. import discord
import tomlkit
import logging

# FIXME: switch loggers to __name__, etc
_logger = logging.getLogger(__name__)


def load_config():
    # Slightly less invasive than the discord listener/etc
    # FIXME: configurable >:C
    config_file = Path('creds.toml')
    try:
        config = tomlkit.loads(config_file.read_text())
    except Exception as err:
        logging.critical('Error loading configuration file: %s', err)
        raise

    try:
        new_token = discord.verify_or_request_token(config['discord'].get('token'))
    except Exception as err:
        raise

    if new_token:
        _logger.info('Saving new token')
        config['discord']['token'] = new_token
        config_file.write_text(tomlkit.dumps(config))




if __name__ == '__main__':
    conf = load_config()
