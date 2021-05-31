#!/usr/bin/env python3

# TODO: this is 3.7+ only
import re
import socket
import ssl
import urllib.parse

from dataclasses import dataclass, field
import requests
import webbrowser
import logging
import copy
import traceback
import argparse
import numpy  # this apparently will make websocket run faster
import secrets
import dateutil.parser
import tomlkit
import queue
import threading
import typing

from . import OAuth2Receiver
from . import twitch

from urllib.parse import parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# FIXME: move to argparse, etc
logging.basicConfig(level=logging.DEBUG)

ready_msg = r"""
 ____  _____    _    ______   __
|  _ \| ____|  / \  |  _ \ \ / /
| |_) |  _|   / _ \ | | | \ V / 
|  _ <| |___ / ___ \| |_| || |  
|_| \_\_____/_/   \_\____/ |_|                                  
"""

crash_msg = r"""
  ____ ____      _    ____  _   _ 
 / ___|  _ \    / \  / ___|| | | |
| |   | |_) |  / _ \ \___ \| |_| |
| |___|  _ <  / ___ \ ___) |  _  |
 \____|_| \_\/_/   \_\____/|_| |_|
"""

dead_msg = r"""
 ____  _____    _    ____         __
|  _ \| ____|  / \  |  _ \   _   / /
| | | |  _|   / _ \ | | | | (_) | | 
| |_| | |___ / ___ \| |_| |  _  | | 
|____/|_____/_/   \_\____/  (_) | | 
                                 \_\
"""


# time.sleep is bad >:C
sleep_event = threading.Event()

# FIXME: queue.get() will do a blocking sleep on windows because of course it would
sound_queue = queue.PriorityQueue()


@dataclass(order=True)
class SoundRequest:
    priority: int
    timestamp: int
    request: Path = field(compare=False)


def sound_loop():
    pass


if __name__ == '__main__':
    config, server_validation, chat_functions, points_functions = load_config()

    if chat_functions:
        chat_listener(config, server_validation, chat_functions)

    if points_functions:
        pass

    if chat_functions or points_functions:
        # start sound thread
        pass
    else:
        logging.critical('Nothing to do!')
