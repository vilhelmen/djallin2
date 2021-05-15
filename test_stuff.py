#!/usr/bin/env python3

import socket
import ssl

import logging
import argparse
import toml
from pathlib import Path

sock_context = ssl.create_default_context()

logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
    creds = toml.loads(Path('creds.toml').read_text())['server']


    print('joined?')

    # max twitch message len is 510+\r\n MAYBE
    # This is IRC in that it kinda looks like IRC

    with socket.create_connection((creds['host'], creds['port'])) as sock:
        sock.setblocking(True)  # The docs DON'T say it DOESN'T work on windows
        # I... do you set the wrapper or...???????????
        # ssock.setblocking(True)
        with sock_context.wrap_socket(sock, server_hostname=creds['host']) as ssock:
            ssock.send('PASS {}\r\nNICK {}\r\nJOIN {}\r\n'.format(''.join(['oauth:', creds['oauth']]), creds['user'], creds['channel']).encode('utf-8'))
            # ":tmi.twitch.tv NOTICE * :Login authentication failed" on bad oauth. idk about expired
            # We should expect a "GLHF!" otherwise in the first response
            # Every 5 minutes we get "PING :tmi.twitch.tv" to which we reply "PONG :tmi.twitch.tv"
            while True:
                msg = ssock.recv(1024).decode('utf-8')
                if len(data):
                    print('NEWMSG:', msg.strip())
                else:
                    print('.', end='')

