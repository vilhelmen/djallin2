#!/usr/bin/env python3

import socket
import ssl
import requests

import logging
import argparse
import toml
from pathlib import Path

sock_context = ssl.create_default_context()

logging.basicConfig(level=logging.DEBUG)


class ProtectedString(str):
    def __str__(self):
        return '---NO---'

    __repr__ = __str__

    def _orig_str(self):
        return str.__str__(self)


def validate_token(oauth_token):
    """
    Check token status with twitch
    :param oauth_token:
    :return:
    """
    try:
        resp = requests.get('https://id.twitch.tv/oauth2/validate',
                            headers={'Authorization': 'OAuth ' + oauth_token})
    except Exception as err:
        logging.critical('Error contacting twitch, internet issues? %s', err)
        raise
    if resp.status_code == 200:
        logging.info('Twitch says our token is valid')
        resp = resp.json()
        # {'client_id': 'r50bzaj62mdvoo3nojyfuqeewxlj23', 'login': 'vilhel',
        #  'scopes': ['channel:read:redemptions', 'chat:read'],
        #  'user_id': '64773936', 'expires_in': 4902655}
        # check scopes
        missing_scopes = {'channel:read:redemptions', 'chat:read'} - set(resp['scopes'])
        if missing_scopes:
            # man %s feel so ancient and gross
            logging.critical('Missing scopes from token (%s)! Discarding it.', missing_scopes)
            return None
        # Uhhhhhh seconds? Let's renew if we're under a week? Could probably do a day or two.
        elif resp['expires_in'] < 60 * 24 * 7:
            logging.info('Token is expiring soon, throwing it out.')
            return None
        # TODO return data blob
        return {

        }
    if resp.status_code == 401:
        logging.info('Existing token looks bad, will need to get a new one')
        return None


def launch_config():
    """
    Load the config file, vaguely check its shape, dial in to twitch/generate token
    :return: config dict
    """
    try:
        # TODO: rename config file, figure out .gitignore for it
        with open('creds.toml', 'r') as f:
            config = toml.load(f)
    except Exception as err:
        logging.critical('Error loading configuration file: %s', err)
        raise

    # TODO: validate config shape here

    has_token = False
    if config.get('token'):
        has_token = True
        config['token'] = ProtectedString(config['token'])
        validate_token(config['token'])

    # There's not a great way to do this. We gotta ping twitch to check expiration/validity
    # But we may want to pull a new token, or have to if we don't have one
    # which we then need to ping twitch for.
    # So we need to (maybe) ping twitch, (maybe) reauth, and then (maybe) ping twitch again


    return config




if __name__ == '__main__':

    config = launch_config()

    token_data = requests.get('https://id.twitch.tv/oauth2/validate', heades={'Authorization': 'OAuth {}'.format(creds['oauth'])})

    with socket.create_connection((creds['host'], creds['port'])) as sock:
        sock.setblocking(True)  # The docs DON'T say it DOESN'T work on windows
        # I... do you set the wrapper or...???????????
        # ssock.setblocking(True)
        with sock_context.wrap_socket(sock, server_hostname=creds['host']) as ssock:
            ssock.send('PASS {}\r\nNICK {}\r\nJOIN {}\r\n'.format(
                ''.join(['oauth:', creds['oauth']]), creds['user'], creds['channel']).encode('utf-8'))
            # ":tmi.twitch.tv NOTICE * :Login authentication failed" on bad oauth. idk about expired
            # We should expect a "GLHF!" otherwise in the first response
            # Every 5 minutes we get "PING :tmi.twitch.tv" to which we reply "PONG :tmi.twitch.tv"
            while True:
                msg = ssock.recv(1024).decode('utf-8').strip()
                # max twitch message len is 512 MAYBE
                # It's IRC in that it's mostly IRC-shaped
                if len(msg):
                    print('NEWMSG:', msg)
                else:
                    print('.', end='')

