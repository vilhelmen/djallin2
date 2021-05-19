#!/usr/bin/env python3

import socket
import ssl
import requests
import webbrowser
import logging
import argparse
import toml
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

sock_context = ssl.create_default_context()

logging.basicConfig(level=logging.DEBUG)

receiver_html = """
<html><body style="margin-left: 30%; margin-top: 10%; background: rgb(233, 233, 45); color: white;"><div>
    <p style="font-size: 256px;">:|</p>
    <form id="token_form" method="POST" action="/">
        <input type="text" id="token_string" name="token_string">
    </form>
    <script>
    window.onload = function(){
        document.forms.token_form.elements.token_string.value = document.location.hash;
        document.forms.token_form.submit();
    };
    </script>
</div></body></html>
""".encode('utf-8')

accepted_html = """
<html><body style="margin-left: 30%; margin-top: 10%; background: rgb(89, 174, 88); color: white;"><div>
    <p style="font-size: 256px;">;)</p>
    <script>setTimeout("window.close()",3000)</script>
</div></body></html>
""".encode('utf-8')

rejected_html = """
<html><body style="margin-left: 30%; margin-top: 10%; background: rgb(217, 33, 4); color: white;"><div>
    <p style="font-size: 256px;">:(</p>
    <script>setTimeout("window.close()",3000)</script>
</div></body></html>
""".encode('utf-8')


class ProtectedString(str):
    def __str__(self):
        return '---NO---'

    __repr__ = __str__

    def _orig_str(self):
        return str.__str__(self)


class TokenReceiver(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self._token_data = None
        super().__init__(*args, **kwargs)

    def serve_forever(self):
        while not self._token_data:
            self.handle_one_request()
        return self._token_data

    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write(receiver_html)

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        print(self.rfile.read(int(self.headers['Content-Length'])))
        self._set_headers()
        self.wfile.write(accepted_html)
        pass


def validate_token(oauth_token):
    """
    Check token status with twitch
    Raises on connection error or unexpected status code from twitch
    :param oauth_token: user token
    :return: validation response if valid or None
    """
    logging.info('Calling Papa Bezos...')
    try:
        resp = requests.get('https://id.twitch.tv/oauth2/validate',
                            headers={'Authorization': 'OAuth ' + oauth_token})
    except Exception as err:
        msg = f'Error contacting Twitch, internet issues? {err}'
        logging.critical(msg)
        raise RuntimeError(msg) from err

    if resp.status_code == 200:
        resp = resp.json()
        need = {'channel:read:redemptions', 'chat:read'}
        has = set(resp['scopes'])
        missing = need - has
        if missing:
            logging.warning(f'Token is missing required scopes: {missing}. Throwing it out.')
            return None
        return resp
    elif resp.status_code == 401:
        return None
    else:
        msg = f'Unrecognized status code during token check: {resp.status_code}, unsure how to proceed.'
        logging.critical(msg)
        raise RuntimeError(msg)


def launch_config():
    """
    Load the config file, vaguely check its shape, dial in to twitch/generate token
    :return: config dict
    """
    # TODO: rename config file, figure out .gitignore for it
    config_file = Path('creds.toml')
    try:
        config = toml.loads(config_file.read_text())
    except Exception as err:
        logging.critical('Error loading configuration file: %s', err)
        raise

    # TODO: validate config shape here

    ready = False
    if config.get('token'):
        # Hide our token, check if it's good
        config['token'] = ProtectedString(config['token'])
        validation_response = validate_token(config['token'])
        if validation_response is None:
            logging.warning('Existing token looks bad, will need to get a new one')
        else:
            if validation_response['expires'] < 60*24*5:
                logging.info('Token is expiring soon, requesting a new one!')
            else:
                ready = True

        if not ready:
            # BE GONE FROM ME SHITTY TOKEN
            del config['token']
            config_file.write_text(toml.dumps(config))

    if not ready:
        logging.info('Booting HTTP server and requesting a new token')
        # Print URL as well!!
        try:
            token = HTTPServer(('localhost', 42069), TokenReceiver).serve_forever()
        except Exception as err:
            pass
        #webbrowser.open('', new=2, autoraise=True)
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

