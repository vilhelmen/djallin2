#!/usr/bin/env python3

import socket
import ssl
import urllib.parse

import requests
import webbrowser
import logging
import copy
import argparse
import numpy  # this apparently will make websocket run faster
import secrets
import toml
import queue
import threading
from urllib.parse import parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

sock_context = ssl.create_default_context()

# FIXME: move to argparse, etc
logging.basicConfig(level=logging.DEBUG)

receiver_html = r"""
<html><body style="margin-left: 30%; margin-top: 10%; background: rgb(233, 233, 45); color: white;"><div>
    <p style="font-size: 256px;">:|</p>
    <form id="token_form" hidden method="POST" action="/" enctype="application/x-www-form-urlencoded">
        <input type="text" id="token_string" name="token_string">
    </form>
    <script>
    window.onload = function(){
        document.forms.token_form.elements.token_string.value = document.location.hash.slice(1);
        document.forms.token_form.submit();
    };
    </script>
</div></body></html>
""".encode('utf-8')

accepted_html = r"""
<html><body style="margin-left: 30%; margin-top: 10%; background: rgb(89, 174, 88); color: white;"><div>
    <p style="font-size: 256px;">;)</p>
    <script>setTimeout("window.close()",5000)</script>
</div></body></html>
""".encode('utf-8')

rejected_html = r"""
<html><body style="margin-left: 30%; margin-top: 10%; background: rgb(217, 33, 4); color: white;"><div>
    <p style="font-size: 256px;">:(</p>
    <script>setTimeout("window.close()",5000)</script>
</div></body></html>
""".encode('utf-8')

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

# class ProtectedString(str):
#     def __str__(self):
#         return '---NO---'
#
#     __repr__ = __str__
#
#     def _orig_str(self):
#         return str.__str__(self)


http_responded = threading.Event()
http_state = secrets.token_urlsafe(16)
http_response = tuple()  # >:C globals
authorize_url = 'https://id.twitch.tv/oauth2/authorize?' + urllib.parse.urlencode(
    {'response_type': 'token',
     'client_id': 'r50bzaj62mdvoo3nojyfuqeewxlj23',
     'redirect_uri': 'http://localhost:42069',
     'scope': 'channel:read:redemptions chat:read',
     'state': http_state}  # set force_verify to true to prompt authorization every time
)

# time.sleep is bad >:C
sleep_event = threading.Event()

# FIXME: queue.get() will do a blocking sleep on windows because of course it would
sound_queue = queue.PriorityQueue()


# Looks like this is instantiated per incoming request >:C
# There's really not a good way to get data out of this thing.
class TokenReceiver(BaseHTTPRequestHandler):
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
        global http_response
        # Hoo and do I mean TRY
        try:
            logging.info('Received response from browser')
            form_resp = self.rfile.read(int(self.headers['Content-Length'], 0)).decode('utf-8')
            parsed_resp = parse_qs(parse_qs(form_resp)['token_string'][0])
            if parsed_resp['state'][0] != http_state:
                raise RuntimeError('Security token mismatch, something is up with our Twitch connection')
            parsed_token = parsed_resp['access_token'][0]
        except Exception as err:
            http_response = err
        else:
            try:
                logging.info('Validating new token')
                validation_data = validate_token(parsed_token)
                if validation_data is None:
                    raise RuntimeError(f'New token validation failed :(')
            except Exception as err:
                http_response = err
            else:
                http_response = (parsed_token, validation_data)

        if isinstance(http_response, Exception):
            resp = rejected_html
        else:
            resp = accepted_html

        self._set_headers()
        self.wfile.write(resp)
        http_responded.set()


def validate_token(oauth_token):
    """
    Check token status with twitch
    Raises on connection error or unexpected status code from twitch
    :param oauth_token: user token
    :return: validation response if valid or None
    """
    logging.info('Phoning Papa Bezos...')
    try:
        resp = requests.get('https://id.twitch.tv/oauth2/validate',
                            headers={'Authorization': 'OAuth ' + oauth_token})
    except Exception as err:
        err_msg = f'Error contacting Twitch, internet issues? {err}'
        logging.critical(err_msg)
        raise RuntimeError(err_msg) from err

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
        err_msg = f'Unrecognized status code during token check: {resp.status_code}, unsure how to proceed.'
        logging.critical(err_msg)
        raise RuntimeError(err_msg)


def token_registration():
    """
    Boot an HTTP listener and contact twitch for a new token.
    Raises on failure
    :return: (token, validation_data)
    """
    logging.info('Booting HTTP server')
    try:
        server = HTTPServer(('localhost', 42069), TokenReceiver)
        http_thread = threading.Thread(target=server.serve_forever, name='http_worker')
        http_thread.start()
    except Exception as err:
        logging.critical(f'Error launching HTTP listener: {err}')
        server = None
        http_thread = None

    logging.info(f'Opening browser to {authorize_url}')
    browser_opened = webbrowser.open(authorize_url, new=2, autoraise=True)
    if not browser_opened:
        logging.error('Browser open failed :(')

    if server is None:
        logging.critical('HTTP listener is down, cannot receive token.\n'
                         'Refer to the documentation for manual authorization.\n'
                         'Closing in 10...')
        # FIXME: see if the windows bundler can leave the window open on exit
        sleep_event.wait(10)
        raise RuntimeError('Failure in HTTP listener')

    logging.info('Waiting for response...')
    http_responded.wait()
    logging.info('Listener cleanup')
    server.shutdown()
    http_thread.join()

    if isinstance(http_response, Exception):
        logging.critical(f'HTTP responder returned an error: {http_response}.\n'
                         'Refer to the documentation for manual authorization.\n'
                         'Closing in 10...')
        sleep_event.wait(10)
        raise RuntimeError('Failure in HTTP listener') from http_response
    return http_response


def validate_config(user_config):
    """
    Check configuration shape, build listener configuration
    :param config: config file data
    :return: listener configuration
    """

    # First, find all the chat and point listeners. then unkink all the links
    listener_conf = {
        'chat': {k: v for k, v in user_config.get('chat',  {}).items() if 'link' not in v},
        'points': {k: v for k, v in user_config.get('points',  {}).items() if 'link' not in v}
    }

    section = None
    k = None
    try:
        for section in ['chat', 'points']:
            for k, v in {key: value for key, value in user_config.get(section,  {}).items() if 'link' in value}.items():
                source = v['link'].split('.')
                # keys set in the linker override the linkee but I'm not gonna announce that
                instance = listener_conf[source[0]][source[1]] | v
                instance.pop('link', None)
                if section == 'points':
                    instance.pop('who', None)
    except Exception as err:
        logging.critical(f'Error reconstructing link for {section}.{k}: {err}')
        raise

    # TODO: more stuff

    # fun idea, we could build functions but also I don't think I remember how to do that

    pass


def load_config():
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

    # TODO: validate config shape here?
    validate_config(copy.deepcopy(config))

    ready = False
    if config.get('token'):
        # Hide our token, check if it's good
        validation_response = validate_token(config['token'])
        if validation_response is None:
            logging.warning('Existing token looks bad, will need to get a new one')
        else:
            if validation_response['expires_in'] < 60*24*5:
                logging.info('Token is expiring soon, requesting a new one')
            else:
                ready = True

        if not ready:
            # BE GONE FROM ME SHITTY TOKEN
            config['token'] = ''
            logging.info('Deleting old token')
            config_file.write_text(toml.dumps(config))

    if not ready:
        token_registration()
        config['token'] = http_response[0]
        logging.info('Saving new token')
        config_file.write_text(toml.dumps(config))
        validation_response = http_response[1]

    return config, validation_response


def chat_listener(config, server_validation):
    creds = {
        'host': 'irc.chat.twitch.tv',
        'port': 6697,
        'user': server_validation['login'],
        'channel': '#' + server_validation['login'],
        'oauth': 'oauth:' + config['token']
    }

    retry_count = 0
    null_count = 0
    while True:
        try:
            # port to websocket?
            #  I don't like that the websocket library has an FAQ section for "why is it slow"
            # Need to see what a network disconnect looks like
            #  MacOS, baby. this just keeps working if you turn the network off and on
            with socket.create_connection((creds['host'], creds['port'])) as sock:
                sock.setblocking(True)  # The docs DON'T say it DOESN'T work on windows
                with sock_context.wrap_socket(sock, server_hostname=creds['host']) as ssock:
                    ssock.send('PASS {}\r\nNICK {}\r\n'.format(creds['oauth'], creds['user']).encode('utf-8'))
                    # ":tmi.twitch.tv NOTICE * :Login authentication failed" on bad oauth. idk about expired
                    # We should expect a "GLHF!" otherwise in the first response
                    login_status = ssock.recv(512).decode('utf-8').strip()
                    if 'GLHF!' not in login_status:
                        err_str = f'Failed to login to chat: {login_status}'
                        logging.critical(err_str)
                        raise RuntimeError(err_str)

                    ssock.send('CAP REQ :twitch.tv/tags\r\n'.encode('utf-8'))
                    cap_add_status = ssock.recv(512).decode('utf-8').strip()
                    if cap_add_status != ':tmi.twitch.tv CAP * ACK :twitch.tv/tags':
                        err_str = f'Failed to activate tag cap: {cap_add_status}'
                        logging.critical(err_str)
                        raise RuntimeError(err_str)

                    ssock.send('JOIN {}\r\n'.format(creds['channel']).encode('utf-8'))
                    join_status = ssock.recv(512).decode('utf-8').strip()
                    if '.tmi.twitch.tv JOIN #' in join_status:
                        # Sometimes we don't get the NAMES message in time
                        if 'End of /NAMES list' not in join_status:
                            join_names = ssock.recv(512).decode('utf-8').strip()
                            if 'End of /NAMES list' not in join_names:
                                err_str = 'Names list reply missing? Got:\n{}'.format('\n'.join([join_status, join_names]))
                                logging.critical(err_str)
                                raise RuntimeError(err_str)
                    else:
                        err_str = f'Failed to join chat: {join_status}'
                        logging.critical(err_str)
                        raise RuntimeError(err_str)

                    logging.info('Connected to chat!')
                    while True:
                        msg = ssock.recv(4096).decode('utf-8').strip()
                        # max twitch message len is 512 MAYBE
                        # It's IRC in that it's mostly IRC-shaped
                        # Tags bump that significantly
                        if len(msg):
                            print('NEWMSG:', msg)
                            # safe parsing seems tricky.
                            # PRIVMSG's tmi string is much more complicated than the regular tmi string
                            # splitting on space up to 5 blocks seems safe. we should only be receiving PRIVMSG and PING
                            # @tags tmi_string privmsg #channel :msg
                            # PING tmi_string
                            components = msg.split(' ', maxsplit=5)
                            if components[0] == 'PING':
                                ssock.send('PONG\r\n'.encode('utf-8'))
                                # congrats, we made it 5 minutes without dying!
                                retry_count = 0
                                null_count = 0
                            elif len(components) == 5 and components[2] == 'PRIVMSG':
                                # user message, send to routing. Echo?
                                pass
                            else:
                                logging.error(f'Mystery message from twitch, probably fine: {msg}')
                            # @badge-info=;badges=broadcaster/1;client-nonce=f3de52b8dc6637fd0f5647f1d5361071;color=#CC7A00;display-name=Vilhel;emotes=;flags=;id=5375de26-03b9-4cfe-938f-bf66f4be6975;mod=0;room-id=64773936;subscriber=0;tmi-sent-ts=1621712675892;turbo=0;user-id=64773936;user-type= :vilhel!vilhel@vilhel.tmi.twitch.tv PRIVMSG #vilhel :frick
                            # @badge-info=;badges=broadcaster/1;client-nonce=f7ae682dbb4de8b90f49fff50f6e156b;color=#CC7A00;display-name=Vilhel;emote-only=1;emotes=305515259:0-12,29-41/307623259:14-27,43-56;flags=;id=28e1f58f-22d7-4688-872d-6f66974fa963;mod=0;room-id=64773936;subscriber=0;tmi-sent-ts=1621712712078;turbo=0;user-id=64773936;user-type= :vilhel!vilhel@vilhel.tmi.twitch.tv PRIVMSG #vilhel :mdcchrMuncher mdcchrYeahbaby mdcchrMuncher mdcchrYeahbaby
                        else:
                            logging.error('Received an empty message?')
                            null_count += 1
                            if null_count >= 5:
                                err_msg = 'Too many empty messages!'
                                logging.error(err_msg)
                                raise RuntimeError(err_msg)
        except Exception as err:
            logging.error(crash_msg)
            retry_count += 1
            if retry_count >= 3:
                logging.critical('Too many chat failures!%s', dead_msg)
                raise
        sleep_event.wait(retry_count*2)


if __name__ == '__main__':
    config, server_validation = load_config()

    #threading.Thread(target=chat_listener, name='soundq_')
    chat_listener(config, server_validation)

    #print(config, server_validation)


