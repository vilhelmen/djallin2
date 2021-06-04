#!/usr/bin/env python3

import logging
import os
import re
import socket
import ssl
import copy
import threading
from pathlib import Path
import typing
import tomlkit
import requests
import traceback
import random
import dateutil.parser
import toml
import signal
import pkg_resources
from . import OAuth2Receiver, SoundServer, StatTracker

logger = logging.getLogger(__name__)
sock_context = ssl.create_default_context()
sleep_event = threading.Event()

# TODO: this is gonna take ahwile to integrate
shutdown_event = threading.Event()


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


def validate_token(oauth_token):
    """
    Check token status with twitch
    Raises on connection error or unexpected status code from twitch
    :param oauth_token: user token
    :return: validation response if valid or None
    """
    logger.info('Phoning Papa Bezos...')
    try:
        resp = requests.get('https://id.twitch.tv/oauth2/validate',
                            headers={'Authorization': 'OAuth ' + oauth_token})
    except Exception as err:
        err_msg = f'Error contacting Twitch, internet issues? {err}'
        logger.critical(err_msg)
        raise RuntimeError(err_msg) from err

    if resp.status_code == 200:
        resp = resp.json()
        need = {'channel:read:redemptions', 'chat:read'}
        has = set(resp['scopes'])
        missing = need - has
        if missing:
            logger.warning(f'Token is missing required scopes: {missing}. Throwing it out.')
            return None
        elif resp['expires_in'] < 60*24*2:
            logger.warning('Token is expiring soon, requesting a new one')
            return None
        return resp
    elif resp.status_code == 401:
        return None
    else:
        err_msg = f'Unrecognized status code during token check: {resp.status_code}, unsure how to proceed.'
        logger.critical(err_msg)
        raise RuntimeError(err_msg)


def build_and_validate_listener_conf(config):
    """
    Check configuration shape and prep listener data
    :param config: config file data
    :return: listener configuration
    """
    # First, find all the chat and point listeners. then unkink all the links
    listener_conf = {
        'chat': {k: v for k, v in config.get('chat',  {}).items() if 'link' not in v},
        'points': {k: v for k, v in config.get('points',  {}).items() if 'link' not in v}
    }

    section = None
    name = None
    try:
        for section in listener_conf.keys():
            for name, conf in {k: v for k, v in config.get(section,  {}).items() if 'link' in v}.items():
                source = conf['link'].split('.')
                # keys set in the linker override the linkee but I'm not gonna announce that
                instance = listener_conf[source[0]][source[1]] | conf
                instance.pop('link', None)
                instance.pop('link', None)
                if section == 'points':
                    instance.pop('who', None)
                    instance.pop('command', None)
                listener_conf[section][name] = instance
    except Exception as err:
        logger.critical(f'Error reconstructing link for {section}.{name}: {err}')
        raise

    # Ok, cool. Do some rough type validation
    # UGH you can't make a union of one type and you can't run isinstace with None
    # and it's not clear how to make NoneType
    key_types = {
        'points': {
            'target': (str,),
            'random': (int,),
            'priority': (bool,),
            'stats': (bool,),
            'rewardname': (str,),
            'chaos': (bool,),
        },
        'chat': {
            'names': (list, type(None)),
            'badges': (list, type(None)),
            'target': (str,),
            'command': (str,),
            'random': (int, type(None)),
            'priority': (bool,),
            'stats': (bool,),
            'chaos': (bool,),
        }
    }
    try:
        for section in listener_conf.keys():
            for name, conf in listener_conf[section].items():
                for k, t in key_types[section].items():
                    if k in conf:
                        assert isinstance(conf[k], t)
                # Types look good, do any formatting
                if section == 'chat':
                    conf['names'] = set(conf.get('names', []))
                    conf['badges'] = set(conf.get('badges', []))
                conf['target'] = Path(conf['target'])
                # I guess we should raise if it's missing
                assert conf['target'].exists()
                conf['random'] = conf.get('random', 0)
                conf['stats'] = conf.get('stats', False)
                conf['chaos'] = conf.get('chaos', False)
                if conf['random'] not in {0, 1, 2}:
                    conf['random'] = 0
                conf['priority'] = conf.get('priority', False)
    except Exception as err:
        logger.critical(f'Error validating config for {section}.{name}: {err}')
        raise

    return listener_conf


def build_listeners(listener_conf, sound_server, stat_server):
    chat_functions = []
    points_functions = {}
    try:
        for section in [k for k, v in listener_conf.items() if v]:
            for name, conf in sorted(listener_conf[section].items()):
                if section == 'chat':
                    chat_functions.append(
                        chat_listener_factory(name, sound_server, conf['stats'], stat_server, conf['badges'],
                                              conf['names'], conf['target'], conf['target'].is_file(),
                                              [] if conf['target'].is_file() else
                                              [_ for _ in conf['target'].glob('*.mp3')],
                                              conf['command'], conf['random'], conf['priority'], conf['chaos'])
                    )
                elif section == 'points':
                    points_functions[conf['name']] = \
                        points_listener_factory(name, sound_server, conf['stats'], stat_server, conf['target'],
                                                conf['target'].is_file(),
                                                [] if conf['target'].is_file() else
                                                [_ for _ in conf['target'].glob('*.mp3')],
                                                conf['random'], conf['priority'], conf['chaos'])
                else:
                    raise RuntimeError(f'Error building listeners, no known section {section}')
    except Exception as err:
        logger.critical(f'Error building listener for {section}.{name}: {err}')
        raise

    return chat_functions, points_functions


# message_filter = re.compile(r"""["'/\\<>:|?*\s]""")
message_filter = re.compile(r'\W')


def chat_listener_factory(entry_name: str,
                          sound_server: SoundServer.SoundServer,
                          stat_track: bool,
                          stat_server: StatTracker.StatTracker,
                          badge_set: set,
                          name_set: set,
                          target: Path,
                          target_is_file: bool,
                          target_file_list: list,
                          command: str,
                          random_mode: int,
                          priority_playback: bool,
                          chaos: bool) -> typing.Callable[[dict, dict, int, str, str, str], bool]:
    def listener(badges: dict, tags: dict, timestamp: int, sender: str, sender_display: str, message: str, **kwargs) -> bool:
        """
        Checks various filters against the request and queues a sound.
        :param badges: User badge map. badge (str): version (str)
        :param tags: Twitch message tags. tag (str): value (str)
        :param timestamp: Message timestamp (ms)
        :param sender: Username of the message sender, lowercase
        :param sender_display: User's display name
        :param message: Chat message - !!NOT SANITIZED!!
        :return: bool indicating if it fired. Stops processing listeners if True
        """
        request = None
        if message.startswith(command):
            if (not badge_set and not name_set) or badges.keys() & badge_set or sender in name_set:
                message = message_filter.sub('', message[len(command):]).lower()
                if target_is_file:
                    request = SoundServer.SoundRequest(50 if priority_playback else 100, timestamp, target, not chaos)
                elif random_mode == 2 or (random_mode == 1 and message == 'random'):
                    request = SoundServer.SoundRequest(50 if priority_playback else 100, timestamp, random.choice(target_file_list), not chaos)
                else:
                    request = SoundServer.SoundRequest(50 if priority_playback else 100, timestamp, target / (message + '.mp3'), not chaos)
        if request is not None:
            sound_server.enqueue(request)
            if stat_track:
                stat_server.submit('chat', sender, entry_name, timestamp, message)
            return True
        return False
    return listener


def points_listener_factory(entry_name: str,
                            sound_server: SoundServer.SoundServer,
                            stat_track: bool,
                            stat_server: StatTracker.StatTracker,
                            target: Path,
                            target_is_file: bool,
                            target_file_list: list,
                            random_mode: int,
                            priority_playback: bool,
                            chaos: bool) -> typing.Callable[[dict, str, dict, str], None]:
    def listener(user: dict, redeemed_at: str, reward: dict, user_input: typing.Optional[str] = None, **kwargs) -> None:
        """
        Reads a points redemption and does whatever it needs to do
        :param user: user data, str: str map. id, login, display_name
        :param redeemed_at: 8601 timestamp string
        :param reward: lots of data, check the twitch api docs https://dev.twitch.tv/docs/pubsub#example-channel-points-event-message
        :param user_input: Data from the user, if applicable
        :param kwargs:
        :return: n/a
        """
        request = None
        timestamp = int(dateutil.parser.parse('2019-12-11T18:52:53.128421623Z').timestamp() * 1000)
        message = message_filter.sub('', user_input) if user_input else ''
        if target_is_file:
            request = SoundServer.SoundRequest(50 if priority_playback else 100, timestamp, target, not chaos)
        elif random_mode == 2 or (random_mode == 1 and message == 'random'):
            request = SoundServer.SoundRequest(50 if priority_playback else 100, timestamp, random.choice(target_file_list), not chaos)
        else:
            request = SoundServer.SoundRequest(50 if priority_playback else 100, timestamp, target / (message + '.mp3'), not chaos)
        if request is not None:
            sound_server.enqueue(request)
            if stat_track:
                stat_server.submit('chat', sender, entry_name, timestamp, message)
    return listener


def do_token_work(config_file: Path):
    """
    Check token stuff, potentially update config file
    :param config_file: Path to conf
    :return: token, server validation data
    """
    config = tomlkit.loads(config_file.read_text())

    ready = False
    if config.get('token'):
        # check if it's good
        validation_response = validate_token(config['token'])
        if validation_response is not None:
            ready = True
        else:
            # BE GONE FROM ME SHITTY TOKEN
            config['token'] = ''
            logger.info('Deleting old token')
            config_file.write_text(tomlkit.dumps(config))

    if not ready:
        oauth_url = 'https://id.twitch.tv/oauth2/authorize'
        # set force_verify to make twitch prompt for authorization every time
        oauth_params = {'response_type': 'token',
                        'client_id': 'r50bzaj62mdvoo3nojyfuqeewxlj23',
                        'redirect_uri': 'http://localhost:42069',
                        'scope': 'channel:read:redemptions chat:read'}

        def url_callback(url):
            logger.error(f'Opening browser, if nothing happens, go to {url}')
            logger.warning('Waiting for token response. '
                            'If the application does not respond, check the documentation for manual authorization.')

        try:
            oauth_response = OAuth2Receiver.get_oauth_code(('localhost', 42069), oauth_url, oauth_params,
                                                           True, url_callback, 300)
        except TimeoutError as err:
            msg = 'Browser response not received, manual authorization required.'
            logger.critical(msg)
            raise RuntimeError(msg) from err
        except Exception as err:
            msg = 'OAuth listener failed, manual authorization required.'
            logger.critical(msg)
            raise RuntimeError(msg) from err

        config['token'] = oauth_response['access_token']
        validation_response = validate_token(config['token'])
        if validation_response is None:
            msg = "New token is bad???"
            logger.critical(msg)
            raise RuntimeError(msg)
        logger.info('Saving new token')
        config_file.write_text(tomlkit.dumps(config))

    return config['token'], validation_response


def chat_listener(config, server_validation, chat_functions):
    creds = {
        'host': 'irc.chat.twitch.tv',
        'port': 6697,
        'user': server_validation['login'],
        'channel': '#' + server_validation['login'],
        'oauth': 'oauth:' + config['token']
    }

    retry_count = 0
    while True:
        message_buffer = []
        leftovers = b''
        partial_read = False
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
                    sleep_event.wait(0.2)
                    login_status = ssock.recv(512)
                    if b'GLHF!' not in login_status:
                        err_str = f'Failed to login to chat: {login_status}'
                        logger.critical(err_str)
                        raise RuntimeError(err_str)

                    ssock.send('CAP REQ :twitch.tv/tags\r\n'.encode('utf-8'))
                    sleep_event.wait(0.2)
                    cap_add_status = ssock.recv(512).decode('utf-8').strip()
                    if cap_add_status != ':tmi.twitch.tv CAP * ACK :twitch.tv/tags':
                        err_str = f'Failed to activate tag cap: {cap_add_status}'
                        logger.critical(err_str)
                        raise RuntimeError(err_str)

                    ssock.send('JOIN {}\r\n'.format(creds['channel']).encode('utf-8'))
                    sleep_event.wait(0.2)
                    join_status = ssock.recv(512)
                    if b'.tmi.twitch.tv JOIN #' not in join_status:
                        err_str = f'Failed to join chat: {join_status}'
                        logger.critical(err_str)
                        raise RuntimeError(err_str)
                    # Sometimes it's just late but there's not much I can do about it, I don't want to accidentally
                    #  suck up some partial message :/
                    if b'End of /NAMES list' not in join_status:
                        join_status = ssock.recv(512)
                        if b'End of /NAMES list' not in join_status:
                            err_str = f'Failed to get name listing?: {join_status}'
                            logger.critical(err_str)
                            raise RuntimeError(err_str)
                    logger.info('Connected to chat!')
                    while True:
                        # Ok, here's the problem.
                        #  The buffer could be backed up enough that we receive a partial message.
                        # The original version did a regex split on \r\n and always popped off the last entry
                        # And combined it with the next received buffer
                        # I question how well that worked, but it was also a nonblocking recv
                        # So that's probably why it pegs a core.
                        # Yikes, we might cut a multibyte character in half with a partial read. Is that a raise?
                        # Let's not decode until after we've processed linebreaks
                        msg = ssock.recv(4096)
                        logger.debug(msg)
                        if not len(msg):
                            # you literally can't send zero bytes. We got hung up on.
                            # Strange that is is, seemingly, the only way to find out besides a fileno of -1
                            raise ConnectionError('Connection closed')
                        if partial_read:
                            msg = leftovers + msg
                        # max twitch message len is 512 MAYBE
                        # It's IRC in that it's mostly IRC-shaped
                        # Tags bump that significantly
                        partial_read = not msg.endswith(b'\r\n')
                        message_buffer = msg.split(b'\r\n')
                        if partial_read:
                            leftovers = message_buffer.pop()
                        logger.debug(message_buffer)
                        for msg in message_buffer:
                            msg = msg.decode('utf-8')
                            # We, in theory, shouldn't be able to get an empty message anymore.
                            # You PROBABLY can't send \r\n in twitch chat lol
                            if msg:
                                # safe parsing seems tricky.
                                # PRIVMSG's tmi string is much more complicated than the regular tmi string
                                # splitting on space up to 5 blocks seems safe. we should only be receiving PRIVMSG and PING
                                # @tags tmi_string privmsg #channel :msg
                                # PING tmi_string
                                components = msg.split(' ', maxsplit=4)
                                if components[0] == 'PING':
                                    logger.info('Responding to chat ping')
                                    ssock.send('PONG\r\n'.encode('utf-8'))
                                    # congrats, we made it 5 minutes without dying!
                                    retry_count = 0
                                elif len(components) == 5 and components[2] == 'PRIVMSG':
                                    try:
                                        tags = {k: v for k, v in [x.split('=') for x in components[0][1:].split(';')]}
                                        badges = {k: v for k, v in [x.split('/') for x in tags['badges'].split(',')]}
                                        timestamp = int(tags['tmi-sent-ts'])
                                        sender = components[1][1:].split('!', maxsplit=1)[0].lower()
                                        # display-name can be empty
                                        sender_display = sender if not tags.get('display-name') else tags['display-name']
                                        message = components[4][1:]
                                        logging.info(f'{sender}: {message}')
                                        # badges: dict, tags: dict, timestamp: int, sender: str, sender_display: str, message: str, **kwargs
                                        for func in chat_functions:
                                            if func(badges, tags, timestamp, sender, sender_display, message):
                                                break
                                    except Exception as err:
                                        # FIXME? this isn't a reconnect-level issue, but it's still a problem.
                                        logger.error(f'Error in message scanner loop: {err}')
                                        logger.error(traceback.format_exc())
                                else:
                                    logger.error(f'Mystery message from twitch, probably fine: {msg}')
        except Exception as err:
            logger.error(crash_msg)
            logger.error(f'Got {err}')
            logger.error(traceback.format_exc())
            logger.error(f'Lost {len(message_buffer) + partial_read} messages :(')
            retry_count += 1
            if retry_count >= 3:
                logger.critical('Too many chat failures!%s', dead_msg)
                raise
        sleep_event.wait(2*retry_count)


def launch_system(config_file: Path, quiet: bool = False):
    """
    Do all the things
    :param config_file: Path to config file
    """
    try:
        config = toml.loads(config_file.read_text())
    except Exception as err:
        logger.critical('Error loading configuration file: %s', err)
        raise

    # ugh we said paths would be relative to the conf file
    # We might as well chdir, this means we aren't logging/saving abspaths everywhere
    os.chdir(config_file.absolute().parent)

    logger.debug('Checking config')
    listener_conf = build_and_validate_listener_conf(copy.deepcopy(config))

    logging.debug(listener_conf)

    logging.debug('Doing token stuff')
    config['token'], server_validation = do_token_work(config_file)

    logging.debug('Attaching signal handlers')

    def handler(signum, frame):
        logger.critical(f'SIG{signum}: shutting down')
        shutdown_event.set()

    # On Windows, signal() can only be called with SIGABRT, SIGFPE, SIGILL, SIGINT, SIGSEGV, SIGTERM, or SIGBREAK.
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    logger.debug('Starting sound server')
    soundserver = SoundServer.SoundServer(shutdown_event)

    if not quiet:
        soundserver.enqueue(SoundServer.SoundRequest(
            0, 0, Path(pkg_resources.resource_filename(__package__, 'internal/up.mp3')), False))

    logger.debug('Booting stats server')
    # uhhhhhhh base the name on the config... somehow? Generate one and write back?
    disable_stats = not any(conf['stats'] for section in listener_conf.values() for conf in section.values())
    statserver = StatTracker.StatTracker(Path(config.get('stats_db', 'stats.sqlite')), shutdown_event, disable_stats)

    chat_functions, points_functions = build_listeners(listener_conf, soundserver, statserver)

    chat_thread = None
    points_thread = None

    if chat_functions:
        # daemonize because I can't think of a nice way to integrate shutdown yet
        chat_thread = threading.Thread(target=chat_listener, args=(config, server_validation, chat_functions),
                                       name='chat_listener', daemon=True)
        chat_thread.start()

    if points_thread:
        logger.critical('Lol no points')

    if not chat_functions and not points_functions:
        logging.critical('Nothing configured??')
        shutdown_event.set()

    # TODO: Figure out shutdowns in the various bad spots
    #  (soundserver needing a fake(?) sound, chat listener, (eventually) points listnener)
    shutdown_event.wait()

    if not quiet:
        soundserver.enqueue(SoundServer.SoundRequest(
            -1, -1, Path(pkg_resources.resource_filename(__package__, 'internal/down.mp3')), False))

    # So here's the deal. If we raise and we're in windows, the terminal window's probably gonna close immediately
    # so we probably need to wrap this all in a try and if platforms == 'Windows' time.sleep(10) or something
