#!/usr/bin/env python3

from . import OAuth2Receiver
import logging

_logger = logging.getLogger(__name__)


def validate_token(token):
    pass


def validate_response(response):
    pass


def verify_or_request_token(token: str = None):
    """
    Check discord token validity and/or renew it.
    Raises if a token can't be validated/produced
    :param token: Current token, or None
    :return: (new token string, validation data) if necessary, else None.
    """
    ready = False
    if token:
        # TODO: figure out token stuff for discord
        validation_response = validate_token(token)
        if validation_response is None:
            _logger.warning('Existing token looks bad, will need to get a new one')
        else:
            if validation_response['expires_in'] < 60*12:
                _logger.info('Token is expiring soon, requesting a new one')
            else:
                ready = True

    if not ready:
        oauth_url = 'https://discord.com/api/oauth2/authorize'
        # set force_verify to make twitch prompt for authorization every time
        oauth_params = {'response_type': 'token',
                        'client_id': '848353210086588457',
                        'redirect_uri': 'http://localhost:42068',
                        'scope': 'messages.read'}

        def url_callback(url):
            _logger.error(f'Opening browser, if nothing happens, go to {url}')
            _logger.warning('Waiting for token response. '
                            'If the application does not respond, check the documentation for manual authorization.')

        try:
            oauth_response = OAuth2Receiver.get_oauth_code(('localhost', 42068), oauth_url, oauth_params,
                                                           True, url_callback, 300)
        except TimeoutError as err:
            msg = 'Browser response not received, manual authorization required.'
            _logger.critical(msg)
            raise RuntimeError(msg) from err
        except Exception as err:
            msg = 'OAuth listener failed, manual authorization required.'
            _logger.critical(msg)
            raise RuntimeError(msg) from err

        # I don't think there's really anything that can be bad here? idk if we really need to validate?
        token = oauth_response['access_token']
        # {'token_type': 'Bearer', 'access_token': 'XXXX', 'expires_in': '604800', 'scope': 'messages.read', 'state': 'XXXX'}
        validate_response(oauth_response)
        _logger.info('Got new token')
        return token
    else:
        return None
