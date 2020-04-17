import hashlib
import json
import zlib
from base64 import b64decode
from functools import lru_cache
from typing import Union, AnyStr
from uuid import UUID

from flask.json.tag import TaggedJSONSerializer
from itsdangerous import base64_decode, URLSafeTimedSerializer, BadSignature, TimestampSigner
from markupsafe import Markup
from werkzeug.http import parse_date

from flask_unsign import DecodeError, DEFAULT_SALT
from flask_unsign.exceptions import SigningError, FlaskUnsignException
from flask_unsign.helpers import LegacyTimestampSigner


def verify(value: str, secret: str, legacy: bool=False, salt: str=DEFAULT_SALT) -> bool:
    """
    Verifies if a given value matches the signed signature
    :param value: Session cookie string to verify
    :param secret: Secret key
    :param salt: Salt (default: 'cookie-session')
    :param legacy: Should the legacy timestamp generator be used?
    :return: True if the secret key is valid
    """
    if not isinstance(secret, (bytes, str)):
        raise FlaskUnsignException(
            f"Secret must be a string-type (bytes, str) and received "
            f"{type(secret).__name__!r}. To fix this, either add quotes to the "
            f"secret {secret!r} or use the --no-literal-eval argument.")

    try:
        get_serializer(secret, legacy, salt).loads(value)
    except BadSignature:
        return False

    return True


def sign(value: dict, secret: AnyStr, legacy: bool = False, salt: str = DEFAULT_SALT) -> str:
    """
    Signs a custom session value with a known secret
    :param value: Raw Python object (generally a dictionary) to serialize
    :param secret: Server secret key
    :param salt: Salt (default: 'cookie-session')
    :param legacy: Should the legacy timestamp generator be used?
    :return: Encoded string
    """
    if not isinstance(secret, (bytes, str)):
        raise SigningError(
            f"Secret must be a string-type (bytes, str) and received "
            f"{type(secret).__name__!r}. To fix this, either add quotes to the "
            f"secret {secret!r} or use the --no-literal-eval argument.")

    return get_serializer(secret, legacy, salt).dumps(value)


def decode(value: str) -> dict:
    """
    Flask uses a custom JSON serializer so they can encode other data types.
    This code is based on theirs, but we cast everything to strings because
    we don't need them to survive a round trip if we're just decoding them.

    Source: https://www.kirsle.net/wizards/flask-session.cgi#source

    :param value: Session cookie string to decode
    :returns: A dictionary representation of the value which was decoded
    """
    try:
        compressed = False
        payload = value

        if payload.startswith('.'):
            compressed = True
            payload = payload[1:]

        data = payload.split(".")[0]

        data = base64_decode(data)

        if compressed:
            data = zlib.decompress(data)

        data = data.decode("utf-8")

    except Exception as e:
        raise DecodeError(
            f'Failed to decode cookie, are you sure '
            f'this was a Flask session cookie? {e}')

    def hook(obj):
        if len(obj) != 1:
            return obj

        key, val = next(iter(obj.items()))

        if key == ' t':
            return tuple(val)
        elif key == ' u':
            return UUID(val)
        elif key == ' b':
            return b64decode(val)
        elif key == ' m':
            return Markup(val)
        elif key == ' d':
            return parse_date(val)

        return obj

    try:
        return json.loads(data, object_hook=hook)

    except json.JSONDecodeError as e:
        raise DecodeError(
            f'Failed to decode cookie, are you sure '
            f'this was a Flask session cookie? {e}')


@lru_cache()
def get_serializer(secret: str, legacy: bool, salt: str) -> URLSafeTimedSerializer:
    """
    Get a (cached) serializer instance
    :param secret: Secret key
    :param salt: Salt
    :param legacy: Should the legacy timestamp generator be used?
    :return: Flask session serializer
    """
    if legacy:
        signer = LegacyTimestampSigner
    else:
        signer = TimestampSigner

    return URLSafeTimedSerializer(
        secret_key=secret,
        salt=salt,
        serializer=TaggedJSONSerializer(),
        signer=signer,
        signer_kwargs={
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1})

