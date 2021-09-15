import sys
import time
import warnings
from argparse import HelpFormatter
from calendar import EPOCH
from contextlib import suppress, contextmanager
from ast import literal_eval
from datetime import datetime
from functools import wraps

from itsdangerous import TimestampSigner
from requests import RequestException
from typing import Union

from flask_unsign import logger, FlaskUnsignException


class CustomHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, indent_increment=2, max_help_position=7, width=None)

    # noinspection PyProtectedMember
    def _format_action(self, action):
        result = super(CustomHelpFormatter, self)._format_action(action) + "\n"

        if 'show this help message and exit' in result:
            result = result.replace('show', 'Show', 1)

        return result


class LegacyTimestampSigner(TimestampSigner):
    """
    Legacy version of the timestamp signer where the epoch was removed from
    the current time. This was changed in version 1.1.0 (following an issue
    which noted that no dates before 2011 could be used, source:
    https://github.com/pallets/itsdangerous/issues/46).
    """

    def get_timestamp(self):
        return int(time.time() - EPOCH)

    def timestamp_to_datetime(self, ts):
        return datetime.utcfromtimestamp(ts + EPOCH)


# noinspection PyUnreachableCode
def parse(line: Union[str, bytes]):
    with suppress(SyntaxError, ValueError):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')

            if isinstance(line, bytes):
                line = line.decode()

            return literal_eval((line.strip() or '').strip())

    return line.strip()


@contextmanager
def wordlist(path: str, *, parse_lines: bool=True):
    with open(path, 'rb') as file:
        if parse_lines:
            yield map(parse, file)
        else:
            yield map(bytes.strip, file)


def extract_error(error: RequestException) -> str:
    while True:
        if hasattr(error, 'reason'):
            error = error.reason.args[1]
        elif hasattr(error, 'args'):
            error = error.args[0]
        else:
            return error


def handle_interrupt(func):
    """Decorator which ensures that keyboard interrupts are handled properly."""
    @wraps(func)
    def wrapper():
        try:
            return func() or 0

        except KeyboardInterrupt:
            logger.write('\b\b[!] Aborted.', stream=sys.stderr)
            return 1

        except FlaskUnsignException as e:
            logger.write(f'[!] {e}', stream=sys.stderr)
            return 1

    return wrapper


def fix_stdout(func):
    """Decorator which ensures stdout is put back in place after run"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        stdout = sys.stdout
        try:
            return func(*args, **kwargs)
        finally:
            if sys.stdout is not stdout:
                try:
                    sys.stdout.close()
                finally:
                    sys.stdout = stdout
    return wrapper
