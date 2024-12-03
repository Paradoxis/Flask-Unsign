# Metadata
# =============================================================================
__version__ = '1.2.1'
__url__ = 'https://github.com/Paradoxis/Flask-Unsign'
__author__ = 'Luke Paris (Paradoxis)'

# Default configuration
# =============================================================================

DEFAULT_SALT = 'cookie-session'
DEFAULT_NAME = 'session'
DEFAULT_AGENT = f'Flask-Unsign/{__version__}'

try:
    # noinspection PyUnresolvedReferences
    import flask_unsign_wordlist
    DEFAULT_WORDLIST = flask_unsign_wordlist.get('all')
    del flask_unsign_wordlist

except ImportError:
    DEFAULT_WORDLIST = None

# Exports
# =============================================================================
from flask_unsign.exceptions import FlaskUnsignException, DecodeError
from flask_unsign.session import sign, decode, verify
from flask_unsign.cracker import Cracker
