import sys
from os import unlink
from io import StringIO
from uuid import UUID
from base64 import b64encode
from datetime import datetime, timezone
from importlib import reload
from unittest import TestCase
from unittest.mock import patch, MagicMock
from contextlib import redirect_stderr, redirect_stdout, suppress
from tempfile import mktemp

from markupsafe import Markup
from requests.exceptions import ProxyError
from urllib3.exceptions import MaxRetryError

import flask_unsign
from flask_unsign import __main__ as cli, logger, __version__, FlaskUnsignException
from flask_unsign.helpers import wordlist


INDEX_FN_NAME = 0
INDEX_ARGS = 1
INDEX_KWARGS = 2


class TestCaseBase(TestCase):
    wordlist = None

    def setUp(self):
        reload(cli)
        reload(logger)

    @classmethod
    def setUpClass(cls):
        cls.wordlist = cls.create_wordlist()
        flask_unsign.DEFAULT_WORDLIST = cls.wordlist

    @classmethod
    def tearDownClass(cls):
        with suppress(FileNotFoundError):
            unlink(cls.wordlist)

    @staticmethod
    def create_wordlist():
        path = mktemp()

        data = '\n'.join(map(ascii, (
            'foo',
            'bar',
            'baz',
            'CHANGEME'
        )))

        with open(path, 'w') as file:
            file.write(data)

        return path


class FlaskUnsignTestCase(TestCaseBase):
    secret = 'CHANGEME'
    value = {
        'hello': 'world',
        'tuple': ('bar', 'baz'),
        'base64': b64encode(b'Hello world'),
        'datetime': datetime.now(tz=timezone.utc).replace(microsecond=0),
        'uuid': UUID(bytes=b'x' * 16),
        'markup': Markup('<script>alert("evil")</script>'),
        'dict': {'hello': 'world'}
    }

    def test_basic_functionality(self):
        kwargs = {
            'value': self.value,
            'secret': self.secret}

        modern = flask_unsign.sign(**kwargs)
        legacy = flask_unsign.sign(**kwargs, legacy=True)

        self.assertNotEqual(modern, legacy)

        self.assertTrue(flask_unsign.verify(modern, self.secret))
        self.assertTrue(flask_unsign.verify(legacy, self.secret, legacy=True))

        self.assertFalse(flask_unsign.verify(modern, self.secret + 'x'))
        self.assertFalse(flask_unsign.verify(legacy, self.secret + 'x', legacy=True))

        self.assertEqual(self.value, flask_unsign.decode(modern))
        self.assertEqual(self.value, flask_unsign.decode(legacy))

        with self.assertRaises(flask_unsign.DecodeError):
            flask_unsign.decode('Hello world!')

        with self.assertRaises(flask_unsign.DecodeError):
            flask_unsign.decode('')

        with wordlist(flask_unsign.DEFAULT_WORDLIST) as iterable:
            cracker = flask_unsign.Cracker(value=modern)
            cracker.crack(iterable)
            self.assertEqual(cracker.secret, self.secret)

        with wordlist(flask_unsign.DEFAULT_WORDLIST) as iterable:
            cracker = flask_unsign.Cracker(value=legacy, legacy=True)
            cracker.crack(iterable)
            self.assertEqual(cracker.secret, self.secret)

    def test_verify(self):
        with self.assertRaises(FlaskUnsignException):
            flask_unsign.verify(value='', secret=[], legacy=False)


class CliTestCase(TestCaseBase):
    encoded = 'eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA'
    decoded = {'hello': 'world'}
    secret = 'CHANGEME'

    def call(self, *argv):
        stdout, stderr = StringIO(), StringIO()

        with patch.object(sys, 'argv', new=['flask-unsign'] + list(argv)):
            with redirect_stdout(stdout):
                with redirect_stderr(stderr):
                    cli.main()

        stdout.seek(0)
        stderr.seek(0)

        return stdout, stderr

    def test_default(self):
        """Ensure a default help message when none of the operators are used"""
        stdout, stderr = self.call()
        self.assertIn('Copyright', stderr.read())

    def test_version_argument(self):
        """Ensure that the current version number is printed correctly"""
        stdout, stderr = self.call('-v')
        self.assertEqual(stdout.read().strip(), __version__)

        stdout, stderr = self.call('--version')
        self.assertEqual(stdout.read().strip(), __version__)

    def test_cookie_argument(self):
        """Ensure that cookie can be passed as an argument"""
        stdout, stderr = self.call('--decode', '--cookie', self.encoded)
        self.assertEqual(stdout.read().strip(), str(self.decoded))

        with patch.object(cli.sys.stdin, 'read', return_value=self.encoded):
            stdout, stderr = self.call('--decode', '--cookie')
            self.assertEqual(stdout.read().strip(), str(self.decoded))

    @patch.object(cli.requests, 'session')
    def test_server(self, requests):
        """Ensure it's possible to fetch cookies from a server and errors are handled properly"""
        requests.return_value = requests
        requests.get.return_value = requests

        requests.cookies = {'session': self.encoded}
        stdout, stderr = self.call('--decode', '--server', 'http://localhost:5000')
        self.assertEqual(stdout.read().strip(), str(self.decoded))

        requests.cookies = {'something-else': self.encoded}
        stdout, stderr = self.call('--decode', '--server', 'http://localhost:5000')
        self.assertNotEqual(stderr.read(), '', msg='Expected an error message')
        self.assertEqual(stdout.read(), '')

        requests.cookies = {'something-else': self.encoded}
        stdout, stderr = self.call('--decode', '--server', 'http://localhost:5000', '--cookie-name', 'something-else')
        self.assertEqual(stdout.read().strip(), str(self.decoded))

        requests.cookies = {'session': self.encoded}
        stdout, stderr = self.call(
            '--decode',
            '--server', 'http://localhost:5000',
            '--proxy', 'https://root:password@localhost:8080')

        self.assertEqual(stdout.read().strip(), str(self.decoded))

        for call in requests.mock_calls:
            if call[INDEX_FN_NAME] == 'get':
                if 'proxies' in call[INDEX_KWARGS]:
                    break

        else:
            raise AssertionError('Didn\'t find "proxies" argument in call args.')

        error_reason = ProxyError()
        error_reason.args = ('Cannot connect to proxy', OSError('Tunnel connection failed'))
        error = ProxyError(MaxRetryError(reason=error_reason, pool=MagicMock(), url='http://localhost:5000'))
        requests.get.side_effect = error

        requests.cookies = {'session': self.encoded}
        stdout, stderr = self.call(
            '--decode',
            '--server', 'http://localhost:5000',
            '--proxy', 'https://root:password@localhost:8080')

        self.assertIn('Tunnel connection failed', stderr.read().strip())
        self.assertTrue(requests.verify, msg='Verify should be true by default')

        for flag in ('-i', '-k', '--insecure'):
            requests.verify = True

            self.call(
                '--decode',
                '--server', 'http://localhost:5000',
                flag)

            self.assertFalse(requests.verify, msg=(
                f'Verify should be set to False if called with the {flag} flag'))

    def test_decode(self):
        """Ensure --decode works as expected"""
        stdout, stderr = self.call('--decode', '--cookie', self.encoded)
        self.assertEqual(stdout.read().strip(), str(self.decoded))

        stdout, stderr = self.call('--decode')
        self.assertIn('--cookie', stderr.read())

    def test_quiet(self):
        """Ensure the 'quiet' option mutes output"""
        stdout, stderr = self.call('--decode', '--cookie', self.encoded, '--quiet')
        self.assertEqual(stdout.read().strip(), str(self.decoded))
        self.assertEqual(stderr.read(), '')

        stdout, stderr = self.call('--decode', '--quiet')
        self.assertEqual(stdout.read(), '')
        self.assertEqual(stderr.read(), '')

        stdout, stderr = self.call('--unsign', '--cookie', self.encoded, '--quiet')
        self.assertEqual(stdout.read().strip(), ascii(self.secret))
        self.assertEqual(stderr.read(), '')

    def test_sign(self):
        stdout, stderr = self.call('--sign', '--cookie', str(self.decoded), '--secret', self.secret)
        self.assertTrue(flask_unsign.verify(stdout.read().strip(), secret=self.secret))

        stdout, stderr = self.call('--sign', '--cookie', str(self.decoded), '--secret', '12345')
        self.assertNotEqual(stderr.read(), '', msg=(
            'Expected an error when a non-string type is passed to sign'))

        stdout, stderr = self.call('--sign', '--cookie', str(self.decoded))
        self.assertIn('--secret', stderr.read())

        stdout, stderr = self.call('--sign', '--secret', self.secret)
        self.assertIn('--cookie', stderr.read())

    @patch.object(cli.requests, 'session')
    def test_unsign(self, requests):
        requests.return_value = requests
        requests.get.return_value = requests

        stdout, stderr = self.call('--unsign', '--cookie', self.encoded)
        self.assertEqual(stdout.read().strip(), ascii(self.secret))
        self.assertNotEqual(stderr.read(), '')

        requests.cookies = {'session': self.encoded}
        stdout, stderr = self.call('--unsign', '--server', 'http://localhost:5000')
        self.assertEqual(stdout.read().strip(), ascii(self.secret))
        self.assertNotEqual(stderr.read(), '')

        stdout, stderr = self.call('--unsign')
        stderr = stderr.read()
        self.assertEqual(stdout.read(), '')
        self.assertIn('--server', stderr)
        self.assertIn('--cookie', stderr)

        stdout, stderr = self.call('--unsign', '--cookie', self.encoded + 'x')
        self.assertIn('Failed to find secret key', stderr.read())
        self.assertEqual(stdout.read(), '')

        stdout, stderr = self.call('--unsign', '--cookie', 'x' * 50)
        self.assertIn('Failed to decode cookie', stderr.read())
        self.assertEqual(stdout.read(), '')

    def test_no_literal_eval(self):
        with patch.object(flask_unsign.session, 'sign') as sign:
            self.call(
                '--sign',
                '--cookie', str(self.decoded),
                '--secret', '"hello"')

            self.assertEqual(sign.call_args[1]['secret'], 'hello', msg=(
                'Expected the secret to be parsed'))

            self.call(
                '--sign',
                '--cookie', str(self.decoded),
                '--secret', '"hello"',
                '--no-literal-eval')

            self.assertEqual(sign.call_args[1]['secret'], '"hello"', msg=(
                'Expected the secret to remain as-is'))

            stdout, stderr = self.call(
                '--unsign',
                '--cookie', self.encoded,
                '--no-literal-eval')

            self.assertIn('Failed to find secret key', stderr.read())
            self.assertEqual(stdout.read(), '')

    def test_no_wordlist(self):
        with patch.object(flask_unsign, 'DEFAULT_WORDLIST', new=None):
            reload(cli)  # Prevent argumentparser from caching the value

            stdout, stderr = self.call(
                '--unsign',
                '--cookie', self.encoded)

            self.assertIn('No wordlist selected, nor was a default wordlist found', stderr.read())

    def test_error_handler(self):
        with patch.object(cli.Cracker, 'unsign', side_effect=ValueError('oops!')):
            stdout, stderr = self.call(
                '--unsign',
                '--cookie', self.encoded)

            self.assertIn('Error', stderr.read(), msg='Expected error message to be in stderr')

        with patch.object(cli.Cracker, 'unsign', side_effect=ValueError('I/O operation on closed file')):
            stdout, stderr = self.call(
                '--unsign',
                '--cookie', self.encoded)

            self.assertIn('Aborted', stderr.read(), msg='Expected abort message')
