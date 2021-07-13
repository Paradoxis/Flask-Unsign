import sys
from datetime import datetime
from argparse import ArgumentParser
from typing import Optional

import requests

from flask_unsign.cracker import Cracker

from flask_unsign.helpers import (
    CustomHelpFormatter, wordlist, parse,
    extract_error, handle_interrupt)

from flask_unsign import (
    DecodeError,
    logger, session,
    __url__, __author__, __version__,
    DEFAULT_WORDLIST, DEFAULT_SALT,
    DEFAULT_NAME, DEFAULT_AGENT)


@handle_interrupt
def main() -> Optional[int]:
    """
    Main entry point of the application
    :return: None
    """
    parser = ArgumentParser(
        formatter_class=CustomHelpFormatter,
        description=(
            'Flask Unsign is a penetration testing utility that attempts to '
            'uncover a Flask server\'s secret key by taking a signed session '
            'verifying it against a wordlist of commonly used and publicly '
            'known secret keys (sourced from books, GitHub, StackOverflow '
            'and various other sources). To begin, use one of the following '
            'arguments: --unsign, --sign, --decode'))

    parser.add_argument('-d', '--decode', action='store_true', help=(
        'Only decode the sessions\'s contents and write them to stdout.'))
    
    parser.add_argument('-u', '--unsign', action='store_true', help=(
        'Attempts to crack the session\'s signature by iterating over a given '
        'wordlist with commonly used .'))

    parser.add_argument('-s', '--sign', action='store_true', help=(
        "Sign a session with a specified secret key, often used for session "
        "manipulation. Requires the '--secret' argument."))

    parser.add_argument('-l', '--legacy', action='store_true', help=(
        'Generate / verify signatures using itsdangerous\'es legacy timestamp '
        'generator. Note: All installations of flask before 2018-10-18 use '
        'this form of timestamp and all generated signatures will be regarded '
        'as expired (meaning you will not be able to brute-force the secret key '
        'nor forge any sessions).'))

    parser.add_argument('-c', '--cookie', const='', nargs='?', help=(
        'Session cookie string. If you\'re decoding/cracking a session key this'
        'can be obtained by manually inspecting an HTTP request and extracting '
        'the value of the "session" cookie. If you\'re signing a cookie, this '
        'can be any arbitrary Python dictionary with data (or other data type, '
        'whatever floats your boat, but don\'t expect the server to understand '
        'it). If no argument is provided, the program will attempt to read '
        'from stdin. Note: When signing data, this will ALWAYS be evaluated.'))

    parser.add_argument('--secret', '-S', help=(
        'Secret key to sign a new session cookie with. Generally obtained by '
        'brute-forcing a known session using "--unsign". Note: this '
        'argument is affected by the "--no-literal-eval" argument.'))

    parser.add_argument('--salt', default=DEFAULT_SALT, help=(
        'Custom salt string, this will not be changed in most instances '
        'of Flask. But hey, if you need to change it, you can! Note: this '
        'argument is affected by the "--no-literal-eval" argument.'))

    parser.add_argument('--wordlist', '-w', help=(
        'Note: this argument is affected by the "--no-literal-eval" argument.'))

    parser.add_argument('--threads', '-t', default=8, type=int, help=(
        'Specifies the number of threads to brute-force the secret key with. '
        'Defaults to: 8'))

    parser.add_argument('--no-literal-eval', '-nE', action='store_true', help=(
        'Due to the fact that a lot of secret keys are binary strings, all '
        'lines in wordlists are encapsulated with double/single quotes to '
        'represent Python strings. This is done so it\'s easier to generate '
        'wordlists without having to store the data in an arbitrary binary '
        'format (or SQL databases). By enabling this option, you\'ll be able '
        'to use a wordlist / secret keys / salts without having to wrap each '
        'line with quotes.'))

    parser.add_argument('--server', help=(
        'Specifies a remote HTTP(S) server to fetch the session cookie from. '
        'In order for this to work, you\'ll have to specify an url which '
        'returns a "Set-Cookie" header.'))

    parser.add_argument('--insecure', '-i', '-k', help=(
        'By default, all SSL connections are verified to be secure to prevent '
        'man-in-the-middle attacks. This option disables TLS/SSL certificate '
        'verification entirely.'), action='store_true', default=False)

    parser.add_argument('-p', '--proxy', help=(
        'Specifies an HTTP(S) proxy to connect to before firing the request. '
        'Useful for making requests for a service behind a firewall.'))

    parser.add_argument('--cookie-name', default=DEFAULT_NAME, help=(
        f'Specifies the cookie name which contains the session information. In '
        f'default Flask applications this defaults to {DEFAULT_NAME!r}, however '
        f'it is possible to change this. Only use in combination with the '
        f'"--server" argument.'))

    parser.add_argument('-U', '--user-agent', default=DEFAULT_AGENT, help=(
        f'Specifies a custom user agent to use when making requests to the '
        f'server. Only use in combination with the "--server" argument. '
        f'Defaults to: {DEFAULT_AGENT!r}'))

    parser.add_argument('-q', '--quiet', '--stfu', action='store_true', help=(
        'Disables verbose output logging, and only logs usable output. '
        'Note: All "usable" output is logged to stdout, wheras all informative '
        'output is logged to stderr, so you could extract all usable output by '
        'redirecting it with > in bash.'))

    parser.add_argument('-C', '--chunk-size', type=int, default=128, help=(
        'Number of passwords loaded into memory per thread cycle. After each '
        'password of the chunk has been depleted a status update will be '
        'printed to the console with the attempted password. Default: 128'))

    parser.add_argument('-v', '--version', action='store_true', help=(
        'Prints the current version number to stdout and exits.'))

    args = parser.parse_args()

    if args.version:
        print(__version__)
        return 0

    if not args.sign and not args.unsign and not args.decode:
        logger.write(f'Flask-Unsign - ({__url__})')
        logger.write(f'Copyright (c) {datetime.now().year} - {__author__}')
        logger.write('')
        parser.print_help()
        logger.write('')
        return 1

    if args.quiet:
        logger.muted = True

    if args.proxy and isinstance(args.proxy, str):
        args.proxy = {'http': args.proxy, 'https': args.proxy, 'ftp': args.proxy}

    if args.server:
        sess = requests.session()
        sess.verify = not args.insecure

        if args.insecure:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        try:
            resp = sess.get(args.server, headers={
                'User-Agent': args.user_agent
            }, allow_redirects=False, proxies=args.proxy)
        except requests.RequestException as e:
            return logger.error(f'Failed to fetch session data from the server. {extract_error(e)}')

        logger.info(f'Server returned HTTP {resp.status_code} ({resp.reason})')
        args.cookie = sess.cookies.get(args.cookie_name)

        if not args.cookie:
            return logger.error(
                'Failed to fetch session data from the server. Are you sure '
                'the cookie name and url is correct? You can always manually '
                'specify a session cookie using the "--cookie" argument.')

        else:
            logger.success(f'Successfully obtained session cookie: {args.cookie}')

    if args.cookie == '':
        args.cookie = sys.stdin.read().strip()

    if args.sign:
        if not args.secret:
            return logger.error('Missing required parameter "--secret".')

        if not args.cookie:
            return logger.error('Missing required parameter "--cookie".')

        if not args.no_literal_eval:
            args.salt = parse(args.salt)
            args.secret = parse(args.secret)

        # Dictionaries must always be parsed before use. If you want to use
        # this anyway, simply import this library in a custom python script
        # and call the `flask_unsign.sign()` manually with your parameters of
        # choice.
        args.cookie = parse(args.cookie)

        return logger.write(session.sign(
            value=args.cookie,
            secret=args.secret,
            salt=args.salt,
            legacy=args.legacy
        ), stream=sys.stdout)

    if args.decode:
        if not args.cookie:
            return logger.error('Missing required parameter "--cookie".')

        return logger.write(session.decode(value=args.cookie), stream=sys.stdout)

    if args.unsign:
        if not args.cookie and not args.server:
            return logger.error(
                f'Please specify a cookie to crack/decode or specify an '
                f'http(s) url to automatically fetch the session cookie from. '
                f'One of "--server" or "--cookie" must be supplied.')

        logger.info(f'Session decodes to: {session.decode(args.cookie)}')

        if not args.wordlist and not DEFAULT_WORDLIST:
            return logger.error(
                'No wordlist selected, nor was a default wordlist found. '
                'Please specify one using the "--wordlist" argument, or '
                'install the optional wordlist module by running: '
                'pip install flask-unsign[wordlist]')

        if not args.wordlist:
            logger.info('No wordlist selected, falling back to default wordlist..')
            args.wordlist = DEFAULT_WORDLIST

        cracker = Cracker(
            value=args.cookie,
            legacy=args.legacy,
            salt=args.salt,
            threads=args.threads,
            chunk_size=args.chunk_size,
            quiet=args.quiet)

        with wordlist(args.wordlist, parse_lines=(not args.no_literal_eval)) as iterator:
            logger.info(f'Starting brute-forcer with {args.threads} threads..')
            cracker.crack(iterator)

        if cracker.secret:
            logger.success(f'Found secret key after {cracker.attempts} attempts')
            logger.write(ascii(cracker.secret), stream=sys.stdout)
        else:
            return logger.error(
                f'Failed to find secret key after '
                f'{cracker.attempts} attempts.')


if __name__ == '__main__':
    exit(main() or 0)

