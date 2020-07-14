import sys
import time
from itertools import islice
from threading import BoundedSemaphore
from traceback import print_tb
from typing import Iterable
from multiprocessing.pool import ThreadPool

from flask_unsign import session, logger, __url__


class Cracker:
    def __init__(self, value: str, legacy: bool=False, salt: str='cookie-session', threads: int=8, chunk_size: int = 128, quiet: bool = False):
        """
        Cracker constructor
        :param value: Session cookie to crack / decode
        :param salt: Session salt, hard coded to 'cookie-session' in Flask
        :param threads: Number of threads to attempt to crack the signature
        :param chunk_size: Number of secrets to load between attempt cycles
        """
        self.lock = BoundedSemaphore()
        self.pool = ThreadPool(processes=threads)
        self.thread_count = threads
        self.chunk_size = chunk_size
        self.has_error = False
        self.iterable = None

        self.secret = None
        self.salt = salt
        self.legacy = legacy
        self.session = value
        self.quiet = quiet

        self.attempts = 0

    def crack(self, iterable: Iterable[str]):
        """Run the brute-forcer by iterating over a set of strings"""
        self.iterable = iterable

        for i in range(self.thread_count):
            self.pool.apply_async(self.unsign, args=[i + 1], error_callback=self.error_handler)

        self.pool.close()
        self.pool.join()
        return self.secret

    def secrets(self):
        self.lock.acquire()
        secrets = list(islice(self.iterable, self.chunk_size))
        self.lock.release()
        return secrets

    def unsign(self, thread_id: int):
        """
        Attempt to unsign the previously set cookie with a given secret
        :param thread_id: Nth thread currently running
        :return: True if the decode was successful
        """
        time.sleep(0.1 * thread_id)

        attempts = 0
        secret = b''
        secrets = self.secrets()

        while any(secrets) and not self.secret and not self.has_error:
            for secret in secrets:
                attempts += 1

                if session.verify(self.session, secret, legacy=self.legacy, salt=self.salt):
                    self.secret = secret
                    self.pool.terminate()

            self.lock.acquire()
            self.attempts += attempts

            if not self.quiet:
                if not isinstance(secret, bytes):
                    secret = secret.encode()

                print((
                    f"[*] Attempted ({self.attempts}): "
                    f"{secret[0:30].decode('ascii', errors='ignore').ljust(30, ' ')}".strip()
                ), end='\r', flush=True, file=sys.stderr)

            self.lock.release()

            secrets = self.secrets()
            attempts = 0

    def error_handler(self, exc):
        """
        Error callback handler for thread related issues
        :param exc: Exception
        :return: None
        """
        self.has_error = True
        self.pool.terminate()

        if isinstance(exc, ValueError) and 'I/O operation on closed file' in str(exc):
            return logger.write('\b\b[!] Aborted.', stream=sys.stderr)

        logger.error(
            f'Unhandled exception in cracker thread. Please report this issue '
            f'on the official bug tracker: "{__url__}/issues" and don\'t forget '
            f'to include the following traceback:\n')

        print('## Stack Trace', file=sys.stderr)
        print('```', file=sys.stderr)
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        print_tb(exc.__traceback__, file=sys.stderr)
        print('```\n', file=sys.stderr)

