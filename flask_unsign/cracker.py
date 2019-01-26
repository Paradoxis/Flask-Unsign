from typing import Iterable
from multiprocessing.pool import ThreadPool

from flask_unsign import session, logger


class Cracker:
    def __init__(self, value: str, legacy: bool=False, salt: str='cookie-session', threads: int=8):
        """
        Cracker constructor
        :param value: Session cookie to crack / decode
        :param salt: Session salt, hard coded to 'cookie-session' in Flask
        :param threads: Number of threads to attempt to crack the signature
        """
        self.secret = None
        self.salt = salt
        self.legacy = legacy
        self.session = value
        self.pool = ThreadPool(processes=threads)
        self.attempts = 0

    def crack(self, iterable: Iterable[str]):
        """Run the brute-forcer by iterating over a set of strings"""
        self.pool.map_async(self.unsign, iterable, error_callback=logger.error)
        self.pool.close()
        self.pool.join()
        return self.secret

    def unsign(self, secret):
        """
        Attempt to unsign the previously set cookie with a given secret
        :param secret: Secret key to break the cookie with
        :return: True if the decode was successful
        """
        if session.verify(self.session, secret, legacy=self.legacy, salt=self.salt):
            self.secret = secret
            self.pool.terminate()

        self.attempts += 1
