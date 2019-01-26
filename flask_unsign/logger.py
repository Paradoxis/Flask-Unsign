import sys
from threading import BoundedSemaphore


lock = BoundedSemaphore()
muted = False


def write(message, *, stream=None):
    if not stream:
        stream = sys.stderr

    if muted and stream is sys.stderr:
        return

    lock.acquire()
    print(message, file=stream)
    lock.release()


def error(message):
    write(f'[!] {message}')
    return 1


def info(message):
    write(f'[*] {message}')


def success(message):
    write(f'[+] {message}')
