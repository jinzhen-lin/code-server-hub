# encoding: utf-8
import hashlib
import random
import socket


def random_hash_str(length=32):
    """Get a random hash string with given length."""
    return "".join(chr(random.randint(97, 122)) for _ in range(length))


def random_port():
    """Get a single random port."""
    sock = socket.socket()
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def sha256sum(s):
    """Hash the string using SHA-256"""
    if isinstance(s, str):
        s = s.encode("utf8")
    return hashlib.sha256(s).hexdigest()
