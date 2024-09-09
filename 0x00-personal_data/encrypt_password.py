#!/usr/bin/env python3
"""
Defines a hash_password function to return a hashed password
"""
import bcrypt
from bcrypt import hashpw


def hash_password(passwd: str) -> bytes:
    """
    Returns a hashed password
    Args:
        password (str): password to be hashed
    """
    b = passwd.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_passwd: bytes, passwd: str) -> bool:
    """
    Check if a password is valid
    Args:
        hashed_passwd (bytes): hashed password
        passwd (str): password in string
    Return:
        bool
    """
    return bcrypt.checkpw(passwd.encode(), hashed_passwd)
