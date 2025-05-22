#!/usr/bin/env python3
"""module for encrypting passwords"""
import bcrypt


def hash_password(password: str) -> bytes:
    """returns salted and hashed password"""
    return( bcrypt.hashpw(password.encode(), bcrypt.gensalt()))


def is_valid(hashed_password: bytes, password: str) -> bool:
    """checks if the password matches the hashed one"""
    is_match = bcrypt.checkpw(password.encode(), hashed_password)
    return (is_match)
