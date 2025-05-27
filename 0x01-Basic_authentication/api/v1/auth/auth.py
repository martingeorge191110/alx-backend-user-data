#!/usr/bin/env python3
"""module for Auth class that handles authentication"""
from typing import List, TypeVar
from flask import request


class Auth:
    """Auth class for handling authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """path and excluded_paths will be used later"""
        return False

    def authorization_header(self, request=None) -> str:
        """request will be the Flask request object"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """request will be the Flask request object"""
        return None

