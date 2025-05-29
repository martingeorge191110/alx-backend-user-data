#!/usr/bin/env python3
"""module for Auth class that handles authentication"""
from typing import List, TypeVar
from flask import request
from os import getenv


class Auth:
    """Auth class for handling authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """returns True if the path is
        not in the list of strings excluded_paths"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        # Make path slash tolerant by ensuring it ends with /
        if not path.endswith('/'):
            path = path + '/'

        # Check if path is in excluded_paths
        for excluded_path in excluded_paths:
            if path == excluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """returns the value of the Authorization request header"""
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """request will be the Flask request object"""
        return None

    def session_cookie(self, request=None):
        """Returns a cookie value from a request"""
        if request is None:
            return (None)

        session_name = getenv('SESSION_NAME')
        if session_name is None:
            return (None)

        return (request.cookies.get(session_name))
