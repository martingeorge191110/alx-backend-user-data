#!/usr/bin/env python3
"""module for BasicAuth class"""
from .auth import Auth
import base64


class BasicAuth(Auth):
    """BasicAuth class that inherits from Auth"""

    def extract_base64_authorization_header(self,
                                            authorization_header) -> str:
        """returns the Base64 part
        of the Authorization header"""
        if authorization_header is None or not isinstance(
               authorization_header, str):
            return (None)
        if not authorization_header.startswith('Basic '):
            return (None)
        return (authorization_header[6:])

    def decode_base64_authorization_header(self,
                                           base64_authorization_header) -> str:
        """returns the decoded value of a Base64 string"""
        if base64_authorization_header is None or not isinstance(
                  base64_authorization_header, str):
            return (None)
        try:
            decoded = base64.b64decode(base64_authorization_header)
            return decoded.decode('utf-8')
        except Exception:
            return (None)
