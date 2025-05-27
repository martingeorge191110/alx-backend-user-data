#!/usr/bin/env python3
"""module for BasicAuth class"""
from .auth import Auth
import base64
from typing import TypeVar
from models.user import User


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

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header) -> (str, str):
        """returns the user email and password from the Base64 decoded value"""
        if (decoded_base64_authorization_header is None or
                not isinstance(decoded_base64_authorization_header, str)):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        email, password = decoded_base64_authorization_header.split(':', 1)
        return (email, password)

    def user_object_from_credentials(
            self, user_email, user_pwd) -> TypeVar('User'):
        """returns the User instance based on email and password"""
        if user_email is None or not isinstance(user_email, str):
            return (None)
        if user_pwd is None or not isinstance(user_pwd, str):
            return (None)

        try:
            users = User.search({'email': user_email})
            if not users:
                return (None)
            user = users[0]
            if not user.is_valid_password(user_pwd):
                return (None)
            return (user)
        except Exception:
            return (None)

    def current_user(self, request=None) -> TypeVar('User'):
        """retrieves the User instance for a request"""
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return (None)

        base64_header = self.extract_base64_authorization_header(auth_header)
        if base64_header is None:
            return (None)

        decoded_header = self.decode_base64_authorization_header(base64_header)
        if decoded_header is None:
            return (None)

        user_creds = self.extract_user_credentials(decoded_header)
        if user_creds[0] is None or user_creds[1] is None:
            return (None)

        return (self.user_object_from_credentials(user_creds[0],
                                                  user_creds[1]))
