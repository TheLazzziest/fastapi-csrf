from os import urandom
from hashlib import sha1
from typing import Optional

from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadData

from .exceptions import TokenValidationError

def encode_token(secret_key: str, salt: Optional[str] = None, session_id: Optional[str] = None) -> str:
    '''
    Generate a CSRF token. The token is cached for a request, so multiple
    calls to this function will generate the same token.
    '''
    serializer = URLSafeTimedSerializer(secret_key, salt=salt)
    token = serializer.dumps(
        session_id or sha1(urandom(64)).hexdigest()
    )
    return token

def decode_token(token: str, secret_key: str, salt: Optional[str] = None, max_age: Optional[int] = 0) -> str:
    '''
    Check if the given data is a valid CSRF token. This compares the given
    signed token to the one stored in the session.
    :param data: The signed CSRF token to be checked.
    :param secret_key: Used to securely sign the token.
        Default is set in CsrfConfig
    :param time_limit: Number of seconds that the token is valid.
        Default is set in CsrfConfig
    :raises TokenValidationError: Contains the reason that validation failed.
    '''
    serializer = URLSafeTimedSerializer(secret_key, salt=salt)
    try:
      token = serializer.loads(token, max_age=max_age)
    except SignatureExpired as exc:
      raise TokenValidationError('The CSRF token has expired.') from exc
    except BadData as exc:
      raise TokenValidationError('The CSRF token is invalid.') from exc
    return token
