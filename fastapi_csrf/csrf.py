from typing import Any, Mapping, Optional, Callable, Type

from fastapi import Request
from fastapi.responses import Response
from itsdangerous import BadData, SignatureExpired, URLSafeTimedSerializer
from starlette.datastructures import Headers

from .exceptions import MissingTokenError, TokenValidationError
from .settings import CSRFSettings
from .utils import decode_token, encode_token

class CSRF:
  def __init__(
    self,
    settings: Type[CSRFSettings],
    secret: str,
    salt: Optional[str] = None,
    encoder: Optional[Callable] = encode_token,
    decoder: Optional[Callable] = decode_token
  ):
    '''
    Retrieve response object if jwt in the cookie
    :param settings: settings object for CSRF
    :param res: response from endpoint
    '''
    self.secret = secret
    self.salt = salt
    self.settings = settings

    self.__encoder = encoder
    self.__decoder = decoder

  @property
  def encode(self) -> Callable:
    return self.__encoder

  @property
  def decode(self) -> Callable:
    return self.__decoder

  def __call__(self, request: Request) -> str:
    return self.validate(request)

  def set_cookie(
    self,
    response: Optional[Response],
    session_id: Optional[str] = None,
    **options: Mapping[str, Any]
  ) -> Response:
    '''Put a CSRF cookie into the response using a session id or a random value.'''
    response.set_cookie(
      self.settings.CSRF_COOKIE_NAME,
      self.encode(self.secret, self.salt, session_id),
      max_age=options.get("max_age", self.settings.CSRF_MAX_AGE),
      path=options.get("path", self.settings.CSRF_COOKIE_PATH),
      domain=options.get("domain", self.settings.CSRF_COOKIE_DOMAIN),
      secure=options.get("secure", self.settings.CSRF_COOKIE_SECURE),
      httponly=options.get("httponly", self.settings.CSRF_COOKIE_HTTPONLY),
      samesite=options.get("samesite", self.settings.CSRF_COOKIE_SAMESITE.value)
    )
    return response

  def unset_cookie(self, response: Optional[Response], **options: Mapping[str, Any]) -> Response:
    '''Remove a csrf cookie from the response'''
    response.delete_cookie(
      self.settings.CSRF_COOKIE_NAME,
      path=options.get("path", self.settings.CSRF_COOKIE_PATH),
      domain=options.get("domain", self.CSRF_COOKIE_DOMAIN)
    )
    return response

  def validate(self, request: Request, time_limit: Optional[int] = None):
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
    if time_limit is None:
      time_limit = self.settings.CSRF_MAX_AGE

    token = request.cookies.get(self.settings.CSRF_COOKIE_NAME)
    if token is None:
      token = request.headers.get(self.settings.CSRF_HEADER_NAME)

    if token is None:
      raise MissingTokenError('The CSRF token is missing')

    return decode_token(token, self.secret, self.salt, time_limit)
