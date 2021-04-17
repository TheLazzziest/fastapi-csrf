#!/usr/bin/env python3
# Copyright (C) 2019-2020 All rights reserved.
# FILENAME:  core.py
# VERSION: 	 0.0.1
# CREATED: 	 2020-11-25 14:35
# AUTHOR: 	 Aekasitt Guruvanich <aekazitt@gmail.com>
# DESCRIPTION:
#
# HISTORY:
#*************************************************************
from typing import Any, Mapping, Optional

from fastapi import Request
from fastapi.responses import Response
from itsdangerous import BadData, SignatureExpired, URLSafeTimedSerializer
from starlette.datastructures import Headers

from .exceptions import MissingTokenError, TokenValidationError
from .settings import CSRFSettings
from .utils import decode_token, encode_token

class CsrfProtect:
  def __init__(self, secret: str, settings: CSRFSettings):
    '''
    Retrieve response object if jwt in the cookie
    :param req: all incoming request
    :param res: response from endpoint
    '''
    self.secret = secret
    self.settings = settings

  def set_csrf_cookie(self, response: Optional[Response], session_id: Optional[str] = None,  **options: Mapping[str, Any]) -> Response:
    """Generate a CSRF token based on """
    response.set_cookie(
      self.settings.CSRF_COOKIE_NAME,
      encode_token(session_id, self.secret),
      max_age=options.get("max_age", self.settings.CSRF_MAX_AGE),
      path=options.get("path", self.settings.CSRF_COOKIE_PATH),
      domain=options.get("domain", self.settings.CSRF_COOKIE_DOMAIN),
      secure=options.get("secure", self.settings.CSRF_COOKIE_SECURE),
      httponly=options.get("httponly", self.settings.CSRF_COOKIE_HTTPONLY),
      samesite=options.get("samesite", self.settings.CSRF_COOKIE_SAMESITE.value)
    )
    return response

  def unset_csrf_cookie(self, response: Optional[Response]= None, **options: Mapping[str, Any]) -> Response:
    '''
    Remove Csrf Protection token from the response cookies
    :param response: The FastAPI response object to delete the access cookies in.
    '''
    if response and not isinstance(response,Response):
      raise TypeError('The response must be an object response FastAPI')
    response = response or self._response
    response.delete_cookie(
      self.settings.CSRF_COOKIE_NAME,
      path=options.get("path", self.settings.CSRF_COOKIE_PATH),
      domain=options.get("domain", self.CSRF_COOKIE_DOMAIN)
    )
    return response

  def validate_csrf(self, request: Request, time_limit: Optional[int] = None):
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

    return decode_token(token, self.secret, max_age=time_limit)
