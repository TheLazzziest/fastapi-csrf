import unittest

from http import HTTPStatus
from time import sleep

from fastapi_csrf import CSRF

from .base import BaseTestCase


class ValidTokenTestCase(BaseTestCase):

  def test_valid_cookie_token(self, route='/protected'):
    response = self.client.get('/set-cookie')
    assert response.status_code == HTTPStatus.OK.value
    response = self.client.get(route, cookies=response.cookies)
    assert response.status_code == HTTPStatus.OK.value
    assert response.json()["detail"] == 'OK'

  def test_valid_header_token(self, route='/protected'):
    response = self.client.get('/set-cookie')
    assert response.status_code == HTTPStatus.OK.value
    csrf_cookie = response.cookies[self.settings.CSRF_COOKIE_NAME]
    del self.client.cookies[self.settings.CSRF_COOKIE_NAME]
    response = self.client.get(
      route,
      headers={
        self.settings.CSRF_HEADER_NAME: csrf_cookie
      }
    )
    assert response.status_code == HTTPStatus.OK.value
    assert response.json()["detail"] == 'OK'


class MissingTokenTestCase(BaseTestCase):

  def test_missing_token_request(self, route='/protected'):
    response = self.client.get(route)
    assert response.status_code == HTTPStatus.BAD_REQUEST.value
    assert response.json()['detail'] == 'The CSRF token is missing'

  def test_inlined_missing_token_request(self, route='/protected/inline'):
    response = self.client.get(route)
    assert response.status_code == HTTPStatus.BAD_REQUEST.value
    assert response.json()['detail'] == 'The CSRF token is missing'

class InvalidTokenTestCase(BaseTestCase):

  def test_token_invalid_request(self, route='/protected'):
    response = self.client.get(route, cookies={ self.settings.CSRF_COOKIE_NAME: 'invalid' })
    assert response.status_code == HTTPStatus.BAD_REQUEST.value
    assert response.json()["detail"] == 'The CSRF token is invalid.'
    
  def test_inlined_invalid_request(self, route='/protected/inline'):
    response = self.client.get(route, cookies={ self.settings.CSRF_COOKIE_NAME: 'invalid' })
    assert response.status_code == HTTPStatus.BAD_REQUEST.value
    assert response.json()['detail'] == 'The CSRF token is invalid.'


class TokenExpiredTestCase(BaseTestCase):

  def test_token_expired(self, route='/protected'):
    response = self.client.get('/set-cookie')
    assert response.status_code == HTTPStatus.OK.value
    sleep(2)
    response = self.client.get(route, params={"timeout": 0}, cookies=response.cookies)
    assert response.status_code == HTTPStatus.BAD_REQUEST.value
    assert response.json()['detail'] == 'The CSRF token has expired.'
