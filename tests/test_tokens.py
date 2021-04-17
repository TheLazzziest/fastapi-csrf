import unittest

from http import HTTPStatus
from time import sleep

from fastapi_csrf import CsrfProtect

from .base import BaseTestCase


class ValidTokenTestCase(BaseTestCase):

  def test_valid_token(self, route='/protected'):
    response = self.client.get('/set-cookie')
    assert response.status_code == HTTPStatus.OK.value
    response = self.client.get(route, cookies=response.cookies)
    assert response.status_code == HTTPStatus.OK.value
    assert response.json()["detail"] == 'OK'


class MissingTokenTestCase(BaseTestCase):

  def test_missing_token_request(self, route='/protected'):
    response = self.client.get(route)
    assert response.status_code == HTTPStatus.BAD_REQUEST.value
    assert response.json()['detail'] == 'The CSRF token is missing'


class InvalidTokenTestCase(BaseTestCase):

  def test_token_invalid_request(self, route='/protected'):
    response = self.client.get(route, cookies={ self.settings.CSRF_COOKIE_NAME: 'invalid' })
    assert response.status_code == HTTPStatus.BAD_REQUEST.value
    assert response.json()["detail"] == 'The CSRF token is invalid.'


class TokenExpiredTestCase(BaseTestCase):

  def test_token_expired(self, route='/protected'):
    response = self.client.get('/set-cookie')
    assert response.status_code == HTTPStatus.OK.value
    sleep(2)
    response = self.client.get(route, params={"timeout": 0}, cookies=response.cookies)
    assert response.status_code == HTTPStatus.BAD_REQUEST.value
    assert response.json()['detail'] == 'The CSRF token has expired.'
