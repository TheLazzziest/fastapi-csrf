import unittest

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fastapi_csrf import CSRF, CSRFSettings, get_settings
from fastapi_csrf.exceptions import CSRFError


def get_csrf(r: Request) -> CSRF:
  return r.app.csrf

def validate_csrf_token(r: Request) -> str:
  return r.app.csrf(r)


class BaseTestCase(unittest.TestCase):

  def setUp(self):
    app = FastAPI()
    app.csrf = CSRF(get_settings(), "secret")

    @app.get('/set-cookie')
    def cookie(csrf: CSRF = Depends(get_csrf)):
      return csrf.set_cookie(
        JSONResponse(status_code=200, content={'detail': 'OK'})
      )

    @app.get('/protected')
    def protected(request: Request, csrf: CSRF = Depends(get_csrf)):
      timeout = int(request.query_params["timeout"]) if "timeout" in request.query_params else None
      token = csrf.validate(request, timeout)
      return JSONResponse(status_code=200, content={'detail': 'OK'})

    @app.get('/protected/inline')
    def protected(request: Request, token: str = Depends(validate_csrf_token)):
      return JSONResponse(status_code=200, content={'detail': 'OK'})

    @app.exception_handler(CSRFError)
    def csrf_protect_error_handler(request: Request, exc: CSRFError):
      return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    self.settings = get_settings()
    self.client = TestClient(app)

  def tearDown(self):
    del self.client
