#!/usr/bin/env python3
# Copyright (C) 2019-2020 All rights reserved.
# FILENAME:  base.py
# VERSION: 	 0.1.0
# CREATED: 	 2020-11-26 18:50
# AUTHOR: 	 Aekasitt Guruvanich <aekazitt@gmail.com>
# DESCRIPTION:
#
# HISTORY:
#*************************************************************
import unittest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fastapi_csrf import CsrfProtect, CSRFSettings, get_settings
from fastapi_csrf.exceptions import CsrfProtectError


def get_csrf(r: Request) -> CsrfProtect:
  return CsrfProtect("secret", get_settings())


class BaseTestCase(unittest.TestCase):

  def setUp(self):
    app = FastAPI()

    @app.get('/set-cookie')
    def cookie(csrf_protect: CsrfProtect = Depends(get_csrf)):
      response = JSONResponse(status_code=200, content={'detail': 'OK'})
      return csrf_protect.set_csrf_cookie(response)

    @app.get('/protected')
    def protected(request: Request, csrf_protect: CsrfProtect = Depends(get_csrf)):
      timeout = int(request.query_params["timeout"]) if "timeout" in request.query_params else None
      csrf_protect.validate_csrf(request, timeout)
      return JSONResponse(status_code=200, content={'detail': 'OK'})

    @app.exception_handler(CsrfProtectError)
    def csrf_protect_error_handler(request: Request, exc: CsrfProtectError):
      return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    self.settings = get_settings()
    self.client = TestClient(app)

  def tearDown(self):
    del self.client
