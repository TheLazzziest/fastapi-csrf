# FastAPI CSRF Protect

[![Build Status](https://travis-ci.com/aekazitt/fastapi-csrf-protect.svg?branch=master)](https://travis-ci.com/aekazitt/fastapi-csrf-protect)
[![Package Vesion](https://img.shields.io/pypi/v/fastapi-csrf-protect)](https://pypi.org/project/fastapi-csrf-protect)
[![Format](https://img.shields.io/pypi/format/fastapi-csrf-protect)](https://pypi.org/project/fastapi-csrf-protect)
[![Python Version](https://img.shields.io/pypi/pyversions/fastapi-csrf-protect)](https://pypi.org/project/fastapi-csrf-protect)
[![License](https://img.shields.io/pypi/l/fastapi-csrf-protect)](https://pypi.org/project/fastapi-csrf-protect)

FastAPI extension that provides Cross-Site Request Forgery (XSRF) Protection support (easy to use and lightweight).
This extension inspired by `fastapi-jwt-auth` 😀 .

## Features

- Processing a csrf token passed by cookies or headers
- Generate a random token or use a user defined session id as a seed
- Support a user defined implementation of a token encoder/decoder

## Installation

The easiest way to start working with this extension with pip

```bash
pip install fastapi-csrf-protect
```

## Usage

### With Context and Headers

```python

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from fastapi_csrf import CSRF, CSRFError, encode_token, get_settings
from pydantic import BaseModel

app = FastAPI()
app.csrf = CSRF("asecret", get_settings())
templates = Jinja2Templates(directory='templates')

def get_csrf(r: Request) -> CsrfProtect:
  return r.app.csrf

@app.get('/form')
def form(request: Request, csrf: CSRF = Depends(get_csrf)):
  '''
  Returns form template.
  '''
  response = templates.TemplateResponse('form.html', {
    'request': request, 'csrf_token': csrf.encode(secret_key, session_id="session_id")
  })
  return response

@app.post('/posts', response_class=JSONResponse)
def create_post(request: Request, csrf: CSRF = Depends(get_csrf)):
  '''
  Creates a new Post
  '''
  csrf_token = csrf_protect.validate_csrf(request, 3600)
  # Do stuff

@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
  return JSONResponse(
    status_code=exc.status_code,
      content={ 'detail':  exc.message
    }
  )

```

### With Cookies

```python
from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CSRF, CSRFError, get_settings
from pydantic import BaseModel

app = FastAPI()
app.csrf = CSRF("asecret", get_settings())
templates = Jinja2Templates(directory='templates')

def get_csrf(r: Request) -> CSRF:
  return r.app.csrf

def validate_csrf_token(r: Request) -> str:
  return r.app.csrf(r)

@app.get('/form')
def form(request: Request, csrf: CSRF = Depends(validate_csrf_token)):
  '''
  Returns form template.
  '''
  return csrf.set_cookie(
    templates.TemplateResponse('form.html', { 'request': request })
  )

@app.post('/posts', response_class=JSONResponse)
def create_post(request: Request, token: str = Depends(validate_csrf_token)):
  '''
  Creates a new Post
  '''
  # Do stuff

@app.exception_handler(CSRFError)
def csrf_protect_exception_handler(request: Request, exc: CSRFError):
  return JSONResponse(status_code=exc.status_code, content={ 'detail':  exc.message })

```

## License

This project is licensed under the terms of the MIT license.
