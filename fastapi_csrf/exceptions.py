from http import HTTPStatus


class CSRFError(Exception):
  def __init__(self, status_code, message):
    self.status_code = status_code
    self.message = message


class MissingTokenError(CSRFError):
  def __init__(self, message):
    super().__init__(HTTPStatus.BAD_REQUEST.value, message)


class TokenValidationError(CSRFError):
  def __init__(self, message):
    super().__init__(HTTPStatus.BAD_REQUEST.value, message)
