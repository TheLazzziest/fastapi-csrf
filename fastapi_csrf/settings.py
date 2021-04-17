from typing import Sequence, Optional
from functools import cached_property, lru_cache
from pydantic import validator, BaseSettings, ValidationError

from .enums import SameSiteEnum


class CSRFSettings(BaseSettings):
  'CSRF settings'

  # Common settings
  CSRF_SECRET_KEY: str = None
  CSRF_MAX_AGE: int = 3600
  # Header settings
  CSRF_HEADER_NAME: str = 'X-CSRF-Token'
  CSRF_HTTP_METHODS: Sequence[str] = { 'POST', 'PUT', 'PATCH', 'DELETE' }
  # Cookie settings
  CSRF_COOKIE_NAME: str = 'FAPICSRFTOKEN'
  CSRF_COOKIE_PATH: str = '/'
  CSRF_COOKIE_DOMAIN: str = None
  CSRF_COOKIE_SECURE: bool = False
  CSRF_COOKIE_SAMESITE: Optional[SameSiteEnum] = SameSiteEnum.none.value
  CSRF_COOKIE_HTTPONLY: bool = True

  @validator('CSRF_HTTP_METHODS', each_item=True, allow_reuse=True)
  def validate_csrf_methods(cls, v: Optional[str]) -> str:
    method = v.upper()
    if method not in {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH'}:
      raise ValueError(f"The method {method} is not allowed")
    return method

  @validator('CSRF_COOKIE_SAMESITE', pre=True, allow_reuse=True)
  def validate_cookie_samesite(cls, v: Optional[str]) -> SameSiteEnum:
    if v not in {'strict', 'lax', 'none'}:
      raise ValueError(f"Value {v} for SAMESITE must be one of the following: 'strict', 'lax', 'none'")
    return SameSiteEnum(v)


@lru_cache
def get_settings() -> CSRFSettings:
  return CSRFSettings()
