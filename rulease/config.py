"""Validated configuration for the PostgreSQL-only v2 platform."""
from ipaddress import ip_network
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='RULEASE_', extra='ignore')
    database_url: str
    secret_key: SecretStr
    public_url: str = 'http://127.0.0.1:8000'
    production: bool = False
    cookie_secure: bool = True
    max_context_bytes: int = Field(default=65536, ge=1, le=1048576)
    max_source_bytes: int = Field(default=262144, ge=1, le=1048576)
    max_batch_size: int = Field(default=100, ge=1, le=1000)
    max_body_bytes: int = Field(default=1048576, ge=1)
    trusted_proxies: list[str] = Field(default_factory=list)
    login_ip_limit: int = Field(default=60, ge=1, le=10000)
    login_username_limit: int = Field(default=10, ge=1, le=1000)
    login_window_seconds: int = Field(default=900, ge=1, le=86400)
    retention_days: int = Field(default=30, ge=1)

    @model_validator(mode='after')
    def validate_server(self):
        self.trusted_proxies = [str(ip_network(value, strict=False)) for value in self.trusted_proxies]
        if make_url(self.database_url).get_backend_name() != 'postgresql':
            raise ValueError('Rulease v2 server requires PostgreSQL')
        if len(self.secret_key.get_secret_value().encode()) < 32:
            raise ValueError('RULEASE_SECRET_KEY must contain at least 32 bytes')
        if self.production and (not self.cookie_secure or not self.public_url.startswith('https://')):
            raise ValueError('Production requires secure cookies and an HTTPS public URL')
        return self
