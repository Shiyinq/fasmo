from typing import List

from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    ENV: str = "dev"
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_MAX_AGE_DAYS: int = 30

    # DB
    MONGODB_URI: str
    DB_NAME: str = "fasmo"

    # External Auth
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    GOOGLE_REDIRECT_URI: str
    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: str
    GITHUB_REDIRECT_URI: str

    # Frontend
    FRONTEND_URL: str
    ORIGINS: str

    # Email
    RESEND_API_KEY: str
    EMAIL_FROM: str = "onboarding@resend.dev"
    EMAIL_VERIFICATION_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_EXPIRE_HOURS: int = 1

    # Security
    MAX_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15
    MAX_REQUESTS_PER_MINUTE: int = 60

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_PATH: str = "/var/log/fasmo/"

    # Internal
    API_KEY_PREFIX: str = "ffk_"

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=True
    )

    @property
    def is_env_dev(self) -> bool:
        return self.ENV == "dev"

    @computed_field
    @property
    def cors_origins(self) -> List[str]:
        if not self.ORIGINS:
            if self.is_env_dev:
                return ["http://localhost:5050", "http://localhost:5173"]
            else:
                raise ValueError(
                    "ORIGINS environment variable is required in production"
                )

        origins = [origin.strip() for origin in self.ORIGINS.split(",") if origin.strip()]

        if not self.is_env_dev:
            for origin in origins:
                if origin == "*":
                    raise ValueError("Wildcard (*) origins are not allowed in production")
                if not origin.startswith("https://"):
                    raise ValueError(
                        f"Only HTTPS origins allowed in production: {origin}"
                    )

        return origins

    @property
    def mongo_uri(self) -> str:
        return self.MONGODB_URI

    @property
    def db_name(self) -> str:
        return self.DB_NAME

    @property
    def secret_key(self) -> str:
        return self.SECRET_KEY

    @property
    def algorithm(self) -> str:
        return self.ALGORITHM

    @property
    def access_token_expire_minutes(self) -> int:
        return self.ACCESS_TOKEN_EXPIRE_MINUTES

    @property
    def refresh_token_max_age_days(self) -> int:
        return self.REFRESH_TOKEN_MAX_AGE_DAYS

    @property
    def google_client_id(self) -> str:
        return self.GOOGLE_CLIENT_ID

    @property
    def google_client_secret(self) -> str:
        return self.GOOGLE_CLIENT_SECRET

    @property
    def google_redirect_uri(self) -> str:
        return self.GOOGLE_REDIRECT_URI
    
    @property
    def github_client_id(self) -> str:
        return self.GITHUB_CLIENT_ID

    @property
    def github_client_secret(self) -> str:
        return self.GITHUB_CLIENT_SECRET

    @property
    def github_redirect_uri(self) -> str:
        return self.GITHUB_REDIRECT_URI

    @property
    def frontend_url(self) -> str:
        return self.FRONTEND_URL

    @property
    def resend_api_key(self) -> str:
        return self.RESEND_API_KEY
    
    @property
    def email_from(self) -> str:
        return self.EMAIL_FROM
    
    @property
    def email_verification_expire_hours(self) -> int:
        return self.EMAIL_VERIFICATION_EXPIRE_HOURS
    
    @property
    def password_reset_expire_hours(self) -> int:
        return self.PASSWORD_RESET_EXPIRE_HOURS
    
    @property
    def max_login_attempts(self) -> int:
        return self.MAX_LOGIN_ATTEMPTS
    
    @property
    def account_lockout_minutes(self) -> int:
        return self.ACCOUNT_LOCKOUT_MINUTES
    
    @property
    def max_requests_per_minute(self) -> int:
        return self.MAX_REQUESTS_PER_MINUTE
    
    @property
    def log_level(self) -> str:
        return self.LOG_LEVEL
    
    @property
    def log_path(self) -> str:
        return self.LOG_PATH
    
    @property
    def api_key_prefix(self) -> str:
        return self.API_KEY_PREFIX


config = Settings()
