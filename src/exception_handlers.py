from fastapi import Request
from fastapi.responses import JSONResponse

from src.exceptions import DomainException
from src.http_exceptions import DetailedHTTPException
from src.logging_config import create_logger

# Users Exceptions
from src.users.exceptions import (
    UserCreationError,
    UsernameAlreadyExistsError,
    EmailAlreadyExistsError,
    ProviderUserCreationError,
)
from src.users.http_exceptions import (
    UsernameTaken,
    EmailTaken,
    ServerError,
)

# Auth Exceptions
from src.auth.exceptions import (
    IncorrectCredentialsError,
    InvalidRefreshTokenError,
    RefreshTokenExpiredError,
    SuspiciousActivityError,
    VerificationTokenInvalidError,
    PasswordResetTokenInvalidError,
    PasswordsDoNotMatchError,
    PasswordPolicyViolationError,
)
from src.auth.http_exceptions import (
    IncorrectEmailOrPassword,
    InvalidRefreshToken,
    RefreshTokenExpired,
    SuspiciousActivity,
    VerificationTokenInvalid,
    PasswordResetTokenInvalid,
    PasswordsNotMatch,
    PasswordPolicyViolation,
)

# API Keys Exceptions
from src.api_keys.exceptions import (
    APIKeyCreationError,
    APIKeyDeletionError,
    APIKeyNotFoundError,
)
from src.api_keys.http_exceptions import (
    APIKeyCreateError,
    APIKeyDeleteError,
    APIKeyNotFound,
)

# Create central logger for exceptions
logger = create_logger("exceptions", __name__)


async def domain_exception_handler(request: Request, exc: DomainException):
    # Log the exception with context
    logger.warning(
        f"Domain exception occurred: type={type(exc).__name__}, message={str(exc)}, path={request.url.path}"
    )

    # Users
    if isinstance(exc, UsernameAlreadyExistsError):
        return await detailed_http_exception_handler(request, UsernameTaken())
    if isinstance(exc, EmailAlreadyExistsError):
        return await detailed_http_exception_handler(request, EmailTaken())
    if isinstance(exc, (UserCreationError, ProviderUserCreationError)):
        # For server errors, we might want to log as error instead of warning
        logger.error(f"Critical domain error: {str(exc)}")
        return await detailed_http_exception_handler(request, ServerError())

    # Auth
    if isinstance(exc, IncorrectCredentialsError):
        return await detailed_http_exception_handler(request, IncorrectEmailOrPassword())
    if isinstance(exc, InvalidRefreshTokenError):
        return await detailed_http_exception_handler(request, InvalidRefreshToken())
    if isinstance(exc, RefreshTokenExpiredError):
        return await detailed_http_exception_handler(request, RefreshTokenExpired())
    if isinstance(exc, SuspiciousActivityError):
        logger.error(f"Suspicious activity detected: {str(exc)}")
        return await detailed_http_exception_handler(request, SuspiciousActivity())
    if isinstance(exc, VerificationTokenInvalidError):
        return await detailed_http_exception_handler(request, VerificationTokenInvalid())
    if isinstance(exc, PasswordResetTokenInvalidError):
        return await detailed_http_exception_handler(request, PasswordResetTokenInvalid())
    if isinstance(exc, PasswordsDoNotMatchError):
        return await detailed_http_exception_handler(request, PasswordsNotMatch())
    if isinstance(exc, PasswordPolicyViolationError):
        return await detailed_http_exception_handler(request, PasswordPolicyViolation())

    # API Keys
    if isinstance(exc, APIKeyCreationError):
        return await detailed_http_exception_handler(request, APIKeyCreateError())
    if isinstance(exc, APIKeyDeletionError):
        return await detailed_http_exception_handler(request, APIKeyDeleteError())
    if isinstance(exc, APIKeyNotFoundError):
        return await detailed_http_exception_handler(request, APIKeyNotFound())

    # Default fallback
    logger.error(f"Unhandled domain exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )


async def detailed_http_exception_handler(request: Request, exc: DetailedHTTPException):
    return JSONResponse(
        status_code=exc.STATUS_CODE,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None),
    )
