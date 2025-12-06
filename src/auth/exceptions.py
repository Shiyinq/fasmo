from src.auth.constants import DomainErrorCode
from src.exceptions import DomainException


class IncorrectCredentialsError(DomainException):
    ERROR_CODE = DomainErrorCode.INCORRECT_CREDENTIALS


class InvalidRefreshTokenError(DomainException):
    ERROR_CODE = DomainErrorCode.INVALID_REFRESH_TOKEN


class RefreshTokenExpiredError(DomainException):
    ERROR_CODE = DomainErrorCode.REFRESH_TOKEN_EXPIRED


class SuspiciousActivityError(DomainException):
    ERROR_CODE = DomainErrorCode.SUSPICIOUS_ACTIVITY_DETECTED


class VerificationTokenInvalidError(DomainException):
    ERROR_CODE = DomainErrorCode.VERIFICATION_TOKEN_INVALID


class PasswordResetTokenInvalidError(DomainException):
    ERROR_CODE = DomainErrorCode.PASSWORD_RESET_TOKEN_INVALID


class PasswordsDoNotMatchError(DomainException):
    ERROR_CODE = DomainErrorCode.PASSWORDS_DO_NOT_MATCH


class PasswordPolicyViolationError(DomainException):
    ERROR_CODE = DomainErrorCode.PASSWORD_POLICY_VIOLATION