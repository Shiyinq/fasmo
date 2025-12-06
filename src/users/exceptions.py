from src.users.constants import DomainErrorCode
from src.exceptions import DomainException


class UserCreationError(DomainException):
    ERROR_CODE = DomainErrorCode.USER_CREATION_FAILED


class UsernameAlreadyExistsError(UserCreationError):
    ERROR_CODE = DomainErrorCode.USERNAME_ALREADY_EXISTS


class EmailAlreadyExistsError(UserCreationError):
    ERROR_CODE = DomainErrorCode.EMAIL_ALREADY_EXISTS


class ProviderUserCreationError(UserCreationError):
    ERROR_CODE = DomainErrorCode.PROVIDER_USER_CREATION_FAILED


class AccountLocked(DomainException):
    ERROR_CODE = DomainErrorCode.ACCOUNT_LOCKED


class EmailNotVerified(DomainException):
    ERROR_CODE = DomainErrorCode.EMAIL_NOT_VERIFIED
