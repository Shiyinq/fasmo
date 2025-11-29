from src.users.constants import DomainErrorCode


class UserCreationError(Exception):
    def __init__(self, message: str = None):
        self.message = message or DomainErrorCode.USER_CREATION_FAILED
        super().__init__(self.message)


class UsernameAlreadyExistsError(UserCreationError):
    def __init__(self):
        super().__init__(DomainErrorCode.USERNAME_ALREADY_EXISTS)


class EmailAlreadyExistsError(UserCreationError):
    def __init__(self):
        super().__init__(DomainErrorCode.EMAIL_ALREADY_EXISTS)


class ProviderUserCreationError(UserCreationError):
    def __init__(self):
        super().__init__(DomainErrorCode.PROVIDER_USER_CREATION_FAILED)


class AccountLocked(Exception):
    def __init__(self):
        self.message = "Account is locked"
        super().__init__(self.message)


class EmailNotVerified(Exception):
    def __init__(self):
        self.message = "Email not verified"
        super().__init__(self.message)
