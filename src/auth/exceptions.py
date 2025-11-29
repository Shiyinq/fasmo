from src.auth.constants import DomainErrorCode


class IncorrectCredentialsError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.INCORRECT_CREDENTIALS
        super().__init__(self.message)


class InvalidRefreshTokenError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.INVALID_REFRESH_TOKEN
        super().__init__(self.message)


class RefreshTokenExpiredError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.REFRESH_TOKEN_EXPIRED
        super().__init__(self.message)


class SuspiciousActivityError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.SUSPICIOUS_ACTIVITY_DETECTED
        super().__init__(self.message)


class VerificationTokenInvalidError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.VERIFICATION_TOKEN_INVALID
        super().__init__(self.message)


class PasswordResetTokenInvalidError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.PASSWORD_RESET_TOKEN_INVALID
        super().__init__(self.message)


class PasswordsDoNotMatchError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.PASSWORDS_DO_NOT_MATCH
        super().__init__(self.message)


class PasswordPolicyViolationError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.PASSWORD_POLICY_VIOLATION
        super().__init__(self.message)