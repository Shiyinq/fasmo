from src.api_keys.constants import DomainErrorCode


class APIKeyCreationError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.API_KEY_CREATION_FAILED
        super().__init__(self.message)


class APIKeyDeletionError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.API_KEY_DELETION_FAILED
        super().__init__(self.message)


class APIKeyNotFoundError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.API_KEY_NOT_FOUND
        super().__init__(self.message)


class InvalidAPIKeyError(Exception):
    def __init__(self):
        self.message = DomainErrorCode.INVALID_API_KEY
        super().__init__(self.message)