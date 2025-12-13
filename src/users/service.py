import asyncio

from pymongo.errors import DuplicateKeyError

from src.auth.email_service import EmailService
from src.auth.security_service import SecurityService
from src.config import Settings
from src.logging_config import create_logger
from src.users.exceptions import (
    EmailAlreadyExistsError,
    ProviderUserCreationError,
    UserCreationError,
    UsernameAlreadyExistsError,
)
from src.users.repository import UserRepository
from src.users.schemas import (
    ProviderUserCreate,
    UserCreate,
    UserCreated,
    UserCreatedWithEmail,
)

logger = create_logger("users_service", __name__)


class UserService:
    def __init__(
        self,
        user_repo: UserRepository,
        security_service: SecurityService,
        email_service: EmailService,
        config: Settings,
    ):
        self.user_repo = user_repo
        self.security_service = security_service
        self.email_service = email_service
        self.config = config

    async def base_create_user(self, user: UserCreate) -> UserCreated:
        try:
            user_data = user.to_dict()

            if "username" in user_data:
                user_data["username"] = user_data["username"].lower()
            if "email" in user_data:
                user_data["email"] = user_data["email"].lower()

            if "password" in user_data:
                user_data["password"] = await asyncio.to_thread(
                    self.security_service.get_password_hash, user_data["password"]
                )

            await self.user_repo.insert_user(user_data)
            return UserCreated()
        except DuplicateKeyError as dk:
            if dk.details and "keyPattern" in dk.details:
                keys = dk.details["keyPattern"]
                if "username" in keys:
                    raise UsernameAlreadyExistsError()
                elif "email" in keys:
                    raise EmailAlreadyExistsError()

            # Fallback for some mongo versions or mock
            dk_str = str(dk)
            if "username" in dk_str:
                raise UsernameAlreadyExistsError()
            elif "email" in dk_str:
                raise EmailAlreadyExistsError()
        except Exception as e:
            logger.exception(f"Unexpected error in base_create_user: {str(e)}")
            raise UserCreationError()

    async def create_user(self, user: UserCreate) -> UserCreated:
        """
        Create a new user and trigger email verification.
        """

        await self.base_create_user(user)

        try:
            token = await self.security_service.create_and_save_token(
                user.userId,
                "email_verification",
                self.config.email_verification_expire_hours,
            )

            await self.email_service.send_email_verification(
                user.email, token, user.username
            )
            return UserCreatedWithEmail()
        except Exception as e:
            logger.warning(f"User created but error sending verification email: {e}")
            return UserCreated()

    async def create_user_provider(self, user: ProviderUserCreate) -> UserCreated:
        try:
            user_data = user.to_dict()

            if "username" in user_data:
                user_data["username"] = user_data["username"].lower()
            if "email" in user_data:
                user_data["email"] = user_data["email"].lower()

            user_data["isEmailVerified"] = True
            user_data["provider"] = user.provider
            await self.user_repo.insert_user(user_data)
            return UserCreated()
        except DuplicateKeyError as dk:
            if dk.details and "keyPattern" in dk.details:
                keys = dk.details["keyPattern"]
                if "username" in keys:
                    raise UsernameAlreadyExistsError()
                elif "email" in keys:
                    raise EmailAlreadyExistsError()

            dk = str(dk)
            if "username" in dk:
                raise UsernameAlreadyExistsError()
            elif "email" in dk:
                raise EmailAlreadyExistsError()
        except Exception as e:
            logger.exception(f"Unexpected error in create_user_provider: {str(e)}")
            raise ProviderUserCreationError()
