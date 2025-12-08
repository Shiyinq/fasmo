from typing import Dict, Union

from fastapi import BackgroundTasks
from pymongo.errors import DuplicateKeyError

from src.auth.service import AuthService
from src.logging_config import create_logger
from src.users.repository import UserRepository
from src.users.constants import Info
from src.users.exceptions import (
    UserCreationError,
    UsernameAlreadyExistsError,
    EmailAlreadyExistsError,
    ProviderUserCreationError
)
from src.users.schemas import ProviderUserCreate, UserCreate, UserCreated, UserCreatedWithEmail

logger = create_logger("users_service", __name__)

class UserService:
    def __init__(self, user_repo: UserRepository, auth_service: AuthService):
        self.user_repo = user_repo
        self.auth_service = auth_service

    async def base_create_user(self, user) -> UserCreated:
        try:
            user_data = user.to_dict()
            # Normalize to lowercase
            if "username" in user_data:
                user_data["username"] = user_data["username"].lower()
            if "email" in user_data:
                user_data["email"] = user_data["email"].lower()
                
            if "password" in user_data:
                user_data["password"] = await self.auth_service.get_password_hash(user_data["password"])
                
            await self.user_repo.insert_user(user_data)
            return UserCreated()
        except DuplicateKeyError as dk:
            dk = str(dk)
            if "username" in dk:
                raise UsernameAlreadyExistsError()
            elif "email" in dk:
                raise EmailAlreadyExistsError()
        except Exception as e:
            logger.exception(f"Unexpected error in base_create_user: {str(e)}")
            raise UserCreationError()


    async def create_user(self, user: UserCreate, background_tasks: BackgroundTasks) -> Union[UserCreatedWithEmail, UserCreated]:
        await self.base_create_user(user)

        # Send email verification for regular signup
        try:
            await self.auth_service.send_email_verification(user.userId, user.email, user.username, background_tasks)
            # Return success message with email verification info
            return UserCreatedWithEmail()
        except Exception as e:
            logger.warning(f"Error sending verification email: {e}")
            # Don't fail the signup if email fails, return basic success message
            return UserCreated()


    async def create_user_provider(self, user: ProviderUserCreate) -> UserCreated:
        # For provider users, mark email as verified since it's already verified by the provider
        try:
            user_data = user.to_dict()
            # Normalize to lowercase
            if "username" in user_data:
                user_data["username"] = user_data["username"].lower()
            if "email" in user_data:
                user_data["email"] = user_data["email"].lower()
                
            user_data["isEmailVerified"] = True
            user_data["provider"] = user.provider
            await self.user_repo.insert_user(user_data)
            return UserCreated()
        except DuplicateKeyError as dk:
            dk = str(dk)
            if "username" in dk:
                raise UsernameAlreadyExistsError()
            elif "email" in dk:
                raise EmailAlreadyExistsError()
        except Exception as e:
            logger.exception(f"Unexpected error in create_user_provider: {str(e)}")
            raise ProviderUserCreationError()
