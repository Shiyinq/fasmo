from typing import Dict, Union
import asyncio
from src.utils import hash_token

from fastapi import BackgroundTasks
from pymongo.errors import DuplicateKeyError

from src.auth.security_service import SecurityService
from src.logging_config import create_logger
from src.users.repository import UserRepository
from src.users.constants import Info
from src.users.exceptions import (
    UserCreationError,
    UsernameAlreadyExistsError,
    EmailAlreadyExistsError,
    EmailAlreadyExistsError,
    ProviderUserCreationError
)
from src.auth.email_service import EmailService
from src.users.schemas import ProviderUserCreate, UserCreate, UserCreated, UserCreatedWithEmail

logger = create_logger("users_service", __name__)

class UserService:
    def __init__(self, user_repo: UserRepository, security_service: SecurityService, email_service: EmailService):
        self.user_repo = user_repo
        self.security_service = security_service
        self.email_service = email_service

    async def base_create_user(self, user: UserCreate) -> UserCreated:
        try:
            user_data = user.to_dict()
            # Normalize to lowercase
            if "username" in user_data:
                user_data["username"] = user_data["username"].lower()
            if "email" in user_data:
                user_data["email"] = user_data["email"].lower()
                
            if "password" in user_data:
                # Use SecurityService instance
                user_data["password"] = await asyncio.to_thread(self.security_service.get_password_hash, user_data["password"])
                
            await self.user_repo.insert_user(user_data)
            return UserCreated()
        except DuplicateKeyError as dk:
            # Check keyPattern if available (robust way)
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
        # 1. Create User
        await self.base_create_user(user)

        # 2. Trigger Email Verification
        try:
            # Logic similar to AuthService.create_email_verification_token
            # We use security_service directly to avoid circular dependency with AuthService
            token = self.security_service.create_token()
            token_hash = hash_token(token)
            # We need config here, ensure it's imported
            from src.config import config
            await self.security_service.save_token(
                user.userId, token_hash, "email_verification", config.email_verification_expire_hours
            )
            
            await self.email_service.send_email_verification(
                user.email,
                token,
                user.username
            )
            return UserCreatedWithEmail()
        except Exception as e:
            logger.warning(f"User created but error sending verification email: {e}")
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
            # Check keyPattern if available (robust way)
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
