from typing import Dict, Union

from fastapi import BackgroundTasks
from pymongo.errors import DuplicateKeyError

from src.auth.service import send_email_verification
from src.logging_config import create_logger
from src.users import repository
from src.users.constants import Info
from src.users.exceptions import (
    UserCreationError,
    UsernameAlreadyExistsError,
    EmailAlreadyExistsError,
    ProviderUserCreationError
)
from src.users.schemas import ProviderUserCreate, UserCreate, UserCreated, UserCreatedWithEmail

logger = create_logger("users_service", __name__)


async def base_create_user(user) -> UserCreated:
    try:
        user_data = user.to_dict()
        # Normalize to lowercase
        if "username" in user_data:
            user_data["username"] = user_data["username"].lower()
        if "email" in user_data:
            user_data["email"] = user_data["email"].lower()
            
        await repository.insert_user(user_data)
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


async def create_user(user: UserCreate, background_tasks: BackgroundTasks) -> Union[UserCreatedWithEmail, UserCreated]:
    await base_create_user(user)

    # Send email verification for regular signup
    try:
        await send_email_verification(user.userId, user.email, user.username, background_tasks)
        # Return success message with email verification info
        return UserCreatedWithEmail()
    except Exception as e:
        logger.warning(f"Error sending verification email: {e}")
        # Don't fail the signup if email fails, return basic success message
        return UserCreated()


async def create_user_provider(user: ProviderUserCreate) -> UserCreated:
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
        await repository.insert_user(user_data)
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
