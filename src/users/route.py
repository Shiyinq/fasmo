from fastapi import APIRouter, Depends, BackgroundTasks 

from src import dependencies
from src.auth.schemas import UserCurrent
from src.auth.email_service import EmailService
from src.logging_config import create_logger
from src.users.schemas import UserCreate, UserCreateResponse, UserCreatedWithEmail, UserCreated
from src.users.service import UserService
from src.auth.service import AuthService
from src.dependencies import get_user_service, get_auth_service, get_email_service

router = APIRouter()

logger = create_logger("users", __name__)


@router.post("/users/signup", status_code=201, response_model=UserCreateResponse)
async def signup(
    user: UserCreate, 
    background_tasks: BackgroundTasks,
    user_service: UserService = Depends(get_user_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service)
):
    """
    Register a new user account.
    """
    # 1. Create User (Service Layer - Pure Business Logic)
    await user_service.create_user(user)
    
    # 2. Trigger Email Verification (Controller Layer - Usage of Framework "BackgroundTasks")
    try:
        token = await auth_service.create_email_verification_token(user.userId)
        background_tasks.add_task(
            email_service.send_email_verification, 
            user.email, 
            token, 
            user.username
        )
        logger.info(
            f"User created successfully and verification email sent: user_id={user.userId}"
        )
        return UserCreatedWithEmail()
    except Exception as e:
        logger.warning(f"User created but error sending verification email: {e}")
        # Don't fail the signup if email fails, return basic success message
        return UserCreated()


@router.get("/users/profile", response_model=UserCurrent)
async def user_profile(current_user=Depends(dependencies.get_current_user)):
    """
    Get the profile information of the currently logged-in user.

    Returns:
        UserCurrent: The current user's profile data.
    """

    
    return current_user
