from fastapi import APIRouter, Depends 

from src import dependencies
from src.auth.schemas import UserCurrent
from src.auth.email_service import EmailService
from src.logging_config import create_logger
from src.users.schemas import UserCreate, UserCreateResponse, UserCreatedWithEmail, UserCreated
from src.users.service import UserService
from src.users.service import UserService
# AuthService and EmailService removed from imports as they are used internally by UserService
from src.dependencies import get_user_service

router = APIRouter()

logger = create_logger("users", __name__)


@router.post("/users/signup", status_code=201, response_model=UserCreateResponse)
@router.post("/users/signup", status_code=201, response_model=UserCreateResponse)
async def signup(
    user: UserCreate, 
    user_service: UserService = Depends(get_user_service)
):
    """
    Register a new user account.
    """
    # Create User (Service Layer handles both creation and email verification trigger)
    result = await user_service.create_user(user)
    
    if isinstance(result, UserCreatedWithEmail):
        logger.info(f"User created successfully and verification email sent: user_id={user.userId}")
    else:
        logger.info(f"User created successfully: user_id={user.userId}")
        
    return result


@router.get("/users/profile", response_model=UserCurrent)
async def user_profile(current_user=Depends(dependencies.get_current_user)):
    """
    Get the profile information of the currently logged-in user.

    Returns:
        UserCurrent: The current user's profile data.
    """

    
    return current_user
