from fastapi import APIRouter, Depends, BackgroundTasks 

from src import dependencies
from src.auth.schemas import UserCurrent
from src.logging_config import create_logger
from src.users.schemas import UserCreate, UserCreateResponse
from src.users.service import UserService
from src.dependencies import get_user_service

router = APIRouter()

logger = create_logger("users", __name__)


@router.post("/users/signup", status_code=201, response_model=UserCreateResponse)
async def signup(
    user: UserCreate, 
    background_tasks: BackgroundTasks,
    user_service: UserService = Depends(get_user_service)
):
    """
    Register a new user account.
    """
    new_user = await user_service.create_user(user, background_tasks)
    
    logger.info(
        f"User created successfully: user_id={getattr(new_user, 'userId', None)}"
    )
    return new_user


@router.get("/users/profile", response_model=UserCurrent)
async def user_profile(current_user=Depends(dependencies.get_current_user)):
    """
    Get the profile information of the currently logged-in user.

    Returns:
        UserCurrent: The current user's profile data.
    """

    
    return current_user
