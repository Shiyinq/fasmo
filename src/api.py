from fastapi import APIRouter

from src.auth.route import router as auth_router
from src.users.route import router as user_router

router = APIRouter()

router.include_router(auth_router, tags=["Auth"])
router.include_router(user_router, tags=["Users"])
