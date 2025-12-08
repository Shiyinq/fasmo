from datetime import datetime, timezone
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

class AuthRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.refresh_tokens = db["refresh_tokens"]
        self.login_history = db["login_history"]

    async def insert_refresh_token(self, data: dict):
        return await self.refresh_tokens.insert_one(data)

    async def find_refresh_token(self, token: str) -> Optional[dict]:
        return await self.refresh_tokens.find_one({"hashRefreshToken": token})

    async def update_refresh_token_last_used(self, token: str):
        return await self.refresh_tokens.update_one(
            {"hashRefreshToken": token},
            {"$set": {"lastUsedAt": datetime.now(timezone.utc).isoformat()}},
        )

    async def delete_refresh_token(self, token: str):
        return await self.refresh_tokens.delete_one({"hashRefreshToken": token})

    async def insert_login_history(self, data: dict):
        return await self.login_history.insert_one(data)

    async def find_last_login_history(self, user_id: str) -> Optional[dict]:
        return await self.login_history.find_one(
            {"userId": user_id}, sort=[("loginAt", -1)]
        )
