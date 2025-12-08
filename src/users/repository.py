from typing import Optional, Dict
from motor.motor_asyncio import AsyncIOMotorDatabase

class UserRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.collection = db["users"]

    async def insert_user(self, user_data: dict):
        return await self.collection.insert_one(user_data)

    async def find_one(self, query: dict) -> Optional[dict]:
        return await self.collection.find_one(query)

    async def update_one(self, filter_query: dict, update_data: dict):
        return await self.collection.update_one(filter_query, update_data)
