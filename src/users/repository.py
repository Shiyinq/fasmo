from src.database import database_instance


async def insert_user(user_data: dict):
    return await database_instance.database["users"].insert_one(user_data)
