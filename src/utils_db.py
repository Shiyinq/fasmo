import asyncio
from src.database import database_instance
from src.logging_config import create_logger

logger = create_logger("database_indexes", __name__)

async def create_indexes():
    """Create database indexes."""
    try:
        db = database_instance.database
        
        # User indexes
        await db["users"].create_index("userId", unique=True)
        await db["users"].create_index("username", unique=True)
        await db["users"].create_index("email", unique=True)
        
        # Refresh token indexes
        await db["refresh_tokens"].create_index("hashRefreshToken", unique=True)
        await db["refresh_tokens"].create_index("userId")
        # Automatic expiry for tokens
        await db["refresh_tokens"].create_index("createdAt", expireAfterSeconds=30 * 24 * 60 * 60) # 30 days
        
        # API Keys indexes
        await db["api_keys"].create_index("userId")
        # Compound index for user and prefix if needed
        
        logger.info("Database indexes created successfully")
    except Exception as e:
        logger.exception(f"Failed to create indexes: {str(e)}")
