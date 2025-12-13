from src.config import config
from src.database import database_instance
from src.logging_config import create_logger

logger = create_logger("database_indexes", __name__)


async def create_indexes():
    """Create database indexes."""
    try:
        db = database_instance.database

        await db["users"].create_index("userId", unique=True)
        await db["users"].create_index("username", unique=True)
        await db["users"].create_index("email", unique=True)

        await db["refresh_tokens"].create_index("hashRefreshToken", unique=True)
        await db["refresh_tokens"].create_index("userId")

        expire_seconds = config.refresh_token_max_age_days * 24 * 60 * 60
        await db["refresh_tokens"].create_index(
            "createdAt", expireAfterSeconds=expire_seconds
        )

        await db["api_keys"].create_index("userId")

        await db["verification_tokens"].create_index("userId")
        await db["verification_tokens"].create_index("hashToken", unique=True)
        await db["verification_tokens"].create_index("expiresAt", expireAfterSeconds=0)

        logger.info("Database indexes created successfully")
    except Exception as e:
        logger.exception(f"Failed to create indexes: {str(e)}")
