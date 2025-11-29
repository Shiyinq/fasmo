from fastapi import APIRouter, Depends, Request

from src.config import config
from src.api_keys import service
from src.api_keys.exceptions import (
    APIKeyCreationError,
    APIKeyDeletionError,
    APIKeyNotFoundError,
    InvalidAPIKeyError
)
from src.api_keys.http_exceptions import (
    APIKeyCreateError,
    APIKeyDeleteError,
    APIKeyNotFound,
    InvalidAPIKey
)
from src.api_keys.schemas import APIKeysResponse
from src.logging_config import create_logger
from src.dependencies import get_current_user, require_csrf_protection
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

logger = create_logger("api_keys", __name__)


@router.post("/key", status_code=201, response_model=APIKeysResponse)
@limiter.limit(f"{config.max_requests_per_minute}/minute")
async def create_api_key(request: Request, current_user=Depends(get_current_user), _=Depends(require_csrf_protection)):
    """
    Create a new API key for the current user.

    Returns:
        APIKeysResponse: Newly generated API key and detail message.
    """
    logger.info(f"Incoming request: user_id={current_user.userId}")
    try:
        new_api_key = await service.create_api_key(current_user.userId)
        return new_api_key
    except APIKeyCreationError:
        logger.warning(f"API key creation failed: user_id={current_user.userId}")
        raise APIKeyCreateError()
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        raise APIKeyCreateError()


@router.delete("/key", status_code=200, response_model=APIKeysResponse)
async def delete_api_key(current_user=Depends(get_current_user), _=Depends(require_csrf_protection)):
    """
    Delete the current user's API key.

    Returns:
        APIKeysResponse: Confirmation message after deleting the API key.

    Raises:
        APIKeyNotFound: If the current user does not have an API key.
    """
    logger.info(f"Incoming request: user_id={current_user.userId}")
    try:
        deleted = await service.delete_api_key(current_user.userId)
        logger.info(
            f"Success: user_id={current_user.userId}"
        )
        return deleted
    except APIKeyNotFoundError:
        logger.warning(f"API key not found: user_id={current_user.userId}")
        raise APIKeyNotFound()
    except APIKeyDeletionError:
        logger.warning(f"API key deletion failed: user_id={current_user.userId}")
        raise APIKeyDeleteError()
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        raise APIKeyDeleteError()