from fastapi import Depends, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from src.auth.http_exceptions import InvalidJWTToken
from src.auth.schemas import TokenData, UserCurrent
from src.auth.service import AuthService
from src.auth.repository import AuthRepository
from src.users.repository import UserRepository
from src.users.service import UserService
from src.auth.csrf_service import CSRFService
from src.config import config
from src.logging_config import create_logger
from src.database import database_instance
from src.api_keys.repository import ApiKeyRepository
from src.api_keys.service import ApiKeyService
from src.auth.security_service import SecurityService
from src.auth.email_service import EmailService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/signin")
logger = create_logger("dependencies", __name__)


def get_db():
    return database_instance.database


def get_email_service() -> EmailService:

    background_runner = AsyncBackgroundRunner()
    return EmailService(background_runner)





def get_api_key_repository(db=Depends(get_db)) -> ApiKeyRepository:
    return ApiKeyRepository(db)


def get_api_key_service(
    repo: ApiKeyRepository = Depends(get_api_key_repository)
) -> ApiKeyService:

    background_runner = AsyncBackgroundRunner()
    return ApiKeyService(repo, background_runner)





def get_user_repository(db=Depends(get_db)) -> UserRepository:
    return UserRepository(db)


def get_auth_repository(db=Depends(get_db)) -> AuthRepository:
    return AuthRepository(db)

from src.infrastructure import AsyncBackgroundRunner

def get_security_service(

    auth_repo: AuthRepository = Depends(get_auth_repository),
    user_repo: UserRepository = Depends(get_user_repository),
    email_service: EmailService = Depends(get_email_service)
) -> SecurityService:

    background_runner = AsyncBackgroundRunner()
    return SecurityService(auth_repo, user_repo, email_service, background_runner)



def get_auth_service(
    auth_repo: AuthRepository = Depends(get_auth_repository),
    user_repo: UserRepository = Depends(get_user_repository),
    security_service: SecurityService = Depends(get_security_service),
    email_service: EmailService = Depends(get_email_service)
) -> AuthService:
    return AuthService(auth_repo, user_repo, security_service, email_service)


def get_user_service(
    user_repo: UserRepository = Depends(get_user_repository),
    security_service: SecurityService = Depends(get_security_service),
    email_service: EmailService = Depends(get_email_service)
) -> UserService:
    return UserService(user_repo, security_service, email_service)


async def get_current_user(
    token: str = Depends(oauth2_scheme), 
    api_key_service: ApiKeyService = Depends(get_api_key_service),
    auth_service: AuthService = Depends(get_auth_service),
    background_tasks: BackgroundTasks = None
):
    try:
        if token.startswith(config.api_key_prefix):
            try:
                user = await api_key_service.validate_api_key(token)
                return UserCurrent(**user)
            except Exception as e:
                logger.warning(f"API Key validation failed: {str(e)}")
                raise InvalidJWTToken() # Re-raise as 401 for consistency

        payload = jwt.decode(token, config.secret_key, algorithms=[config.algorithm])
        username: str = payload.get("sub")
        if username is None:
            logger.warning("Token does not contain sub/username")
            raise InvalidJWTToken()
        token_data = TokenData(username=username)
    except JWTError as e:
        logger.exception(f"JWTError: {str(e)}")
        raise InvalidJWTToken()
    user = await auth_service.get_user(username_or_email=token_data.username)
    if user is None:
        logger.warning(f"User not found: {token_data.username}")
        raise InvalidJWTToken()
    return UserCurrent(**user.dict())


def require_csrf_protection(request: Request):
    if request.method == "OPTIONS":
        return True

    if request.headers.get("authorization") and request.headers.get("authorization").startswith(f"Bearer {config.api_key_prefix}"):
        return True

    if config.is_env_dev:
        referer = request.headers.get("referer", "")
        sec_fetch_site = request.headers.get("sec-fetch-site", "")
        if (
            (referer.startswith("http://localhost:8000/docs") or referer.startswith("http://localhost:8000/redoc"))
            and sec_fetch_site == "same-origin"
        ):
            return True

        user_agent = request.headers.get("user-agent", "").lower()
        if "postman" in user_agent:
            return True

    header_token = request.headers.get(CSRFService.CSRF_TOKEN_HEADER)
    cookie_token = request.cookies.get(CSRFService.CSRF_TOKEN_COOKIE)
    
    if not CSRFService.validate_csrf_token_string(header_token, cookie_token):
        raise InvalidCSRFToken()
    return True
