from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from app.backend.db_depends import get_db
from app.config import settings
from app.models import User
from app.models.token import TokenBlacklist
from app.schemas import CreateUser, TokenData, UserResponse, UserUpdate
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from loguru import logger
from passlib.context import CryptContext
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/auth", tags=["auth"])
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


class AuthService:
    """Сервис для работы с аутентификацией и авторизацией"""

    @staticmethod
    async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> UserResponse:
        """Получает текущего пользователя по JWT токену."""

        blacklisted = await db.scalar(
            select(TokenBlacklist).where(TokenBlacklist.token == token)
        )
        if blacklisted:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked"
            )
        try:
            payload = jwt.decode(
                token, settings.secret_key, algorithms=settings.algorithm
            )
            user_id: int | None = payload.get("id")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                )
            user = await db.scalar(
                select(User).where(User.id == user_id, User.is_active == True)
            )
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                )
            return UserResponse(
                id=user.id,
                first_name=user.first_name,
                last_name=user.last_name,
                username=user.username,
                email=user.email,
                is_admin=user.is_admin,
                is_active=user.is_active,
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
            )
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )

    @staticmethod
    async def authenticate_user(
        db: Annotated[AsyncSession, Depends(get_db)], username: str, password: str
    ) -> User:
        """Аутентифицирует пользователя по логину и паролю."""

        user = await db.scalar(
            select(User).where(User.username == username, User.is_active == True)
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        if not bcrypt_context.verify(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password",
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User inactive",
            )
        return user

    @staticmethod
    async def create_token(
        username: str,
        user_id: int,
        is_admin: bool,
        expires_delta: timedelta,
        token_type: str,
    ) -> str:
        """Создает JWT токен."""

        expires_delta = expires_delta or (
            timedelta(minutes=settings.access_token_expire_minutes)
            if token_type == "access"
            else timedelta(days=settings.refresh_token_expire_days)
        )
        expire = datetime.now(timezone.utc) + expires_delta
        payload = {
            "sub": username,
            "id": user_id,
            "is_admin": is_admin,
            "exp": int(expire.timestamp()),
            "type": token_type,
        }
        return jwt.encode(payload, settings.secret_key, settings.algorithm)

    @staticmethod
    async def validate_user_access(current_user: UserResponse, user_id: int) -> None:
        """Проверяет права доступа к данным пользователя."""

        if not current_user.is_admin and current_user.id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
            )

    @staticmethod
    async def add_to_blacklist(
        db: Annotated[AsyncSession, Depends(get_db)], token: str, expire_at: datetime
    ):
        """Добавляет токен в черный список."""

        await db.execute(
            insert(TokenBlacklist).values(token=token, expire_at=expire_at)
        )
        await db.commit()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def create_user(
    db: Annotated[AsyncSession, Depends(get_db)], create_user: CreateUser
):
    """Регистрирует нового пользователя в системе."""

    try:
        await db.execute(
            insert(User).values(
                first_name=create_user.first_name,
                last_name=create_user.last_name,
                username=create_user.username,
                email=create_user.email,
                hashed_password=bcrypt_context.hash(create_user.password),
            )
        )
        await db.commit()
        return {"message": "User created successfully"}
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during user creation",
        )


@router.post("/token", response_model=TokenData)
async def login(
    db: Annotated[AsyncSession, Depends(get_db)],
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    """Аутентифицирует пользователя и возвращает JWT токены."""

    user = await AuthService.authenticate_user(
        db, form_data.username, form_data.password
    )
    access_token = await AuthService.create_token(
        user.username,
        user.id,
        user.is_admin,
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
        token_type="access",
    )
    refresh_token = await AuthService.create_token(
        username=user.username,
        user_id=user.id,
        is_admin=user.is_admin,
        expires_delta=timedelta(days=settings.refresh_token_expire_days),
        token_type="refresh",
    )
    return TokenData(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


@router.post("/refresh", response_model=TokenData)
async def refresh_token(
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
):
    """Обновляет пару access и refresh токенов."""

    refresh_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing"
        )
    try:
        payload = jwt.decode(
            refresh_token, settings.secret_key, algorithms=[settings.algorithm]
        )
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
            )
        expire_at = datetime.fromtimestamp(payload["exp"], timezone.utc)
        await AuthService.add_to_blacklist(db, refresh_token, expire_at)
        access_token = await AuthService.create_token(
            username=payload["sub"],
            user_id=payload["id"],
            is_admin=payload.get("is_admin", False),
            expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
            token_type="access",
        )
        new_refresh_token = await AuthService.create_token(
            username=payload["sub"],
            user_id=payload["id"],
            is_admin=payload.get("is_admin", False),
            expires_delta=timedelta(days=settings.refresh_token_expire_days),
            token_type="refresh",
        )
        return TokenData(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )


@router.post("/logout")
async def logout(
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
):
    """Выход из системы - добавляет токен в черный список."""

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token missing"
        )
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
        expire_at = datetime.fromtimestamp(payload["exp"], timezone.utc)
        await AuthService.add_to_blacklist(db, token, expire_at)
        return {"message": "Successfully logged out"}
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token"
        )


@router.get("/me", response_model=UserResponse)
async def read_current_user(user: UserResponse = Depends(AuthService.get_current_user)):
    """Получает данные текущего авторизованного пользователя."""

    return user


@router.get("/check_token")
async def check_token_validity(
    user: UserResponse = Depends(AuthService.get_current_user),
):
    """Проверяет валидность текущего токена."""

    return {"is_valid": True, "user": user.model_dump(), "message": "Token is valid"}


@router.patch("/users/{user_id}")
async def update_user(
    user_id: int,
    updated_data: UserUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: UserResponse = Depends(AuthService.get_current_user),
):
    """Обновляет данные пользователя."""

    await AuthService.validate_user_access(current_user, user_id)
    updated_values = {
        k: v for k, v in updated_data.model_dump().items() if v is not None
    }
    if not updated_values:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No data to update",
        )
    await db.execute(update(User).where(User.id == user_id).values(**updated_values))
    await db.commit()
    return {"message": "User updated successfully"}


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user_profile(
    user_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: UserResponse = Depends(AuthService.get_current_user),
):
    """Получает профиль пользователя по ID."""

    await AuthService.validate_user_access(current_user, user_id)
    user = await db.scalar(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return UserResponse(
        id=user.id,
        first_name=user.first_name,
        last_name=user.last_name,
        username=user.username,
        email=user.email,
        is_admin=user.is_admin,
        is_active=user.is_active,
    )


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[UserResponse, Depends(AuthService.get_current_user)],
    user_id: int,
):
    """Деактивирует пользователя (мягкое удаление)."""

    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permissions required",
        )
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot delete yourself",
        )
    user = await db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if not user.is_active:
        return
    await db.execute(update(User).where(User.id == user.id).values(is_active=False))
    await db.commit()


@router.get("/users", response_model=list[UserResponse])
async def get_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: UserResponse = Depends(AuthService.get_current_user),
):
    """Получает список всех активных пользователей (только для администраторов)."""

    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin permissions required"
        )
    users = await db.scalars(select(User).where(User.is_active == True))
    return [
        UserResponse(
            id=user.id,
            first_name=user.first_name,
            last_name=user.last_name,
            username=user.username,
            email=user.email,
            is_admin=user.is_admin,
            is_active=user.is_active,
        )
        for user in users
    ]
