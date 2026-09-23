from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import get_settings
from backend.core.security import decode_token
from backend.db.session import get_db
from backend.models import RefreshToken, User

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
http_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        if not payload:
            raise credentials_exception
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_type = payload.get("type")
        if token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user


def require_role(*roles: str):
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions"
            )
        return current_user

    return role_checker


require_admin = require_role("admin")
require_analyst = require_role("admin", "analyst")


async def verify_refresh_token(refresh_token: str, db: AsyncSession) -> User | None:
    token_hash = hash_password(refresh_token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    stored_token = result.scalar_one_or_none()

    if not stored_token:
        return None

    if stored_token.revoked_at is not None:
        return None

    if stored_token.expires_at < datetime.now(timezone.utc):
        return None

    result = await db.execute(select(User).where(User.id == stored_token.user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return None

    return user


from datetime import datetime, timezone

from backend.core.security import hash_password


async def create_refresh_token_record(
    user_id: int, refresh_token: str, request: Request, db: AsyncSession
) -> RefreshToken:
    token_hash = hash_password(refresh_token)
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return token


async def revoke_refresh_token(refresh_token: str, db: AsyncSession) -> bool:
    token_hash = hash_password(refresh_token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    stored_token = result.scalar_one_or_none()

    if not stored_token:
        return False

    stored_token.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    return True


async def revoke_all_user_tokens(user_id: int, db: AsyncSession) -> int:
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
        )
    )
    tokens = result.scalars().all()

    count = 0
    for token in tokens:
        token.revoked_at = datetime.now(timezone.utc)
        count += 1

    await db.commit()
    return count


from datetime import timedelta
