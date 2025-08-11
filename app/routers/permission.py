from typing import Annotated

from app.backend.db_depends import get_db
from app.models import User
from app.routers.auth import get_current_user
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/permissions", tags=["permissions"])


@router.delete("/delete")
async def delete_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    get_user: Annotated[dict, Depends(get_current_user)],
    user_id: int,
):
    if get_user.get("is_admin"):
        user = await db.scalar(select(User).where(User.id == user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        if user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Ypu can't delete admin user",
            )
        if user.is_active:
            await db.execute(
                update(User).where(User.id == user.id).values(is_active=False)
            )
            await db.commit()
            return {"status_code": status.HTTP_200_OK, "detail": "User is deleted"}
        else:
            return {
                "status_code": status.HTTP_200_OK,
                "detail": "User has already been deleted",
            }
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have admin permissions",
        )
