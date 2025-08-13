from pydantic import BaseModel, EmailStr


class CreateUser(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    password: str
    is_admin: bool | None = None


class UserUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    is_admin: bool | None = None


class UserResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    username: str
    email: str
    is_admin: bool
    is_active: bool


class TokenData(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
