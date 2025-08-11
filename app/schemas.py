from pydantic import BaseModel


class CreateUser(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: str
    password: str
