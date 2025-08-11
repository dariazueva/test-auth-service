from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = (
        "postgresql+asyncpg://authservice_user:mysecretpassword@localhost:5432/authservice"
    )
    secret_key: str = "your-secret-key"
    algorithm: str = "HS256"

    model_config = SettingsConfigDict(env_file="../.env", env_file_encoding="utf-8")


settings = Settings()
