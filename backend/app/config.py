
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Always locate .env inside the backend directory
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"


class Settings(BaseSettings):

    PROJECT_NAME: str = "NyensungAI"

    ENVIRONMENT: str = "development"

    DATABASE_URL: str = "sqlite:///./sentinelai.db"

    SECRET_KEY: str

    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    FRONTEND_URL: str = "http://localhost:5173"

    # Required for endpoint-agent ingestion. Never commit the real value.
    AGENT_API_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @model_validator(mode="after")
    def validate_production_secrets(self):
        if self.ENVIRONMENT.lower() == "production":
            if len(self.SECRET_KEY) < 32 or "replace-with" in self.SECRET_KEY.lower():
                raise ValueError("Production SECRET_KEY must be a unique random value of at least 32 characters")
            if len(self.AGENT_API_KEY) < 32 or "replace-with" in self.AGENT_API_KEY.lower():
                raise ValueError("Production AGENT_API_KEY must be a unique random value of at least 32 characters")
            if not self.FRONTEND_URL.lower().startswith("https://"):
                raise ValueError("Production FRONTEND_URL must use HTTPS")
        return self


settings = Settings()
