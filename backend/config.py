from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    openai_api_key: str = ""
    openai_base_url: str = "https://openrouter.ai/api/v1"
    openai_model: str = "openai/gpt-4o-mini"
    frontend_origin: str = "http://localhost:3000"
    max_scan_duration_seconds: int = 120
    max_pages_to_crawl: int = 10


settings = Settings()
