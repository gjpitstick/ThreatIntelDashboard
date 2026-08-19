"""Application configuration, loaded from environment / .env file."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Optional API keys -- ingestion degrades gracefully without them.
    nvd_api_key: str = ""
    abusech_api_key: str = ""

    app_port: int = 8000
    refresh_interval_hours: int = 4
    lookback_days: int = 7
    database_path: str = "./data/ctidash.db"
    log_level: str = "INFO"

    # RSS news sources. Category is a hint used only as a fallback if
    # keyword-based categorization in ingestion/news.py can't decide.
    news_feeds: dict[str, str] = {
        "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
        "Cyber Security News": "https://cybersecuritynews.com/feed/",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "Krebs on Security": "https://krebsonsecurity.com/feed/",
    }


settings = Settings()
