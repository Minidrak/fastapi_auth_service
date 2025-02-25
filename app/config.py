import os

class Config:
    JWT_SECRET = os.getenv("JWT_SECRET")
    YANDEX_CLIENT_ID = os.getenv("YANDEX_CLIENT_ID")
    YANDEX_CLIENT_SECRET = os.getenv("YANDEX_CLIENT_SECRET")
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHANNEL_CHAT_ID = os.getenv("TELEGRAM_CHANNEL_CHAT_ID")
    DB_NAME = os.getenv("DB_NAME", "dbname")
    DB_USER = os.getenv("DB_USER", "user")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
    DB_HOST = os.getenv("DB_HOST", "db")
    DB_PORT = os.getenv("DB_PORT", "5432")
    KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    REDIRECT_URI = os.getenv("REDIRECT_URI")

config = Config()