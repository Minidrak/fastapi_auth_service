from kafka import KafkaConsumer
import json
import telegram
import os

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHANNEL_CHAT_ID = os.getenv("TELEGRAM_CHANNEL_CHAT_ID")

bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
consumer = KafkaConsumer('registration_topic', bootstrap_servers='kafka:9092')

for message in consumer:
    event = json.loads(message.value.decode('utf-8'))
    user_id = event['user_id']
    email = event['email']
    bot.send_message(chat_id=CHANNEL_CHAT_ID, text=f"Новый пользователь зарегистрирован: {email} (ID: {user_id})")