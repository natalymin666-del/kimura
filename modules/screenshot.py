from telegram import Update
from telegram.ext import ContextTypes

# ПРОСТОЙ DEMO-ВАРИАНТ БЕЗ requests
# Telegram сам скачивает картинку по URL

async def screenshot_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "❗ Укажи домен. Пример:\n"
            "/screenshot tesla.com"
        )
        return

    domain = context.args[0].lower()

    # Добавим https:// если его нет
    if not domain.startswith("http://") and not domain.startswith("https://"):
        url = f"https://{domain}"
    else:
        url = domain

    # Простой публичный сервис скриншотов (demo)
    screenshot_url = f"https://image.thum.io/get/width/1200/{url}"

    # Просто отправляем URL как фото — без предварительной проверки
    await update.message.reply_photo(
        screenshot_url,
        caption=f"📸 Скриншот главной страницы: {url}\n\n"
                "Режим: demo, через публичный screenshot-сервис."
    )
