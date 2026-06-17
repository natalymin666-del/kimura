import requests
from telegram import Update
from telegram.ext import ContextTypes

API_URL = "https://archive.org/wayback/available?url={domain}"

async def wayback_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\nПример:\n/wayback tesla.com"
        )
        return

    domain = context.args[0]

    try:
        response = requests.get(API_URL.format(domain=domain)).json()

        snapshots = response.get("archived_snapshots", {})
        closest = snapshots.get("closest")

        if closest:
            url = closest.get("url")
            timestamp = closest.get("timestamp")
            await update.message.reply_text(
                f"📚 Wayback Snapshot:\n"
                f"Дата: {timestamp}\n"
                f"URL: {url}"
            )
        else:
            await update.message.reply_text("Архивные версии не найдены.")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")
