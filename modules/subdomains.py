import requests
from telegram import Update
from telegram.ext import ContextTypes

async def subdomains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) == 0:
        await update.message.reply_text("❗ Укажите домен.\nПример: /subdomains target.com")
        return

    domain = context.args[0]
    await update.message.reply_text(f"🔍 Ищу поддомены для: {domain} ...")

    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

    try:
        response = requests.get(url, timeout=10)
        data = response.text.split("\n")

        if not data or "error" in data[0].lower():
            await update.message.reply_text("⚠️ Не удалось получить поддомены.")
            return

        subdomains = "\n".join(data[:50])  # показываем первые 50

        await update.message.reply_text(f"🌐 Найденные поддомены:\n{subdomains}")

    except Exception as e:
        await update.message.reply_text(f"Ошибка: {str(e)}")
