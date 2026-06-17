import whois
from telegram import Update
from telegram.ext import ContextTypes

async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для WHOIS.\n\nПример:\n/whois tesla.com"
        )
        return

    domain = context.args[0].strip()

    try:
        info = whois.whois(domain)
    except Exception as e:
        await update.message.reply_text(f"Не удалось выполнить WHOIS: {e}")
        return

    text = f"🔎 WHOIS для: {domain}\n\n"

    def add(label, value):
        if value:
            return f"• {label}: {value}\n"
        return ""

    text += add("Регистратор", info.registrar)
    text += add("Страна", info.country)
    text += add("Дата регистрации", info.creation_date)
    text += add("Истекает", info.expiration_date)
    text += add("DNS (Name Servers)", info.name_servers)
    text += add("Emails", info.emails)

    if text.strip() == "":
        text = "Информации нет."

    await update.message.reply_text(text, parse_mode="Markdown")
