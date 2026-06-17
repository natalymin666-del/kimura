import requests
from telegram import Update
from telegram.ext import ContextTypes

async def tech_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для анализа технологий.\n\n"
            "Пример:\n"
            "/tech tesla.com"
        )
        return

    domain = context.args[0].lower().strip()

    # --- Пока демо-режим, как в /leaks ---
    demo_response = (
        f"🧪 Анализ технологий для: {domain}\n\n"
        f"Сейчас включен демо-режим.\n"
        f"Структура модуля уже работает и ждёт API ключ.\n\n"
        f"После подключения API Wappalyzer ты будешь получать:\n"
        f"• CMS (например WordPress / Shopify / Drupal)\n"
        f"• Язык backend (PHP, Python, Node.js)\n"
        f"• JS-фреймворки (React, Vue, Angular)\n"
        f"• Web-сервер (Nginx, Apache)\n"
        f"• Системы аналитики (Google Analytics и другие)\n"
        f"• Возможные админ-панели\n\n"
        f"Модуль готов к интеграции."
    )

    await update.message.reply_text(demo_response)
