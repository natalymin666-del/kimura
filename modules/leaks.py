import re
from telegram import Update
from telegram.ext import ContextTypes

EMAIL_REGEX = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


async def leaks_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # 1. Проверяем, что пользователь передал email
    if not context.args:
        await update.message.reply_text(
            "Укажи email для проверки утечек.\n\nПример:\n/leaks test@example.com"
        )
        return

    email = context.args[0].strip()

    # 2. Проверяем формат email
    if not re.match(EMAIL_REGEX, email):
        await update.message.reply_text("Похоже, это не похоже на валидный email 🙂")
        return

    # 3. Пока делаем демо-режим (заглушка)
    # Здесь позже подключим реальное API проверки утечек
    text = (
        f"🕵️ Проверка утечек для: {email}\n\n"
        "🚧 Сейчас включён демо-режим.\n"
        "Структура модуля уже готова:\n"
        "• запрос к API базы утечек\n"
        "• парсинг ответа\n"
        "• формирование короткого отчёта\n\n"
        "Когда подключим реальное API, ты сможешь видеть:\n"
        "• количество утечек\n"
        "• имена слитых баз\n"
        "• даты утечек\n"
        "• типы скомпрометированных данных (пароли, телефоны и т.п.)\n\n"
        "Сейчас Kimura просто проверяет формат email и готова к интеграции."
    )

    await update.message.reply_text(text, parse_mode="Markdown")
