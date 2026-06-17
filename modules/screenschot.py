from telegram import Update
from telegram.ext import ContextTypes


def normalize_url(target: str) -> str:
    """
    Нормализуем домен: добавляем https:// если его нет.
    """
    target = target.strip()

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    return target


async def screenshot_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /screenshot домен — делает скриншот главной страницы через публичный сервис.
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для скриншота.\n\n"
            "Пример:\n"
            "/screenshot tesla.com\n"
            "/screenshot example.org"
        )
        return

    target = context.args[0]
    url = normalize_url(target)

    # Публичный сервис скриншотов (без ключа, демо-режим)
    screenshot_url = f"https://image.thum.io/get/fullpage/{url}"

    try:
        await update.message.reply_photo(
            screenshot_url,
            caption=f"📷 Скриншот для: {target}"
        )
    except Exception as e:
        await update.message.reply_text(
            "Не удалось получить скриншот. "
            "Возможно, сайт не отвечает или сервис скриншотов недоступен."
        )
