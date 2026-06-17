import requests
from telegram import Update
from telegram.ext import ContextTypes


async def robots_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # если домен не передан
    if not context.args:
        await update.message.reply_text(
            "Укажи домен. Пример:\n"
            "/robots tesla.com"
        )
        return

    domain = context.args[0].strip()

    # добавляем https:// если нет схемы
    if not domain.startswith("http://") and not domain.startswith("https://"):
        base_url = f"https://{domain}"
    else:
        base_url = domain

    url = base_url.rstrip("/") + "/robots.txt"

    try:
        resp = requests.get(url, timeout=5)
    except requests.RequestException:
        await update.message.reply_text(
            "Не удалось получить robots.txt — сайт не отвечает."
        )
        return

    if resp.status_code != 200:
        await update.message.reply_text(
            f"Запрос к {url} вернул статус {resp.status_code}.\n"
            "Возможно, robots.txt отсутствует или недоступен."
        )
        return

    text = resp.text.strip()

    if not text:
        await update.message.reply_text(
            f"Файл robots.txt по адресу {url} пустой."
        )
        return

    # чтобы сообщение не было слишком длинным
    if len(text) > 3500:
        text = text[:3500] + "\n\n… (обрезано)"

    message = (
        f"🤖 robots.txt для цели: {domain}\n\n"
        "txt\n"
        f"{text}\n"
        ""
    )

    await update.message.reply_text(message, parse_mode="Markdown")
