from telegram import Update
from telegram.ext import ContextTypes
import socket
import requests


async def revip_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Reverse IP lookup: домены, размещённые на одном IP."""

    if not context.args:
        await update.message.reply_text(
            "Укажи домен для Reverse IP.\n\n"
            "Пример:\n"
            "/revip tesla.com"
        )
        return

    target = context.args[0].strip()

    # 1. Резолвим домен в IP
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        await update.message.reply_text(
            f"Не удалось получить IP для цели: {target}."
        )
        return

    # 2. Делаем Reverse IP через публичный API (демо-режим)
    await update.message.reply_text(
        f"🔍 Запускаю Reverse IP lookup для: {target} (IP: {ip})…",
        parse_mode="Markdown",
    )

    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = requests.get(url, timeout=10)
    except Exception:
        await update.message.reply_text(
            "Не удалось получить данные Reverse IP. "
            "Возможно, сервис временно недоступен."
        )
        return

    text = resp.text.strip()

    # Сервис в случае ошибки тоже отвечает текстом
    if not text or "error" in text.lower() or "no records" in text.lower():
        await update.message.reply_text(
            f"Для IP {ip} не найдено доменов (или сервис не вернул данные)."
        )
        return

    domains = [line.strip() for line in text.splitlines() if line.strip()]

    if not domains:
        await update.message.reply_text(
            f"Для IP {ip} не найдено доменов."
        )
        return

    # Ограничим вывод, чтобы не спамить
    max_show = 30
    show_list = domains[:max_show]

    lines = []
    lines.append(f"🧭 Reverse IP для цели: {target} (IP: {ip})")
    lines.append("")
    lines.append(f"Найдено доменов: {len(domains)}")
    if len(domains) > max_show:
        lines.append(f"(показаны первые {max_show})")
    lines.append("")

    for d in show_list:
        lines.append(f"• {d}")

    lines.append("")
    lines.append(
        "Используй это как старт для OSINT и поиска связанных приложений.\n"
        "Режим: demo, через публичный Reverse IP сервис."
    )

    await update.message.reply_text(
        "\n".join(lines),
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )
