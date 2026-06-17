from telegram import Update
from telegram.ext import ContextTypes
import socket


async def reverseip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # если нет аргументов
    if not context.args:
        await update.message.reply_text(
            "Укажи домен или IP.\n"
            "Пример: /reverseip tesla.com"
        )
        return

    target = context.args[0].strip()

    # 1) пытаемся получить IP для домена / IP
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        await update.message.reply_text(
            f"Не удалось получить IP для цели: {target}\n"
            f"Ошибка: {e}"
        )
        return

    # 2) пытаемся сделать reverse DNS (PTR)
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)

        text_lines = [
            f"🔁 Reverse DNS для цели: {target}",
            f"IP: {ip}",
            "",
            f"Основное имя (PTR): {host}",
        ]

        if aliases:
            text_lines.append("Алиасы (доп. имена):")
            for a in aliases:
                text_lines.append(f"• {a}")
        else:
            text_lines.append("Алиасы: не найдены.")

        text = "\n".join(text_lines)

    except Exception:
        # PTR нет или закрыт
        text = (
            f"🔁 Reverse DNS для цели: {target}\n"
            f"IP: {ip}\n"
            "PTR-запись не найдена или недоступна."
        )

    await update.message.reply_text(text)
