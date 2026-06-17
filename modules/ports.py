import socket
from telegram import Update
from telegram.ext import ContextTypes

# Набор популярных портов для быстрого скана
COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (587, "SMTP (TLS)"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8000, "HTTP-alt"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (27017, "MongoDB"),
]


def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Простой TCP-connect скан одного порта."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


async def ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Укажи домен или IP для сканирования портов.\n\n"
            "Пример:\n"
            "/ports tesla.com\n"
            "/ports 8.8.8.8"
        )
        return

    target = context.args[0].strip()

    # 1) Резолвим домен в IP (или принимаем IP как есть)
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        await update.message.reply_text(f"Не удалось определить IP для {target}: {e}")
        return

    await update.message.reply_text(
        f"🔎 Быстрый скан популярных портов для цели: {target} (IP: {ip})...\n"
        f"Это демонстрационный скан, не предназначен для агрессивных атак."
    )

    open_ports = []

    for port, desc in COMMON_PORTS:
        if scan_port(ip, port):
            open_ports.append((port, desc))

    if not open_ports:
        text = (
            f"✅ Скан завершён.\n\n"
            f"Открытых портов из списка популярных не найдено.\n"
            f"(Это не гарантирует полную безопасность — только быстрый чек.)"
        )
    else:
        lines = []
        for port, desc in open_ports:
            lines.append(f"• {port}/tcp — {desc}")

        ports_text = "\n".join(lines)

        text = (
            f"✅ Скан завершён.\n\n"
            f"Найдены открытые порты:\n"
            f"{ports_text}\n\n"
            f"Используй это как старт для более глубокого анализа (nmap, burp и т.п.)."
        )

    await update.message.reply_text(text)
