from telegram import Update
from telegram.ext import ContextTypes
import re
import requests
import hashlib


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_mx_records(domain: str):
    """Пытаемся получить MX через публичный DNS API Google."""
    try:
        resp = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "MX"},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        answers = data.get("Answer", [])
        mx = [a.get("data", "") for a in answers]
        return mx
    except Exception:
        return []


def check_gravatar(email: str) -> bool:
    """Проверяем, есть ли Gravatar для этого email (демо-проверка)."""
    try:
        email_norm = email.strip().lower()
        email_hash = hashlib.md5(email_norm.encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        resp = requests.get(url, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


async def emailosint_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "📧 Укажи email.\n\nПример:\n"
            "/emailosint test@example.com"
        )
        return

    email = context.args[0].strip()

    # 1) базовая валидация
    valid = bool(EMAIL_RE.match(email))
    if "@" in email:
        local_part, domain = email.split("@", 1)
    else:
        local_part, domain = email, "—"

    # 2) MX-записи
    mx_records = get_mx_records(domain) if valid else []
    mx_preview = mx_records[:3]

    # 3) Gravatar
    gravatar_exists = check_gravatar(email) if valid else False

    # 4) Демо-блок по утечкам (готов к интеграции с API)
    leaks_block = (
        "🔒 Leak status: demo-mode.\n"
        "Структура готова для подключения реального API "
        "(например, HaveIBeenPwned / Dehashed и т.п.)."
    )

    text_lines = [
        f"📧 Email OSINT для: {email}",
        "",
        f"• Формат: {'✅ корректный' if valid else '❌ некорректный'}",
        f"• Локальная часть: {local_part}",
        f"• Домен: {domain}",
        "",
    ]

    if valid:
        # MX
        if mx_preview:
            text_lines.append("📨 MX-записи (первые 3):")
            for mx in mx_preview:
                text_lines.append(f"  – {mx}")
        else:
            text_lines.append("📨 MX-записи: не найдены или домен не отвечает.")

        # Gravatar
        text_lines.append(
            f"🖼 Gravatar: {'✅ найден' if gravatar_exists else '❌ не найден'}"
        )

        text_lines.append("")
        text_lines.append(leaks_block)
    else:
        text_lines.append(
            "⚠ Email выглядит подозрительно. Проверь формат и попробуй ещё раз."
        )

    await update.message.reply_text("\n".join(text_lines))
