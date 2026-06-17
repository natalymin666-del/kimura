from telegram import Update
from telegram.ext import ContextTypes
import requests


async def robots_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # /robots tesla.com
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для robots.txt.\n\nПример:\n/robots tesla.com"
        )
        return

    domain = context.args[0].strip()

    # Собираем URL robots.txt
    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain.rstrip("/") + "/robots.txt"
        pretty = domain.rstrip("/")
    else:
        url = f"https://{domain}/robots.txt"
        pretty = domain

    try:
        resp = requests.get(url, timeout=8)
    except Exception:
        await update.message.reply_text(
            f"Не удалось получить robots.txt для {pretty}."
        )
        return

    if resp.status_code != 200:
        await update.message.reply_text(
            f"⚙ robots.txt для {pretty} недоступен.\nHTTP статус: {resp.status_code}"
        )
        return

    content = resp.text.strip()
    if not content:
        await update.message.reply_text(
            f"⚙ robots.txt для {pretty} пустой."
        )
        return

    lines = content.splitlines()
    preview = "\n".join(lines[:25])  # показываем первые 25 строк
    more = "" if len(lines) <= 25 else f"\n… (всего строк: {len(lines)})"

    msg = (
        f"🤖 robots.txt для: {pretty}\n\n"
        "text\n"
        f"{preview}\n"
        ""
        f"{more}"
    )

    await update.message.reply_text(msg, parse_mode="Markdown")
from telegram import Update
from telegram.ext import ContextTypes
import requests


async def wayback_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # /wayback tesla.com
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для Wayback.\n\nПример:\n/wayback tesla.com"
        )
        return

    domain = context.args[0].strip()
    domain_clean = (
        domain.replace("http://", "")
        .replace("https://", "")
        .strip("/")
    )

    # Запрашиваем последние снимки из Wayback Machine
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={domain_clean}/*&output=json&limit=5&filter=statuscode:200&from=2015"
    )

    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        await update.message.reply_text(
            f"Не удалось получить данные Wayback для {domain_clean}."
        )
        return

    # data[0] — заголовок, дальше строки со снимками
    if not data or len(data) <= 1:
        await update.message.reply_text(
            f"🕰 Архив Wayback: снимков для {domain_clean} не найдено."
        )
        return

    header, *rows = data

    lines = [f"🕰 Wayback-снимки для: {domain_clean} (до 5 шт.)"]
    for row in rows[:5]:
        # по формату cdx: timestamp во 2-м поле, оригинальный URL — в 3-м
        ts = row[1]
        original_url = row[2]
        date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        snapshot_url = f"https://web.archive.org/web/{ts}/{original_url}"
        lines.append(f"• {date} — {snapshot_url}")

    await update.message.reply_text("\n".join(lines))
