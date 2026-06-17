# modules/corsscan.py
import aiohttp
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ContextTypes


async def corsscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Команда:
        /cors https://target.com
    """
    if not context.args:
        await update.message.reply_text(
            "🌐 CORSHunter:\n"
            "Проверяю CORS-заголовки.\n\n"
            "Пример:\n"
            "/cors https://target.com"
        )
        return

    raw_url = context.args[0].strip()

    parsed = urlparse(raw_url)
    if not parsed.scheme.startswith("http"):
        await update.message.reply_text("URL должен начинаться с http:// или https://")
        return

    await update.message.reply_text(
        f"🌐 CORSHunter для: {raw_url}\n"
        "Отправляю запрос с поддельным Origin и смотрю на CORS-заголовки…"
    )

    timeout = aiohttp.ClientTimeout(total=12)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get(
                raw_url,
                headers={"Origin": "https://evil-example.com"},
            ) as resp:
                status = resp.status
                headers = resp.headers
        except Exception as e:
            await update.message.reply_text(f"Не удалось подключиться: {e}")
            return

    acao = headers.get("Access-Control-Allow-Origin")
    acac = headers.get("Access-Control-Allow-Credentials")
    acam = headers.get("Access-Control-Allow-Methods")
    acah = headers.get("Access-Control-Allow-Headers")

    lines = [
        f"🔥 CORSHunter отчёт для: {raw_url}",
        f"HTTP статус: {status}",
        "",
        "Полученные CORS-заголовки:",
        f"- Access-Control-Allow-Origin: {acao}",
        f"- Access-Control-Allow-Credentials: {acac}",
        f"- Access-Control-Allow-Methods: {acam}",
        f"- Access-Control-Allow-Headers: {acah}",
        "",
    ]

    risky = []

    if acao == "*" and acac and acac.lower() == "true":
        risky.append(
            "❗️ ACAO='*' И одновременно Allow-Credentials: true – это опасная конфигурация."
        )
    elif acao == "https://evil-example.com":
        risky.append(
            "❗️ Сервер отразил Origin целиком – возможен CORS-misconfig (проверь, есть ли креды)."
        )

    if risky:
        lines.extend(risky)
    else:
        lines.append(
            "ℹ️ Явно опасной CORS-конфигурации по этому запросу не видно.\n"
            "Но всё равно стоит проверить другие Origin / поддомены."
        )

    lines.append(
        "\nПомни: CORS-бага становится серьёзной, когда:\n"
        "- сервер доверяет произвольному Origin\n"
        "- и одновременно выдаёт чувствительные данные с credentials."
    )

    await update.message.reply_text("\n".join(lines))
