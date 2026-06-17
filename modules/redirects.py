# modules/redirects.py
import aiohttp
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ContextTypes

REDIRECT_PAYLOADS = [
    "https://example.com",
    "//example.com",
    "https://example.com@target.com",
    "https://example.com/%2e%2e",
    "https://example.com#@target.com",
]


async def redirects_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Команда:
        /redir https://target.com/redirect?url=FUZZ
    """
    if not context.args:
        await update.message.reply_text(
            "🌀 RedirectHunter:\n"
            "Нужен URL с параметром FUZZ.\n\n"
            "Пример:\n"
            "/redir https://target.com/redirect?url=FUZZ"
        )
        return

    raw_url = context.args[0].strip()

    if "FUZZ" not in raw_url:
        await update.message.reply_text(
            "В URL должно быть слово 'FUZZ'.\n\n"
            "Пример:\n"
            "/redir https://target.com/redirect?url=FUZZ"
        )
        return

    parsed = urlparse(raw_url)
    if not parsed.scheme.startswith("http"):
        await update.message.reply_text("URL должен начинаться с http:// или https://")
        return

    await update.message.reply_text(
        f"🌀 RedirectHunter для:\n{raw_url}\n\n"
        "Пробую разные payload'ы и анализирую Location.\n"
        "Используй только на легальных целях!"
    )

    timeout = aiohttp.ClientTimeout(total=12)
    findings = []

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for payload in REDIRECT_PAYLOADS:
            test_url = raw_url.replace("FUZZ", payload)
            try:
                async with session.get(
                    test_url, allow_redirects=False
                ) as resp:
                    status = resp.status
                    location = resp.headers.get("Location", "")
            except Exception:
                continue

            if status in (301, 302, 303, 307, 308) and location:
                # если Location уходит наружу – помечаем
                ext = not location.startswith("/") and "target" not in location
                findings.append(
                    {
                        "payload": payload,
                        "url": test_url,
                        "status": status,
                        "location": location,
                        "external": ext,
                    }
                )

    if not findings:
        await update.message.reply_text(
            "Я не увидел явных open redirect по базовым payload'ам.\n"
            "Но всё равно стоит вручную погонять редиректы через Burp."
        )
        return

    lines = ["🔥 RedirectHunter отчёт:", ""]
    for i, f in enumerate(findings, start=1):
        mark = "❗️" if f["external"] else "ℹ️"
        lines.append(
            f"{i}. {mark} [HTTP {f['status']}] {f['url']}\n"
            f"   Location: {f['location']}"
        )

    lines.append(
        "\n❗️ Если Location уходит на внешний домен – это сильный кандидат на Open Redirect.\n"
        "Обязательно перепроверь вручную и не эксплуатируй вне легального scope."
    )

    await update.message.reply_text("\n".join(lines))
