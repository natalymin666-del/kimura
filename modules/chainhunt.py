import aiohttp
from telegram import Update
from telegram.ext import ContextTypes

INTERESTING_COOKIES = ["session", "auth", "token", "jwt", "sid"]


async def chainhunt_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /chainhunt https://site.com/profile
    Собирает заголовки, Set-Cookie и подсказывает возможные exploit-цепочки.
    """
    if not context.args:
        await update.message.reply_text(
            "Формат: /chainhunt URL\n"
            "Например:\n"
            "/chainhunt https://example.com/profile"
        )
        return

    url = context.args[0].strip()

    await update.message.reply_text(
        "🧬 ChainHunt: собираю базовую информацию о цели…"
    )

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10, allow_redirects=True) as resp:
                text = await resp.text(errors="ignore")
                headers = dict(resp.headers)
                status = resp.status
        except Exception as e:
            await update.message.reply_text(f"Не получилось подключиться: {e}")
            return

    missing_headers = []
    for h in [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
    ]:
        if h not in headers:
            missing_headers.append(h)

    cookies_hdr = headers.get("Set-Cookie", "")
    cookie_hits = [
        name for name in INTERESTING_COOKIES if name.lower() in cookies_hdr.lower()
    ]

    chains = []

    # Примеры идей цепочек (мы НИЧЕГО не эксплуатируем, только подсказываем)
    if cookie_hits and "Content-Security-Policy" not in headers:
        chains.append(
            "🍪 возможна цепочка «XSS ➜ кража session-cookie», "
            "если найдёшь работающую XSS (нет CSP, есть чувствительные cookie)."
        )

    if "Location" in headers and status in (301, 302, 303, 307, 308):
        chains.append(
            "🔁 есть редиректы — можно искать open redirect и связывать его с "
            "аутентификацией (session fixation / OAuth-flows)."
        )

    if "application/json" in headers.get("Content-Type", "").lower():
        chains.append(
            "📦 JSON-ответ — проверь API на IDOR, mass assignment, "
            "а затем свяжи это с отсутствием заголовков безопасности."
        )

    if not chains and missing_headers:
        chains.append(
            "Общая идея: совмещай отсутствие заголовков с XSS/redirect/IDOR, "
            "чтобы собрать серьёзную exploit-цепочку."
        )

    summary = [
        f"🧬 ChainHunt отчёт для: {url}",
        f"HTTP статус: {status}",
        "",
    ]

    if missing_headers:
        summary.append(
            "Отсутствуют важные security-заголовки:\n- " + "\n- ".join(missing_headers)
        )
    else:
        summary.append("Ключевые security-заголовки на месте.")

    summary.append("")

    if cookie_hits:
        summary.append(
            "В Set-Cookie замечены потенциально чувствительные cookie:\n- "
            + "\n- ".join(cookie_hits)
        )
    else:
        summary.append("Чувствительных cookie в Set-Cookie я не увидел.")

    summary.append("")

    if chains:
        summary.append(
            "Возможные exploit-цепочки (это только идеи, ничего не эксплуатируется):\n"
            + "\n".join(f"- {c}" for c in chains)
        )
    else:
        summary.append(
            "Пока не вижу явной цепочки — но всегда пробуй связать XSS / IDOR / SSRF "
            "с авторизацией, токенами, файлами и т.п."
        )

    await update.message.reply_text("\n".join(summary))
