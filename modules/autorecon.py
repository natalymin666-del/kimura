# modules/autorecon.py

import textwrap
from urllib.parse import urlparse, urljoin

import aiohttp
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import ContextTypes

# Какие security-заголовки нас интересуют
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


async def fetch(session: aiohttp.ClientSession, url: str, *, allow_redirects: bool = True):
    """Аккуратно забираем страницу, чтобы не падало при ошибках."""
    try:
        async with session.get(url, allow_redirects=allow_redirects, timeout=10) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, resp.headers, text
    except Exception as e:
        return None, {}, f"ERROR: {e}"


def normalize_target(raw: str) -> str:
    """Делаем из домена нормальный URL."""
    raw = raw.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        return "https://" + raw
    return raw


async def autorecon_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда /autorecon — умный автопрофиль цели."""
    if not context.args:
        await update.message.reply_text(
            "Использование: /autorecon пример.com\n"
            "Делаю быстрый автопрофиль цели (заголовки, формы, базовые векторы атак).\n"
            "Используй только там, где у тебя есть разрешение."
        )
        return

    raw = context.args[0]
    base_url = normalize_target(raw)
    parsed = urlparse(base_url)
    domain = parsed.netloc

    await update.message.reply_text(
        f"🧠 AutoRecon AI для: {domain}\n"
        f"Собираю базовую информацию о цели…"
    )

    # Что смотрим на цели
    interesting_paths = [
        "/",                          # главная
        "/login",
        "/signin",
        "/admin",
        "/api",
        "/robots.txt",
        "/.well-known/security.txt",
    ]

    results = {}

    async with aiohttp.ClientSession() as session:
        for path in interesting_paths:
            url = urljoin(f"{parsed.scheme}://{domain}", path)
            status, headers, text = await fetch(session, url)
            results[path] = (status, headers, text)

    # Главная страница
    main_status, main_headers, main_html = results.get("/", (None, {}, ""))

    missing_headers = []
    present_headers = []

    if main_headers:
        for h in SECURITY_HEADERS:
            if h in main_headers:
                present_headers.append(h)
            else:
                missing_headers.append(h)

    # Анализ cookie
    set_cookie_headers = [
        v for k, v in main_headers.items() if k.lower() == "set-cookie"
    ]
    cookie_risks = []
    for c in set_cookie_headers:
        low = c.lower()
        if "secure" not in low:
            cookie_risks.append("cookie без флага Secure")
        if "httponly" not in low:
            cookie_risks.append("cookie без флага HttpOnly")

    # Формы + намёки на API / авторизацию
    forms_info = []
    api_hints = set()

    if isinstance(main_html, str) and main_html:
        soup = BeautifulSoup(main_html, "html.parser")

        # формы
        for form in soup.find_all("form"):
            action = form.get("action") or "(нет action)"
            method = (form.get("method") or "GET").upper()
            full_action = urljoin(base_url, action)
            forms_info.append(f"- {method} → {full_action}")

        # простые эвристики по интересным словам
        text_lower = main_html.lower()
        patterns = [
            "api.",
            "/api/",
            "graphql",
            "bearer ",
            "authorization",
            "token=",
            "jwt",
            "/v1/",
            "/v2/",
        ]
        for p in patterns:
            if p in text_lower:
                api_hints.add(p)

    # robots.txt
    robots_status, _, robots_txt = results.get("/robots.txt", (None, {}, ""))
    robots_lines = []
    if robots_status == 200 and isinstance(robots_txt, str):
        for line in robots_txt.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                robots_lines.append(line)

    # security.txt
    sec_status, _, _ = results.get("/.well-known/security.txt", (None, {}, ""))
    have_security_txt = sec_status == 200

    # Сбор отчёта
    lines = []
    lines.append(f"🔥 AutoRecon отчёт для: {domain}")
    lines.append("")
    lines.append(
        "HTTP статус главной страницы: "
        + (str(main_status) if main_status is not None else "нет ответа")
    )

    if present_headers or missing_headers:
        lines.append("")
        lines.append("🧩 Security-заголовки:")
        if present_headers:
            lines.append("✅ Найдены: " + ", ".join(present_headers))
        if missing_headers:
            lines.append("⚠️ Отсутствуют: " + ", ".join(missing_headers))

    if cookie_risks:
        lines.append("")
        lines.append("🍪 Риски по cookie:")
        for r in sorted(set(cookie_risks)):
            lines.append(f"- {r}")

    if forms_info:
        lines.append("")
        lines.append("📥 Найденные формы:")
        for f in forms_info[:5]:
            lines.append(f)
        if len(forms_info) > 5:
            lines.append(f"... и ещё {len(forms_info) - 5} форм(ы)")

    if api_hints:
        lines.append("")
        lines.append("🧵 Подозрительные ключевые слова (API/авторизация):")
        for h in sorted(api_hints):
            lines.append(f"- «{h}»")

    if robots_lines:
        lines.append("")
        lines.append("🤖 Интересные правила из robots.txt:")
        for l in robots_lines[:5]:
            lines.append(l)
        if len(robots_lines) > 5:
            lines.append(f"... и ещё {len(robots_lines) - 5} строк(и)")

    lines.append("")
    lines.append("🔍 Возможные векторы (идеи, ничего не эксплуатируется):")

    if "Content-Security-Policy" in missing_headers:
        lines.append("- XSS / Clickjacking → нет CSP, проверь формы и отражения.")
    if "X-Frame-Options" in missing_headers:
        lines.append("- Clickjacking → страница может встраиваться в iframe.")
    if "X-Content-Type-Options" in missing_headers:
        lines.append("- MIME-sniffing → проверь загрузку файлов.")
    if "Strict-Transport-Security" in missing_headers and parsed.scheme == "https":
        lines.append("- HSTS → проверь, доступен ли http:// и downgrade атаки.")
    if api_hints:
        lines.append("- API → проверь auth-bypass, IDOR, rate-limit, лишние данные.")
    if forms_info:
        lines.append("- Формы → XSS, CSRF, bruteforce, слабая валидация.")

    if have_security_txt:
        lines.append("")
        lines.append("📜 Найден security.txt — у цели есть политика безопасности.")

    lines.append("")
    lines.append(
        "Напоминание: используй результаты только в рамках легального pentest/bug bounty."
    )

    report = "\n".join(lines)

    # Ограничение Telegram ~4096 символов
    if len(report) > 3900:
        report = report[:3900] + "\n\n(отчёт обрезан, сделай более точечный анализ)"

    await update.message.reply_text(report)
