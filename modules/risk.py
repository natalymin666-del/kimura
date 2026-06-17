import requests
from telegram import Update
from telegram.ext import ContextTypes

# Таймаут, чтобы не висеть вечно
TIMEOUT = 7

def build_domain_url(domain: str) -> str:
    domain = domain.strip()
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "https://" + domain
    return domain

def analyze_security(headers: dict, url: str) -> str:
    lines = []

    # Базовая информация
    lines.append(f"🛡 Security quick-check для цели: {url}\n")

    # 1. HSTS
    hsts = headers.get("Strict-Transport-Security")
    if hsts:
        lines.append(f"• Strict-Transport-Security: ✅ задан ({hsts[:80]}...)")
    else:
        lines.append("• Strict-Transport-Security: ❌ отсутствует")

    # 2. Content-Security-Policy
    csp = headers.get("Content-Security-Policy")
    if csp:
        lines.append("• Content-Security-Policy: ✅ задан")
    else:
        lines.append("• Content-Security-Policy: ❌ отсутствует")

    # 3. X-Frame-Options
    xfo = headers.get("X-Frame-Options")
    if xfo:
        lines.append(f"• X-Frame-Options: ✅ {xfo}")
    else:
        lines.append("• X-Frame-Options: ❌ отсутствует")

    # 4. X-Content-Type-Options
    xcto = headers.get("X-Content-Type-Options")
    if xcto:
        lines.append(f"• X-Content-Type-Options: ✅ {xcto}")
    else:
        lines.append("• X-Content-Type-Options: ❌ отсутствует")

    # 5. Referrer-Policy
    rp = headers.get("Referrer-Policy")
    if rp:
        lines.append(f"• Referrer-Policy: ✅ {rp}")
    else:
        lines.append("• Referrer-Policy: ❌ отсутствует")

    # 6. X-XSS-Protection (legacy, но иногда полезен)
    xss = headers.get("X-XSS-Protection")
    if xss:
        lines.append(f"• X-XSS-Protection: ✅ {xss}")
    else:
        lines.append("• X-XSS-Protection: ❌ отсутствует")

    # 7. Очень грубая оценка куки
    cookies_header = headers.get("Set-Cookie", "")
    if cookies_header:
        has_secure = "secure" in cookies_header.lower()
        has_httponly = "httponly" in cookies_header.lower()
        if has_secure and has_httponly:
            lines.append("• Cookies: ✅ есть Secure и HttpOnly (по Set-Cookie)")
        else:
            lines.append("• Cookies: ⚠️ Set-Cookie найден, но Secure/HttpOnly не везде")
    else:
        lines.append("• Cookies: ℹ️ Set-Cookie не найден в ответе")

    # Мини-вывод
    missing_critical = sum(
        1 for text in lines
        if "❌" in text and any(
            key in text for key in [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
            ]
        )
    )

    lines.append("")
    if missing_critical == 0:
        lines.append("✅ Быстрый чек: критичных проблем по заголовкам не видно.")
    elif missing_critical <= 2:
        lines.append("⚠️ Быстрый чек: есть несколько потенциальных проблем — стоит изучить глубже.")
    else:
        lines.append("❌ Быстрый чек: много важных security-заголовков отсутствует. Цель может быть уязвима.")

    lines.append("")
    lines.append("Используй это как старт перед глубоким анализом (Burp, nmap, nuclei и т.п.).")

    return "\n".join(lines)


async def risk_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Получаем домен из сообщения
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/risk tesla.com\n"
            "/risk https://example.com"
        )
        return

    domain = " ".join(context.args)
    url = build_domain_url(domain)

    try:
        await update.message.reply_text(f"🔍 Запускаю security-чек для: {url} ...")

        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=True)
        headers = {k: v for k, v in resp.headers.items()}

        text = analyze_security(headers, url)
        await update.message.reply_text(text)

    except requests.exceptions.SSLError:
        await update.message.reply_text(
            "❌ Ошибка SSL при подключении к цели. "
            "Попробуй указать домен без http/https или проверь сертификат."
        )
    except requests.exceptions.RequestException as e:
        await update.message.reply_text(
            f"❌ Не удалось выполнить запрос к {url}.\n"
            f"Ошибка: {e}"
        )
