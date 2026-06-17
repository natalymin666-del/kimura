import re
from urllib.parse import urlparse

import requests
from telegram import Update
from telegram.ext import ContextTypes

TIMEOUT = 8


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    return target


def detect_from_headers(headers: dict) -> list[str]:
    tech = []

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    via = headers.get("Via", "")
    cf_ray = headers.get("CF-RAY", "") or headers.get("cf-ray", "")

    if server:
        tech.append(f"Web-server: {server}")

        if "nginx" in server.lower():
            tech.append("🔹 nginx")
        if "apache" in server.lower():
            tech.append("🔹 Apache HTTPD")
        if "iis" in server.lower():
            tech.append("🔹 Microsoft IIS")

    if powered:
        tech.append(f"X-Powered-By: {powered}")
        low = powered.lower()
        if "php" in low:
            tech.append("🔹 PHP backend")
        if "asp.net" in low:
            tech.append("🔹 ASP.NET")
        if "node" in low or "express" in low:
            tech.append("🔹 Node.js / Express")
        if "laravel" in low:
            tech.append("🔹 Laravel (PHP)")
        if "django" in low:
            tech.append("🔹 Django (Python)")

    if cf_ray or "cloudflare" in server.lower():
        tech.append("🔹 Cloudflare (CDN/WAF)")

    if via:
        tech.append(f"Via: {via}")

    return tech


def detect_from_html(html: str) -> list[str]:
    tech = []
    low = html.lower()

    # CMS
    if "wp-content" in low or "wp-includes" in low:
        tech.append("🔹 WordPress")
    if "content=\"joomla!" in low:
        tech.append("🔹 Joomla!")
    if "content=\"drupal" in low:
        tech.append("🔹 Drupal")
    if "shopify" in low or "cdn.shopify.com" in low:
        tech.append("🔹 Shopify")
    if "content=\"woocommerce" in low:
        tech.append("🔹 WooCommerce (WordPress)")

    # JS фреймворки
    if "react-dom" in low or "data-reactroot" in low:
        tech.append("🔹 React")
    if "vue.js" in low or "vue.runtime" in low:
        tech.append("🔹 Vue.js")
    if "ng-version" in low or "angular.js" in low:
        tech.append("🔹 Angular")

    # Analytics / трекинг
    if "www.googletagmanager.com/gtm.js" in low or "www.google-analytics.com/analytics.js" in low:
        tech.append("🔹 Google Analytics / GTM")
    if "yandex.metrika" in low:
        tech.append("🔹 Yandex.Metrika")

    # Meta generator
    meta_generators = re.findall(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        flags=re.IGNORECASE,
    )
    for gen in meta_generators:
        tech.append(f"Meta generator: {gen}")

    return tech


def detect_cookies(headers: dict) -> list[str]:
    tech = []
    set_cookie = headers.get("Set-Cookie", "")
    low = set_cookie.lower()

    if "wordpress_" in low or "wp-" in low:
        tech.append("🔹 Cookies похожи на WordPress")
    if "laravel_session" in low:
        tech.append("🔹 Cookies похожи на Laravel")
    if "django" in low:
        tech.append("🔹 Cookies похожи на Django session")
    if "asp.net_sessionid" in low:
        tech.append("🔹 Cookies похожи на ASP.NET session")

    return tech


async def techscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /techscan домен — анализ технологий сайта (whatweb-lite).
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/techscan tesla.com"
        )
        return

    target = context.args[0]
    url = normalize_url(target)

    await update.message.reply_text(
        f"🔍 Загружаю {url} для анализа технологий…"
    )

    try:
        resp = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=True,
        )
    except requests.RequestException as e:
        await update.message.reply_text(
            f"❌ Не удалось загрузить {url}.\n"
            f"Ошибка: {e}"
        )
        return

    final_url = resp.url
    headers = {k: v for k, v in resp.headers.items()}
    html = resp.text

    all_tech: list[str] = []

    # Детект по заголовкам
    all_tech.extend(detect_from_headers(headers))

    # Детект по HTML
    all_tech.extend(detect_from_html(html))

    # Детект по cookies
    all_tech.extend(detect_cookies(headers))

    # Убираем дубли
    seen = set()
    uniq_tech = []
    for t in all_tech:
        if t not in seen:
            uniq_tech.append(t)
            seen.add(t)

    lines: list[str] = []
    parsed = urlparse(final_url)
    host = parsed.netloc

    lines.append(f"🧬 Tech fingerprint для: {target}")
    lines.append(f"Финальный URL: {final_url}")
    lines.append(f"Хост: {host}")
    lines.append("")

    if not uniq_tech:
        lines.append("Не удалось явно определить технологии.\n"
                     "Сайт может быть очень минималистичным или хорошо скрывать стек.")
    else:
        lines.append("Обнаруженные технологии и признаки:")
        for t in uniq_tech:
            lines.append(f"• {t}")

    lines.append("")
    lines.append(
        "Используй это как быстрый whatweb-lite перед более глубоким "
        "анализом (Wappalyzer, nuclei, ручной разбор)."
    )

    text = "\n".join(lines)

    await update.message.reply_text(
        text,
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )
