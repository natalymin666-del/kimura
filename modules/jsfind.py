import re
from urllib.parse import urljoin, urlparse

import requests
from telegram import Update
from telegram.ext import ContextTypes

TIMEOUT = 8


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    return target


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """
    Ищем .js в атрибутах src= и href= и приводим к абсолютным URL.
    Без BeautifulSoup, только regex.
    """
    # Ищем src="..." и src='...'
    pattern = r'''(?:src|href)\s*=\s*["']([^"']+\.js[^"']*)["']'''
    candidates = re.findall(pattern, html, flags=re.IGNORECASE)

    urls = set()

    for c in candidates:
        # Приводим относительные пути к абсолютным
        full = urljoin(base_url, c)
        # Чуть чистим
        parsed = urlparse(full)
        if not parsed.scheme.startswith("http"):
            continue
        # убираем якоря
        clean = full.split("#")[0]
        urls.add(clean)

    return sorted(urls)


async def jsfind_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /jsfind домен — поиск JS-файлов на главной странице.
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/jsfind tesla.com"
        )
        return

    target = context.args[0]
    url = normalize_url(target)

    await update.message.reply_text(
        f"🔍 Загружаю главную страницу: {url}\n"
        f"Ищу подключённые .js-файлы…"
    )

    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=True)
        html = resp.text
    except requests.RequestException as e:
        await update.message.reply_text(
            f"❌ Не удалось загрузить {url}.\n"
            f"Ошибка: {e}"
        )
        return

    js_urls = extract_js_urls(html, resp.url)

    if not js_urls:
        await update.message.reply_text(
            "JS-файлы на главной странице не найдены "
            "или страница очень минималистична."
        )
        return

    max_show = 40
    show_list = js_urls[:max_show]

    lines: list[str] = []
    lines.append(f"📦 Найдено JS-файлов на {resp.url}: {len(js_urls)}")
    if len(js_urls) > max_show:
        lines.append(f"(показаны первые {max_show})")
    lines.append("")

    for u in show_list:
        lines.append(f"• {u}")

    lines.append("")
    lines.append(
        "Используй эти JS-файлы для ручного анализа:\n"
        "– ищи скрытые API endpoints\n"
        "– токены/ключи\n"
        "– внутренние домены и пути\n"
        "– debug-логи."
    )

    text = "\n".join(lines)

    await update.message.reply_text(
        text,
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )
