import re
from urllib.parse import urljoin, urlparse

import requests
from telegram import Update
from telegram.ext import ContextTypes

TIMEOUT = 10

# /urls (basic recon)
WAYBACK_LIMIT = 200        # сколько максимум URL брать из Wayback
SITEMAP_MAX_LOCS = 1000    # максимум URL, которые берём из sitemap.xml
MAINPAGE_MAX_URLS = 500    # максимум ссылок с главной
TOTAL_MAX_URLS = 1500      # максимум уникальных URL после очистки

# /deepurls (deep recon)
DEEP_MAX_PAGES = 15          # максимум HTML-страниц, которые обойдёт спайдер
DEEP_MAX_URLS = 3000         # максимум сырых URL из спайдера
DEEP_MAX_JS_FILES = 20       # сколько JS-файлов максимум качать
DEEP_MAX_JS_ENDPOINTS = 1000 # максимум эндпоинтов, вытянутых из JS


# ================== БАЗОВЫЕ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==================

def normalize_domain(raw: str) -> str:
    raw = raw.strip()
    raw = raw.replace("https://", "").replace("http://", "")
    raw = raw.split("/")[0]
    return raw


def fetch_wayback_urls(domain: str) -> list[str]:
    """
    Забираем URL из Wayback Machine (CDX API).
    """
    api = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(WAYBACK_LIMIT),
    }
    try:
        resp = requests.get(api, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        # первая строка — заголовок, дальше URL
        urls = [row[0] for row in data[1:]]
        return urls
    except Exception:
        return []


def fetch_sitemap_urls(domain: str) -> list[str]:
    """
    Пытаемся скачать sitemap.xml и вытащить URL.
    Ограничиваем количество найденных ссылок.
    """
    urls: list[str] = []
    for scheme in ("https", "http"):
        sitemap_url = f"{scheme}://{domain}/sitemap.xml"
        try:
            resp = requests.get(sitemap_url, timeout=TIMEOUT)
            if resp.status_code != 200:
                continue
            text = resp.text
            locs = re.findall(r"<loc>(.*?)</loc>", text)
            urls.extend(locs)
            if len(urls) >= SITEMAP_MAX_LOCS:
                urls = urls[:SITEMAP_MAX_LOCS]
                break
        except Exception:
            continue
    return urls


def fetch_mainpage_urls(domain: str) -> list[str]:
    """
    Загружаем главную и вынимаем ссылки <a href="...">.
    Ограничиваем количество собранных ссылок.
    """
    collected: list[str] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(url, timeout=TIMEOUT)
        except Exception:
            continue

        base = resp.url
        html = resp.text

        hrefs = re.findall(r'href=["\']([^"\']+)["\']', html)
        for h in hrefs:
            if h.startswith("#") or h.startswith("mailto:") or h.startswith("javascript:"):
                continue
            full = urljoin(base, h)
            collected.append(full)
            if len(collected) >= MAINPAGE_MAX_URLS:
                break

        if len(collected) >= MAINPAGE_MAX_URLS:
            break

    return collected


def clean_urls(urls: list[str], domain: str) -> list[str]:
    """
    Чистим URL:
    - только http/https
    - только наш домен
    - убираем дубли и якоря
    """
    result = set()
    for u in urls:
        u = u.strip()
        if not u:
            continue
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https"):
            continue
        host = parsed.netloc
        if not host.endswith(domain):
            continue
        clean = u.split("#")[0]
        result.add(clean)

    cleaned = sorted(result)
    if len(cleaned) > TOTAL_MAX_URLS:
        cleaned = cleaned[:TOTAL_MAX_URLS]
    return cleaned


# ================== DEEP RECON ВСПОМОГАТЕЛЬНЫЕ ==================

def is_static_asset(path: str) -> bool:
    """
    Помогает отсекать картинки, шрифты, архивы и т.п.
    Чтобы спайдер не лазил по мусору.
    """
    path = path.lower()
    static_ext = (
        ".jpg", ".jpeg", ".png", ".gif", ".svg",
        ".ico", ".css", ".pdf", ".zip", ".rar", ".7z",
        ".mp4", ".mp3", ".webm",
        ".woff", ".woff2", ".ttf", ".eot",
        ".exe", ".msi", ".dmg",
    )
    return any(path.endswith(ext) for ext in static_ext)


def spider_domain(domain: str) -> list[str]:
    """
    Простой ограниченный спайдер:
    - начинает с https:// и http://
    - обходит до DEEP_MAX_PAGES страниц
    - собирает все <a href> и src=...
    """
    start_urls = [f"https://{domain}", f"http://{domain}"]
    visited_pages: set[str] = set()
    to_visit: list[str] = []
    collected: set[str] = set()

    for u in start_urls:
        to_visit.append(u)

    while to_visit and len(visited_pages) < DEEP_MAX_PAGES and len(collected) < DEEP_MAX_URLS:
        current = to_visit.pop(0)
        if current in visited_pages:
            continue
        visited_pages.add(current)

        try:
            resp = requests.get(current, timeout=TIMEOUT)
        except Exception:
            continue

        if resp.status_code >= 400:
            continue

        base = resp.url
        html = resp.text

        # ссылки в href и src
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', html)
        srcs = re.findall(r'src=["\']([^"\']+)["\']', html)

        for raw in hrefs + srcs:
            raw = raw.strip()
            if not raw:
                continue
            if raw.startswith("#") or raw.startswith("mailto:") or raw.startswith("javascript:"):
                continue

            full = urljoin(base, raw)
            collected.add(full)

            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https"):
                continue
            if not parsed.netloc.endswith(domain):
                continue

            path = parsed.path or "/"
            if is_static_asset(path):
                continue

            if full not in visited_pages and full not in to_visit:
                if len(to_visit) < DEEP_MAX_PAGES * 5:
                    to_visit.append(full)

            if len(collected) >= DEEP_MAX_URLS:
                break

        if len(collected) >= DEEP_MAX_URLS:
            break

    return list(collected)


def extract_js_endpoints(domain: str, html_pages: list[str]) -> list[str]:
    """
    Берём HTML-страницы, находим <script src="...js">,
    качаем сами JS-файлы и выдёргиваем потенциальные эндпоинты вида "/api/...", "/v1/..."
    """
    js_urls: set[str] = set()

    # сначала собираем JS-URL из HTML-страниц
    for page_url in html_pages[:DEEP_MAX_PAGES]:
        try:
            resp = requests.get(page_url, timeout=TIMEOUT)
        except Exception:
            continue
        if resp.status_code >= 400:
            continue

        base = resp.url
        html = resp.text
        scripts = re.findall(
            r'script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            html,
            flags=re.IGNORECASE,
        )
        for s in scripts:
            full_js = urljoin(base, s)
            js_urls.add(full_js)
            if len(js_urls) >= DEEP_MAX_JS_FILES:
                break
        if len(js_urls) >= DEEP_MAX_JS_FILES:
            break

    endpoints: set[str] = set()

    # качаем сами JS и выдёргиваем строки, похожие на эндпоинты
    for js_url in list(js_urls)[:DEEP_MAX_JS_FILES]:
        try:
            resp = requests.get(js_url, timeout=TIMEOUT)
        except Exception:
            continue
        if resp.status_code >= 400:
            continue

        text = resp.text

        candidates = re.findall(
            r'["\'](/[^"\'\s]{3,})["\']',
            text
        )
        for c in candidates:
            if " " in c:
                continue
            if c.startswith("//"):
                continue

            full = f"https://{domain}{c}"
            endpoints.add(full)

            if len(endpoints) >= DEEP_MAX_JS_ENDPOINTS:
                break

        if len(endpoints) >= DEEP_MAX_JS_ENDPOINTS:
            break

    return list(endpoints)


# ================== КОМАНДЫ ==================

async def urls_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /urls домен — сбор уникальных URL из Wayback, sitemap и главной страницы.
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/urls tesla.com"
        )
        return

    domain = normalize_domain(context.args[0])

    await update.message.reply_text(
        f"📡 Сбор URL для: {domain}\n"
        "Источники: Wayback, sitemap.xml, главная страница…"
    )

    all_urls: list[str] = []

    # 1) Wayback
    wb = fetch_wayback_urls(domain)
    if wb:
        all_urls.extend(wb)

    # 2) sitemap.xml
    sm = fetch_sitemap_urls(domain)
    if sm:
        all_urls.extend(sm)

    # 3) главная страница
    mp = fetch_mainpage_urls(domain)
    if mp:
        all_urls.extend(mp)

    cleaned = clean_urls(all_urls, domain)

    if not cleaned:
        await update.message.reply_text(
            "Не удалось собрать URL.\n"
            "Возможно, у домена нет архива в Wayback и sitemap, или они временно недоступны."
        )
        return

    max_show = 150
    to_show = cleaned[:max_show]

    lines: list[str] = []
    lines.append(f"Найдено уникальных URL: {len(cleaned)}")
    if len(cleaned) > max_show:
        lines.append(f"(показаны первые {max_show})")
    lines.append("")

    for u in to_show:
        lines.append(u)

    lines.append("")
    lines.append(
        "Совет: сохрани эти URL и корми их в Burp, ffuf, kxss, nuclei и другие инструменты.\n"
        "Это базовый шаг для bug bounty recon."
    )

    text = "\n".join(lines)

    chunk_size = 3500
    for i in range(0, len(text), chunk_size):
        await update.message.reply_text(
            text[i:i + chunk_size],
            disable_web_page_preview=True,
        )


async def deepurls_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /deepurls домен — глубокий сбор URL:
    - Wayback
    - sitemap.xml
    - главная страница
    - спайдер (несколько внутренних страниц)
    - простое извлечение эндпоинтов из JS
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/deepurls tesla.com"
        )
        return

    domain = normalize_domain(context.args[0])

    await update.message.reply_text(
        f"🚀 Deep recon для: {domain}\n"
        "Источники: Wayback, sitemap.xml, главная, спайдер, JS-эндпоинты…"
    )

    all_urls: list[str] = []

    # 1) Wayback
    wb = fetch_wayback_urls(domain)
    if wb:
        all_urls.extend(wb)

    # 2) sitemap.xml
    sm = fetch_sitemap_urls(domain)
    if sm:
        all_urls.extend(sm)

    # 3) главная страница
    mp = fetch_mainpage_urls(domain)
    if mp:
        all_urls.extend(mp)

    # 4) спайдер по домену
    spider_raw = spider_domain(domain)
    if spider_raw:
        all_urls.extend(spider_raw)

    # 5) JS-эндпоинты
    html_like = []
    for u in spider_raw[:DEEP_MAX_PAGES]:
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https"):
            continue
        if not parsed.netloc.endswith(domain):
            continue
        if is_static_asset(parsed.path or "/"):
            continue
        html_like.append(u)

    js_eps = extract_js_endpoints(domain, html_like)
    if js_eps:
        all_urls.extend(js_eps)

    cleaned = clean_urls(all_urls, domain)

    if not cleaned:
        await update.message.reply_text(
            "Не удалось собрать URL даже в deep-режиме.\n"
            "Возможно, домен очень закрытый или источники временно недоступны."
        )
        return

    max_show = 200
    to_show = cleaned[:max_show]

    lines: list[str] = []
    lines.append(f"Deep-режим: найдено уникальных URL: {len(cleaned)}")
    if len(cleaned) > max_show:
        lines.append(f"(показаны первые {max_show})")
    lines.append("")

    for u in to_show:
        lines.append(u)

    lines.append("")
    lines.append(
        "Совет: используй эти URL и эндпоинты с Burp, ffuf, kxss, nuclei.\n"
        "Отдельно проверь /api/* и другие пути из JS — там часто живут дорогие баги."
    )

    text = "\n".join(lines)

    chunk_size = 3500
    for i in range(0, len(text), chunk_size):
        await update.message.reply_text(
            text[i:i + chunk_size],
            disable_web_page_preview=True,
        )
