import re
from urllib.parse import urlparse, urljoin, parse_qs

import requests
from telegram import Update
from telegram.ext import ContextTypes

from modules.urls import (
    normalize_domain,
    fetch_mainpage_urls,
    fetch_sitemap_urls,
    fetch_wayback_urls,
    spider_domain,
    clean_urls,
)

TIMEOUT = 10

# Ограничения, чтобы не ушатать цель
MAX_HTML_PAGES = 10
MAX_JS_FILES = 20
MAX_ENDPOINTS = 180


# --- Вспомогательные регулярки ---

# Любой http/https URL внутри JS/HTML
FULL_URL_RE = re.compile(r'https?://[^\s"\'<>]+')

# Относительные API-пути типа "/api/v1/users" и похожие
REL_API_RE = re.compile(
    r'["\'](/(?:api/|v[0-9]+/|graphql/|auth/|oauth/|user/|account/|admin/|'
    r'backend/|internal/|rest/|service/)[^"\']*)["\']',
    re.IGNORECASE,
)

# fetch("url", { method: "POST" ... })
FETCH_RE = re.compile(
    r'fetch\(\s*["\']([^"\']+)["\']\s*,\s*{[^}]*?method\s*:\s*["\']([A-Z]+)["\']',
    re.IGNORECASE | re.DOTALL,
)

# fetch("url") без явного метода (GET)
FETCH_SIMPLE_RE = re.compile(
    r'fetch\(\s*["\']([^"\']+)["\']\s*\)',
    re.IGNORECASE,
)

# axios.post("url"...)
AXIOS_RE = re.compile(
    r'axios\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# xhr.open("POST", "url", ...)
XHR_RE = re.compile(
    r'\.open\(\s*["\'](GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# <script src="...">
SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# inline JS
INLINE_SCRIPT_RE = re.compile(
    r'<script[^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


# --- Классификация эндпоинтов ---

HIGH_KEYWORDS = {
    "auth": ["auth", "login", "signin", "oauth", "sso", "token", "refresh"],
    "admin": ["admin", "root", "super", "staff", "backoffice"],
    "user": ["user", "account", "profile", "session"],
    "payment": ["payment", "pay", "card", "billing", "invoice", "checkout"],
    "file": ["upload", "download", "export", "import", "file"],
    "graphql": ["graphql"],
}

MEDIUM_KEYWORDS = {
    "debug": ["debug", "test", "dev", "staging", "sandbox"],
    "search": ["search", "query", "lookup"],
    "report": ["report", "stats", "analytics"],
    "config": ["config", "settings"],
}

PARAM_TAGS = {
    "id": ["id", "user_id", "uid", "account_id"],
    "redirect": ["redirect", "redirect_url", "redirect_uri", "next", "return", "continue", "dest", "destination", "url"],
    "token": ["token", "access_token", "auth_token", "id_token", "jwt"],
    "file": ["file", "path", "filename", "filepath"],
    "search": ["q", "query", "search"],
}


def classify_endpoint(url: str, method: str) -> tuple[str, list[str], list[str]]:
    """
    Классифицируем эндпоинт по URL/методу/параметрам.
    Возвращаем (severity, tags, reasons).
    """
    parsed = urlparse(url)
    path = parsed.path.lower()
    m = method.upper()
    qs = parse_qs(parsed.query, keep_blank_values=True)
    param_names = {k.lower() for k in qs.keys()}

    tags: list[str] = []
    reasons: list[str] = []

    severity = "low"

    # HIGH по ключевым словам в пути
    for tag, kws in HIGH_KEYWORDS.items():
        if any(kw in path for kw in kws):
            tags.append(tag)
            reasons.append(f"ключевое слово '{tag}' в пути")
            severity = "high"

    # GraphQL
    if "graphql" in path:
        if "graphql" not in tags:
            tags.append("graphql")
        reasons.append("GraphQL endpoint")
        severity = "high"

    # Payment/Auth/Admin/User + опасные методы
    if m in ("POST", "PUT", "DELETE", "PATCH") and any(
        kw in path for kw in (
            "auth", "login", "token", "admin",
            "user", "profile", "payment", "card",
        )
    ):
        reasons.append(f"чувствительный путь + метод {m}")
        severity = "high"

    # MEDIUM по менее критичным ключам
    if severity == "low":
        for tag, kws in MEDIUM_KEYWORDS.items():
            if any(kw in path for kw in kws):
                tags.append(tag)
                reasons.append(f"ключевое слово '{tag}' в пути")
                severity = "medium"
                break

    # Анализ параметров
    param_based_tags: list[str] = []
    for tag, names in PARAM_TAGS.items():
        if any(n in param_names for n in names):
            param_based_tags.append(tag)

    if param_based_tags:
        tags.extend(param_based_tags)
        reasons.append("чувствительные параметры: " + ", ".join(param_based_tags))

    # /api/* c небезопасным методом
    if severity == "low" and m in ("POST", "PUT", "DELETE", "PATCH") and "/api/" in path:
        severity = "medium"
        reasons.append(f"метод {m} на /api/")

    # redirect-параметры
    if any(p in param_names for p in PARAM_TAGS["redirect"]):
        if severity == "low":
            severity = "medium"
        if "redirect" not in tags:
            tags.append("redirect")
        reasons.append("параметр redirect/next/url (проверь на open redirect)")

    # если вообще ничего не нашли
    if not tags:
        tags.append("generic")

    # убираем дубли
    tags = sorted(set(tags))
    reasons = sorted(set(reasons))

    return severity, tags, reasons


# --- Сбор URL по сайту ---

def collect_site_urls(domain: str) -> list[str]:
    """
    Собираем разные URL сайта: sitemap, главная, spider, немного Wayback.
    """
    all_urls: list[str] = []

    sm = fetch_sitemap_urls(domain)
    if sm:
        all_urls.extend(sm)

    mp = fetch_mainpage_urls(domain)
    if mp:
        all_urls.extend(mp)

    try:
        sp = spider_domain(domain)
        if sp:
            all_urls.extend(sp)
    except Exception:
        pass

    # чуть-чуть Wayback (он сам ограничен внутри)
    try:
        wb = fetch_wayback_urls(domain)
        if wb:
            all_urls.extend(wb)
    except Exception:
        pass

    cleaned = clean_urls(all_urls, domain)
    return cleaned


# --- Сбор HTML-страниц ---

def collect_html_pages(domain: str, site_urls: list[str]) -> list[str]:
    """
    Берём немного HTML-страниц (без статики).
    """
    html_like = []
    for u in site_urls:
        path = urlparse(u).path.lower()
        if any(path.endswith(ext) for ext in (
            ".js", ".css", ".png", ".jpg", ".jpeg",
            ".gif", ".svg", ".ico", ".woff", ".woff2"
        )):
            continue
        html_like.append(u)

    return html_like[:MAX_HTML_PAGES]


# --- Сбор JS-кода ---

def fetch_js_from_html(url: str) -> tuple[list[str], list[str]]:
    """
    Для одной HTML-страницы:
    - возвращает список JS-URL (src)
    - и список inline JS-блоков
    """
    js_urls: list[str] = []
    inline_js: list[str] = []

    try:
        resp = requests.get(url, timeout=TIMEOUT)
    except Exception:
        return js_urls, inline_js

    if resp.status_code >= 400:
        return js_urls, inline_js

    html = resp.text
    base = resp.url

    # внешние скрипты
    for m in SCRIPT_SRC_RE.findall(html):
        full = urljoin(base, m.strip())
        js_urls.append(full)

    # inline JS
    for block in INLINE_SCRIPT_RE.findall(html):
        inline_js.append(block)

    return js_urls, inline_js


def collect_js_sources(domain: str) -> list[tuple[str, str]]:
    """
    Собираем JS-код:
    - внешний (по src из HTML + прямые .js-URL сайта)
    - inline
    Возвращаем список (source_name, code).
    """
    site_urls = collect_site_urls(domain)
    html_pages = collect_html_pages(domain, site_urls)

    js_urls_all: list[str] = []
    inline_blocks_all: list[tuple[str, str]] = []

    # JS из HTML-страниц
    for page in html_pages:
        js_urls, inline_js = fetch_js_from_html(page)
        js_urls_all.extend(js_urls)
        for block in inline_js:
            inline_blocks_all.append((f"inline@{page}", block))

    # JS-файлы, которые прямо есть в URL-ах сайта
    for u in site_urls:
        path = urlparse(u).path.lower()
        if path.endswith(".js"):
            js_urls_all.append(u)

    # чистим js-URL
    uniq_js = []
    seen = set()
    base_dom = normalize_domain(domain)

    for u in js_urls_all:
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https"):
            continue
        host = normalize_domain(parsed.netloc)
        # интересует тот же домен или поддомены
        if not host.endswith(base_dom):
            continue
        if u in seen:
            continue
        uniq_js.append(u)
        seen.add(u)

    uniq_js = uniq_js[:MAX_JS_FILES]

    js_sources: list[tuple[str, str]] = []

    # загружаем внешние JS
    for js_url in uniq_js:
        try:
            resp = requests.get(js_url, timeout=TIMEOUT)
            if resp.status_code >= 400:
                continue
            js_sources.append((js_url, resp.text))
        except Exception:
            continue

    # добавляем inline
    js_sources.extend(inline_blocks_all)

    return js_sources


# --- Парсинг API-эндпоинтов ---

def extract_endpoints_from_js(domain: str, js_sources: list[tuple[str, str]]) -> list[dict]:
    """
    Ищем API-эндпоинты внутри JS (и частично HTML).
    Возвращаем список словарей:
      {
        "url": ...,
        "method": ...,
        "sources": set(...),
        "severity": ...,
        "tags": [...],
        "reasons": [...],
      }
    """
    endpoints: dict[tuple[str, str], dict] = {}
    base_dom = normalize_domain(domain)

    def add_endpoint(raw_url: str, method: str, source: str):
        raw_url = raw_url.strip()
        if not raw_url:
            return

        # нормализуем URL
        if raw_url.startswith("//"):
            raw_url_full = "https:" + raw_url
        elif raw_url.startswith("/"):
            raw_url_full = f"https://{base_dom}{raw_url}"
        else:
            raw_url_full = raw_url

        parsed = urlparse(raw_url_full)
        if parsed.scheme not in ("http", "https"):
            return

        host = normalize_domain(parsed.netloc or base_dom)
        if not host.endswith(base_dom):
            # выкидываем внешние домены
            return

        key = (host + parsed.path + "?" + (parsed.query or ""), method.upper())
        if key in endpoints:
            endpoints[key]["sources"].add(source)
            return

        severity, tags, reasons = classify_endpoint(raw_url_full, method)

        endpoints[key] = {
            "url": raw_url_full,
            "method": method.upper(),
            "sources": {source},
            "severity": severity,
            "tags": tags,
            "reasons": reasons,
        }

    for source_name, code in js_sources:
        # axios.*
        for m in AXIOS_RE.findall(code):
            mname, url = m
            add_endpoint(url, mname.upper(), f"axios@{source_name}")

        # fetch(...) с явным методом
        for m in FETCH_RE.findall(code):
            url, mname = m
            add_endpoint(url, mname.upper(), f"fetch@{source_name}")

        # fetch("url") без метода = GET
        for m in FETCH_SIMPLE_RE.findall(code):
            add_endpoint(m, "GET", f"fetch-simple@{source_name}")

        # xhr.open(...)
        for m in XHR_RE.findall(code):
            mname, url = m
            add_endpoint(url, mname.upper(), f"xhr@{source_name}")

        # относительные API-пути - по умолчанию GET
        for m in REL_API_RE.findall(code):
            add_endpoint(m, "GET", f"rel@{source_name}")

        # полные URL (http/https), где есть /api/ или v1/v2 и т.п.
        for u in FULL_URL_RE.findall(code):
            low = u.lower()
            if any(k in low for k in (
                "/api/", "/v1/", "/v2/", "/v3/",
                "/graphql", "/auth/", "/oauth",
                "/admin", "/user", "/account",
                "/backend", "/internal", "/rest/",
            )):
                add_endpoint(u, "GET", f"url@{source_name}")

    # ограничиваем количество
    all_eps = list(endpoints.values())
    return all_eps[:MAX_ENDPOINTS]


# --- Telegram handler ---

async def apihunt_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /apihunt домен — поиск API-эндпоинтов в JS/HTML (для легального bug bounty/pentest).
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/apihunt tesla.com"
        )
        return

    domain = normalize_domain(context.args[0])

    await update.message.reply_text(
        f"🛰 API Hunter для: {domain}\n"
        "Ищу API-эндпоинты в JS и HTML (fetch/axios/xhr, /api/, /auth/, /admin/, graphql...)\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    try:
        js_sources = collect_js_sources(domain)
    except Exception:
        js_sources = []

    if not js_sources:
        await update.message.reply_text(
            "Не удалось собрать JS/HTML для анализа. "
            "Попробуй сначала /urls, /deepurls или /deepattack, чтобы проверить доступность."
        )
        return

    endpoints = extract_endpoints_from_js(domain, js_sources)

    if not endpoints:
        await update.message.reply_text(
            "Не нашёл явных API-эндпоинтов по эвристикам.\n"
            "Но это только автоматический поиск — руками всё равно стоит проверить JS."
        )
        return

    # считаем по уровням
    counts = {"high": 0, "medium": 0, "low": 0}
    for e in endpoints:
        if e["severity"] in counts:
            counts[e["severity"]] += 1

    # сортируем: high -> medium -> low
    order = {"high": 3, "medium": 2, "low": 1}
    endpoints_sorted = sorted(
        endpoints,
        key=lambda e: order.get(e["severity"], 0),
        reverse=True,
    )

    lines: list[str] = []
    lines.append(f"🔥 API Hunter отчёт для: {domain}")
    lines.append(f"Найдено эндпоинтов: {len(endpoints)}")
    lines.append(
        "Сводка по уровням:\n"
        f"  High:   {counts['high']}\n"
        f"  Medium: {counts['medium']}\n"
        f"  Low:    {counts['low']}\n"
    )
    lines.append("Ниже показаны самые интересные эндпоинты:\n")

    idx = 0
    for e in endpoints_sorted:
        idx += 1
        sev = e["severity"].upper()
        method = e["method"]
        tags = ", ".join(e["tags"])
        reasons = "; ".join(e["reasons"]) if e["reasons"] else ""
        src_list = sorted(e["sources"])
        src_str = ", ".join(src_list[:3])
        if len(src_list) > 3:
            src_str += f" (+{len(src_list) - 3} ещё)"

        lines.append(f"{idx}. ({sev}) [{method}] {e['url']}")
        lines.append(f"   • Теги: {tags}")
        if reasons:
            lines.append(f"   • Причины: {reasons}")
        lines.append(f"   • Найдено в: {src_str}")
        lines.append("")

        if idx >= 60:
            lines.append("... Показаны только первые 60 эндпоинтов.")
            break

    lines.append("")
    lines.append(
        "Напоминание: используй результаты только в рамках легального pentest/bug bounty.\n"
        "Дальше можно проверить эти эндпоинты в Burp, ffuf, kxss, nuclei и своими скриптами."
    )

    text = "\n".join(lines)
    chunk_size = 3500
    for i in range(0, len(text), chunk_size):
        await update.message.reply_text(
            text[i:i + chunk_size],
            disable_web_page_preview=True,
        )

