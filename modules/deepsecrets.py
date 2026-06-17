import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import ContextTypes

# --------- настройки сканера ---------
TIMEOUT = 8                  # таймаут HTTP-запросов
MAX_HTML_PAGES = 20          # сколько HTML-страниц максимум смотреть
MAX_JS_FILES = 40            # сколько JS-файлов максимум качать
MAX_FINDINGS = 80            # максимум найденных "секретов" в отчёте
CHUNK_LIMIT = 3500           # длина одного сообщения в Telegram


# --------- паттерны секретов ---------
SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9\/\-_]+",
    "Discord Webhook": r"https://discord(app)?\.com/api/webhooks/[0-9A-Za-z\/\-_]+",
    "Stripe Secret Key": r"sk_live_[0-9A-Za-z]{20,40}",
    "Stripe Publishable Key": r"pk_live_[0-9A-Za-z]{20,40}",
    "JWT Token": r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    # generic high-entropy — смотрим отдельно, потом фильтруем
    "Generic High-Entropy": r"\b[A-Za-z0-9+/]{32,}={0,2}\b",
}


# --------- утилиты ---------
def normalize_domain(raw: str) -> str:
    raw = raw.strip()
    raw = raw.replace("https://", "").replace("http://", "")
    raw = raw.split("/")[0]
    return raw


def http_get(url: str) -> str:
    try:
        resp = requests.get(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (KimuraDeepSecrets/2.0)"}
        )
        # ограничим размер, чтобы не заглатывать мегабайты
        return resp.text[:150_000]
    except Exception:
        return ""


def extract_links(html: str, base_url: str) -> list[str]:
    """
    Из HTML достаём ссылки на страницы и JS.
    """
    result: list[str] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return result

    # ссылки <a href=...>
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = urljoin(base_url, href)
        result.append(full)

    # <script src="...">
    for s in soup.find_all("script", src=True):
        src = s["src"]
        full = urljoin(base_url, src)
        result.append(full)

    return result


def is_same_domain(url: str, domain: str) -> bool:
    try:
        netloc = urlparse(url).netloc
        return netloc.endswith(domain)
    except Exception:
        return False


def classify_url(url: str) -> str:
    """
    Очень простая классификация: html / js / other.
    """
    lower = url.lower()
    if lower.endswith(".js"):
        return "js"
    if any(ext in lower for ext in [".php", ".aspx", ".html", ".htm", "/"]):
        return "html"
    return "other"


def scan_text_for_secrets(text: str) -> list[tuple[str, str]]:
    """
    Возвращаем список (тип, найденная_строка).
    """
    findings: list[tuple[str, str]] = []
    for name, pattern in SECRET_PATTERNS.items():
        try:
            matches = re.findall(pattern, text)
        except re.error:
            continue

        for m in matches:
            findings.append((name, m))
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


def postprocess_findings(raw: list[tuple[str, str]]) -> list[dict]:
    """
    - убираем дубли
    - режем мусорные high-entropy строки
    - добавляем severity
    """
    uniq: set[tuple[str, str]] = set(raw)
    processed: list[dict] = []

    for secret_type, value in uniq:
        # фильтруем generic high-entropy
        if secret_type == "Generic High-Entropy":
            # короткие или "словесные" строки — выкидываем
            if len(value) < 40:
                continue
            low = value.lower()
            trash_substrings = [
                "content", "application", "charset", "width", "height",
                "border", "padding", "margin", "color", "font", "json", "xml",
            ]
            if any(t in low for t in trash_substrings):
                continue

        severity = classify_severity(secret_type, value)
        processed.append(
            {
                "type": secret_type,
                "value": value,
                "severity": severity,
            }
        )

    # сортировка: CRITICAL → HIGH → MEDIUM → LOW
    order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    processed.sort(key=lambda x: order.get(x["severity"], 0), reverse=True)

    # ограничим сверху
    return processed[:MAX_FINDINGS]


def classify_severity(secret_type: str, value: str) -> str:
    """
    Простая эвристика по уровню риска.
    """
    if secret_type in ("Stripe Secret Key", "AWS Access Key"):
        return "CRITICAL"
    if secret_type in ("Slack Webhook", "Discord Webhook", "Google API Key"):
        return "HIGH"
    if secret_type in ("JWT Token", "Stripe Publishable Key"):
        return "MEDIUM"
    if secret_type == "Generic High-Entropy":
        # очень длинные странные строки — HIGH, остальные MED/LOW
        if len(value) > 80:
            return "HIGH"
        if len(value) > 50:
            return "MEDIUM"
        return "LOW"
    # по умолчанию
    return "LOW"


def deepsecrets_core(domain: str) -> list[dict]:
    """
    Основная логика:
    1) грузим главную
    2) из неё собираем ссылки
    3) отдельно сканируем HTML и JS
    4) ищем секреты по паттернам
    """
    domain = normalize_domain(domain)
    base_https = f"https://{domain}"
    base_http = f"http://{domain}"

    # 1. пробуем https, если пусто — http
    html_main = http_get(base_https)
    base = base_https
    if not html_main:
        html_main = http_get(base_http)
        base = base_http

    if not html_main:
        return []

    # 2. собираем ссылки
    raw_links = extract_links(html_main, base)
    # оставляем только наш домен и убираем дубли
    filtered = []
    for u in raw_links:
        if is_same_domain(u, domain):
            filtered.append(u)

    unique_urls = sorted(set(filtered))

    html_urls: list[str] = []
    js_urls: list[str] = []

    for u in unique_urls:
        t = classify_url(u)
        if t == "html" and len(html_urls) < MAX_HTML_PAGES:
            html_urls.append(u)
        elif t == "js" and len(js_urls) < MAX_JS_FILES:
            js_urls.append(u)

    # главную тоже сканируем как HTML
    if base not in html_urls:
        html_urls.insert(0, base)

    raw_findings: list[tuple[str, str]] = []

    # 3. сканируем HTML-страницы
    for url in html_urls:
        body = http_get(url)
        if not body:
            continue

        findings = scan_text_for_secrets(body)
        for ftype, value in findings:
            raw_findings.append((ftype, value))

    # 4. сканируем JS-файлы
    for url in js_urls:
        body = http_get(url)
        if not body:
            continue

        findings = scan_text_for_secrets(body)
        for ftype, value in findings:
            raw_findings.append((ftype, value))

    # пост-обработка (фильтрация + severity + сортировка)
    processed = postprocess_findings(raw_findings)

    # добавляем источники (откуда найдено значение)
    # чтобы не дёргать сайт заново, просто найдём первое совпадение
    final_results: list[dict] = []
    for item in processed:
        value = item["value"]
        src = find_first_source(value, html_urls, js_urls)
        final_results.append(
            {
                "type": item["type"],
                "value": item["value"],
                "severity": item["severity"],
                "source": src,
            }
        )

    return final_results


def find_first_source(value: str, html_urls: list[str], js_urls: list[str]) -> str:
    """
    Очень грубый способ: пробегаемся по списку URL и ищем первое, где встречается value.
    Это не идеально, но даёт понимание "где живёт секрет".
    """
    all_urls = html_urls + js_urls
    for url in all_urls:
        body = http_get(url)
        if not body:
            continue
        if value in body:
            return url
    # если не нашли — хотя бы вернём домен
    return "(источник не определён)"


def mask_secret(value: str) -> str:
    """
    Маскируем секрет: первые 6 символов + '...' + последние 4.
    """
    if len(value) <= 12:
        return value
    return f"{value[:6]}...{value[-4:]}"


# --------- TELEGRAM-КОМАНДА ---------
async def deepsecrets_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Команда: /deepsecrets domain.com
    """
    if not context.args:
        await update.message.reply_text(
            "❗ Использование:\n"
            "/deepsecrets domain.com"
        )
        return

    domain = normalize_domain(context.args[0])

    await update.message.reply_text(
        f"🧨 Secrets Hunter (aggressive) для: {domain}\n"
        "Ищу расширенный набор секретов: API-ключи, токены, JWT, Stripe, Slack/Discord webhooks, "
        ".env-переменные, high-entropy строки и др.\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    findings = deepsecrets_core(domain)

    if not findings:
        await update.message.reply_text(
            "Не нашёл явных секретов по основным паттернам.\n"
            "Но это только автоматический поиск — руками всё равно стоит проверить JS/HTML."
        )
        return

    # считаем сводку по уровням
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        stats[f["severity"]] = stats.get(f["severity"], 0) + 1

    header_lines = [
        f"🔥 Secrets Hunter отчёт для: {domain}",
        f"Найдено потенциальных секретов: {len(findings)}",
        "",
        "Сводка по уровням:",
        f"CRITICAL: {stats['CRITICAL']}",
        f"HIGH:     {stats['HIGH']}",
        f"MEDIUM:   {stats['MEDIUM']}",
        f"LOW:      {stats['LOW']}",
        "",
        "Ниже показаны самые интересные находки (по убыванию важности):",
        "",
    ]
    header = "\n".join(header_lines)

    chunks: list[str] = []
    current = header

    for i, item in enumerate(findings, 1):
        line = (
            f"{i}. ({item['severity']}) {item['type']}\n"
            f"Источник: {item['source']}\n"
            f"Значение (маскировано): `{mask_secret(item['value'])}`\n\n"
        )

        # если не помещается в текущий блок — отправляем его и начинаем новый
        if len(current) + len(line) > CHUNK_LIMIT:
            chunks.append(current)
            current = line
        else:
            current += line

    if current:
        chunks.append(current)

    # отправляем по частям
    for part in chunks:
        await update.message.reply_text(
            part,
            disable_web_page_preview=True,
            parse_mode="Markdown",
        )

    # напоминание в конце
    await update.message.reply_text(
        "Напоминание: используй результаты только в рамках легального pentest/bug bounty.\n"
        "Всегда проверяй найденные секреты руками и не заливай их в публичные репозитории."
    )
