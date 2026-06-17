import re
from urllib.parse import urlparse

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

MAX_SOURCES = 40          # максимум URL, откуда забираем текст
MAX_CHARS_PER_SOURCE = 80000  # режем большие ответы
MAX_FINDINGS = 80         # максимум находок в отчёте


# --- паттерны секретов ---

SECRET_PATTERNS: dict[str, dict] = {
    "AWS Access Key": {
        "re": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "high",
    },
    "Google API Key": {
        "re": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "high",
    },
    "Slack Token": {
        "re": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
        "severity": "high",
    },
    "Private Key Header": {
        "re": re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----"),
        "severity": "high",
    },
    "JWT": {
        "re": re.compile(
            r"eyJ[a-zA-Z0-9_\-]{5,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"
        ),
        "severity": "high",
    },
    "Generic API key / token": {
        "re": re.compile(
            r"(?i)(api_key|apiKey|apikey|token|access_token)\s*[:=]\s*['\"]([0-9a-zA-Z_\-\.]{10,80})['\"]"
        ),
        "severity": "medium",
    },
    "Password in code": {
        "re": re.compile(
            r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,80}['\"]"
        ),
        "severity": "medium",
    },
    "Basic Auth in URL": {
        "re": re.compile(r"https?://[A-Za-z0-9_\-\.]+:[^@]{4,}@"),
        "severity": "high",
    },
}


SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def collect_candidate_urls(domain: str) -> list[str]:
    """
    Собираем URL сайта: sitemap, главная, spider, немного Wayback.
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

    try:
        wb = fetch_wayback_urls(domain)
        if wb:
            all_urls.extend(wb)
    except Exception:
        pass

    cleaned = clean_urls(all_urls, domain)

    # Оставим только "текстовые" URL
    filtered: list[str] = []
    for u in cleaned:
        path = urlparse(u).path.lower()
        if any(
            path.endswith(ext)
            for ext in (
                ".js",
                ".json",
                ".txt",
                ".config",
                ".conf",
                ".env",
                ".ini",
                ".yml",
                ".yaml",
                ".php",
                ".aspx",
                ".jsp",
                ".html",
                ".htm",
            )
        ):
            filtered.append(u)
            continue

        # URL без расширения тоже могут быть интересны
        if "." not in path.split("/")[-1]:
            filtered.append(u)

    return filtered[:MAX_SOURCES]


def fetch_text_sources(domain: str) -> list[tuple[str, str]]:
    """
    Скачиваем контент с интересных URL.
    Возвращаем список (source_name, text).
    """
    sources: list[tuple[str, str]] = []
    urls = collect_candidate_urls(domain)

    for u in urls:
        try:
            resp = requests.get(u, timeout=TIMEOUT)
        except Exception:
            continue

        ctype = resp.headers.get("Content-Type", "").lower()
        if not (
            "text" in ctype
            or "javascript" in ctype
            or "json" in ctype
        ):
            # пропускаем бинарники
            continue

        text = resp.text
        if len(text) > MAX_CHARS_PER_SOURCE:
            text = text[:MAX_CHARS_PER_SOURCE]

        sources.append((u, text))

    return sources


def mask_value(value: str) -> str:
    """
    Маскируем значение, чтобы не светить полный секрет.
    """
    value = value.strip()
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]


def make_snippet(text: str, start: int, end: int, width: int = 80) -> str:
    """
    Достаём небольшой фрагмент вокруг совпадения.
    """
    left = max(0, start - width)
    right = min(len(text), end + width)
    snippet = text[left:right]
    snippet = snippet.replace("\n", " ").replace("\r", " ")
    return snippet.strip()


def scan_source_for_secrets(source_name: str, text: str) -> list[dict]:
    """
    Ищем секреты в одном источнике.
    Возвращаем список словарей.
    """
    findings: list[dict] = []
    seen_values: set[tuple[str, str]] = set()  # (type, value_masked)

    for stype, info in SECRET_PATTERNS.items():
        pattern = info["re"]
        severity = info["severity"]

        for m in pattern.finditer(text):
            full_match = m.group(0)

            # для generic api key берём вторую группу, если есть
            if stype == "Generic API key / token" and m.lastindex and m.lastindex >= 2:
                # group 1 - имя параметра, group 2 - значение
                full_match = m.group(2)

            masked = mask_value(full_match)
            key = (stype, masked)
            if key in seen_values:
                continue
            seen_values.add(key)

            start, end = m.start(), m.end()
            snippet = make_snippet(text, start, end)

            line_no = text.count("\n", 0, start) + 1

            findings.append(
                {
                    "type": stype,
                    "severity": severity,
                    "source": source_name,
                    "masked": masked,
                    "line": line_no,
                    "snippet": snippet,
                }
            )

    return findings


def collect_secrets(domain: str) -> list[dict]:
    """
    Сканируем несколько источников и собираем все находки.
    """
    all_findings: list[dict] = []

    sources = fetch_text_sources(domain)
    for src_name, text in sources:
        try:
            fs = scan_source_for_secrets(src_name, text)
        except Exception:
            continue
        all_findings.extend(fs)

        if len(all_findings) >= MAX_FINDINGS:
            break

    # сортировка по severity
    all_findings.sort(
        key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True
    )
    return all_findings[:MAX_FINDINGS]


# --- Telegram handler ---

async def secrets_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /secrets домен — поиск потенциальных секретов в JS/HTML (для легального bug bounty/pentest).
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/secrets tesla.com"
        )
        return

    domain = normalize_domain(context.args[0])

    await update.message.reply_text(
        f"🕵️ Secrets Detector для: {domain}\n"
        "Ищу потенциальные секреты в JS/HTML (API-ключи, токены, JWT, private keys...).\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    try:
        findings = collect_secrets(domain)
    except Exception:
        findings = []

    if not findings:
        await update.message.reply_text(
            "Не нашёл явных секретов по основным паттернам.\n"
            "Но это только автоматический поиск — руками всё равно стоит проверить JS/HTML."
        )
        return

    # сводка
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1

    lines: list[str] = []
    lines.append(f"🔥 Secrets Detector отчёт для: {domain}")
    lines.append(f"Найдено потенциальных секретов: {len(findings)}")
    lines.append(
        "Сводка по уровням:\n"
        f"  High:   {counts['high']}\n"
        f"  Medium: {counts['medium']}\n"
        f"  Low:    {counts['low']}\n"
    )
    lines.append("Ниже показаны самые интересные находки:\n")

    for idx, f in enumerate(findings, start=1):
        sev = f["severity"].upper()
        lines.append(f"{idx}. ({sev}) {f['type']}")
        lines.append(f"   • Источник: {f['source']}")
        lines.append(f"   • Строка: {f['line']}")
        lines.append(f"   • Значение (маскированно): `{f['masked']}`")
        lines.append(f"   • Контекст: {f['snippet']}")
        lines.append("")

    if len(findings) >= MAX_FINDINGS:
        lines.append("... Показаны только первые находки, есть ещё.")

    lines.append("")
    lines.append(
        "Напоминание: используй результаты только в рамках легального pentest/bug bounty.\n"
        "Всегда проверяй найденные секреты руками и не заливай их в публичные репозитории."
    )

    text = "\n".join(lines)
    chunk_size = 3500
    for i in range(0, len(text), chunk_size):
        await update.message.reply_text(
            text[i:i + chunk_size],
            disable_web_page_preview=True,
            parse_mode="Markdown",
        )
