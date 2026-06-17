import re
import requests
from telegram import Update
from telegram.ext import ContextTypes

TIMEOUT = 10


def normalize_domain(raw: str) -> str:
    raw = raw.strip()
    raw = raw.replace("https://", "").replace("http://", "")
    raw = raw.split("/")[0]
    return raw


def fetch_hackertarget(domain: str) -> list[str]:
    """hostsearch API от hackertarget — subdomain,ip построчно."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        text = resp.text.strip()
        if "error" in text.lower():
            return []
        subs = []
        for line in text.splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip()
                if sub.endswith(domain):
                    subs.append(sub)
        return subs
    except Exception:
        return []


def fetch_crtsh(domain: str) -> list[str]:
    """crt.sh JSON API — выдёргиваем имена сертификатов."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code != 200:
            return []
        data = resp.json()
        subs = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for line in str(name_value).split("\n"):
                line = line.strip()
                if not line:
                    continue
                if "*" in line:
                    line = line.replace("*.", "")
                if line.endswith(domain):
                    subs.add(line)
        return list(subs)
    except Exception:
        return []


def clean_and_sort(subdomains: list[str], domain: str) -> list[str]:
    """Чистим, убираем мусор и сортируем."""
    cleaned = set()
    pattern = re.compile(rf"[a-zA-Z0-9._-]+\.{re.escape(domain)}\.?$")

    for s in subdomains:
        s = s.strip().lower()
        s = s.rstrip(".")
        if not s:
            continue
        if not pattern.match(s):
            continue
        cleaned.add(s)

    return sorted(cleaned)


async def subscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /subscan домен — мульти-источник поиск поддоменов (demo).
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для поиска поддоменов.\n\n"
            "Пример:\n"
            "/subscan tesla.com"
        )
        return

    raw = context.args[0]
    domain = normalize_domain(raw)

    await update.message.reply_text(
        f"🔍 Запускаю поиск поддоменов для: {domain}\n"
        "Источники: crt.sh, hackertarget (demo режим)…"
    )

    all_subs: list[str] = []

    # 1) crt.sh
    crt_subs = fetch_crtsh(domain)
    if crt_subs:
        all_subs.extend(crt_subs)

    # 2) hackertarget hostsearch
    ht_subs = fetch_hackertarget(domain)
    if ht_subs:
        all_subs.extend(ht_subs)

    subs = clean_and_sort(all_subs, domain)

    if not subs:
        await update.message.reply_text(
            "Поддомены не найдены или источники ничего не вернули.\n"
            "Попробуй позже или с другим доменом."
        )
        return

    max_show = 80
    show_list = subs[:max_show]

    lines: list[str] = []
    lines.append(f"🧩 Subdomain scan (multi-source) для: {domain}")
    lines.append("")
    lines.append(f"Найдено поддоменов: {len(subs)}")
    if len(subs) > max_show:
        lines.append(f"(показаны первые {max_show})")
    lines.append("")

    for s in show_list:
        lines.append(f"• {s}")

    lines.append("")
    lines.append(
        "Используй список поддоменов для дальнейшего анализа:\n"
        "– portscan / ssl / headers / risk / jsfind\n"
        "– поиск панелей, API, старых окружений."
    )
    lines.append("Режим: demo, публичные OSINT-источники.")

    text = "\n".join(lines)

    await update.message.reply_text(
        text,
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )
