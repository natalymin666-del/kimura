import asyncio
import re
from typing import List, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import ContextTypes


# ----- Настройки сканера -----

# Сколько поддоменов максимум проверять
MAX_SUBDOMAINS = 30

# Сколько JS-файлов максимум анализировать
MAX_JS_FILES = 20

# Таймаут HTTP-запросов
REQUEST_TIMEOUT = 8

# Базовый список "интересных" поддоменов
COMMON_PREFIXES = [
    "www", "app", "api", "api-v1", "api-v2",
    "dev", "test", "stage", "staging", "beta",
    "admin", "panel", "dashboard", "auth",
    "mobile", "m", "internal", "intranet",
    "old", "legacy", "backup", "preprod",
]


# ----- Вспомогательные функции -----

def normalize_target(raw: str) -> str:
    """
    Превращает то, что ввёл пользователь, в base-domain.
    Примеры:
      - https://target.com/  -> target.com
      - sub.target.com       -> target.com
      - target.com/abc       -> target.com
    """
    raw = raw.strip()

    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)
    host = parsed.hostname or ""

    # Если субдомен, берём последние 2–3 части (очень упрощённо)
    parts = host.split(".")
    if len(parts) >= 3:
        base_domain = ".".join(parts[-2:])
    else:
        base_domain = host

    return base_domain.lower()


def build_subdomain_list(base_domain: str) -> List[str]:
    subs = []
    for p in COMMON_PREFIXES:
        subs.append(f"{p}.{base_domain}")
    # Удаляем дубли
    return sorted(list(set(subs)))[:MAX_SUBDOMAINS]


async def fetch_text(session: aiohttp.ClientSession, url: str) -> Tuple[int, str]:
    """
    Возвращает (status_code, text) или (0, "") при ошибке.
    """
    try:
        async with session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        ) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, text
    except Exception:
        return 0, ""


async def fetch_head(session: aiohttp.ClientSession, url: str) -> Tuple[int, int, str]:
    """
    HEAD (если поддерживается) или GET c чтением только первых байт.
    Возвращает (status_code, content_length, title).
    """
    try:
        try:
            async with session.head(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            ) as resp:
                status = resp.status
                length = int(resp.headers.get("Content-Length", "0") or "0")
                # иногда HEAD не даёт title → доберёмся GET'ом
                title = ""
        except Exception:
            async with session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            ) as resp:
                status = resp.status
                text = await resp.text(errors="ignore")
                length = len(text)
                title = extract_title(text)

        return status, length, title
    except Exception:
        return 0, 0, ""


def extract_title(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string if soup.title else ""
        return (title or "").strip()
    except Exception:
        return ""


def find_js_urls(html: str, base_url: str) -> List[str]:
    """
    Собираем src у <script> и нормализуем в абсолютные URL.
    """
    urls: List[str] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if not src:
                continue
            full = urljoin(base_url, src)
            urls.append(full)
    except Exception:
        pass

    # Убрали дубли и ограничили количество
    seen = set()
    result = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result[:MAX_JS_FILES]


def extract_api_endpoints(text: str) -> List[str]:
    """
    Очень грубый поиск API/авторизационных путей в JS.
    """
    candidates = set()

    # /api/..., /v1/..., /v2/...
    for m in re.findall(r"(/(?:api|v1|v2)[^\"' <>{}]+)", text, flags=re.IGNORECASE):
        if len(m) < 4 or len(m) > 120:
            continue
        candidates.add(m)

    # Полные URL вида https://something/api/...
    for m in re.findall(r"https?://[a-zA-Z0-9\.\-:/_%\+]+", text):
        if any(x in m.lower() for x in ["/api/", "/auth", "/oauth", "/login", "/token"]):
            if len(m) < 8 or len(m) > 180:
                continue
            candidates.add(m)

    # Чуть-чуть "high-value" строк по ключевым словам
    for m in re.findall(
        r"[A-Za-z0-9_\-\/]{6,80}",
        text,
    ):
        low = m.lower()
        if any(k in low for k in ["jwt", "token", "apikey", "api_key", "bearer"]):
            candidates.add(m)

    return sorted(candidates)


def classify_subdomain(host: str, title: str) -> str:
    """
    Возвращаем "dev/test", "api", "admin" или "common".
    """
    h = host.lower()
    t = (title or "").lower()

    if any(x in h for x in ["dev", "test", "stage", "staging", "beta"]) or \
       any(x in t for x in ["dev", "test", "staging"]):
        return "dev"
    if "api" in h or "/api" in t:
        return "api"
    if any(x in h for x in ["admin", "panel", "dashboard"]):
        return "admin"
    return "common"


# ----- Основная команда -----

async def deeprecon_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /deeprecon target.com
    Глубокий рекогносцировочный скан: поддомены + JS endpoints.
    """
    message = update.effective_message

    if not context.args:
        await message.reply_text(
            "Использование: <code>/deeprecon target.com</code>\n"
            "Без протокола, можно с https://",
            parse_mode="HTML",
        )
        return

    raw_target = context.args[0]
    base_domain = normalize_target(raw_target)

    await message.reply_text(
        f"🕵️ DeepRecon: начинаю разведку для <b>{base_domain}</b>…\n"
        "Собираю поддомены и интересные JS-эндпоинты.\n\n"
        "<i>Используй только в рамках легального pentest/bug bounty.</i>",
        parse_mode="HTML",
    )

    subdomains = build_subdomain_list(base_domain)

    results = []
    js_api_candidates: List[str] = []

    # Основной URL для HTML/JS
    main_url = f"https://{base_domain}"

    async with aiohttp.ClientSession() as session:
        # 1) Поддомены
        sem = asyncio.Semaphore(10)

        async def check_sub(host: str):
            url = f"https://{host}"
            async with sem:
                status, length, title = await fetch_head(session, url)
            if status:
                results.append(
                    {
                        "host": host,
                        "status": status,
                        "length": length,
                        "title": title,
                        "kind": classify_subdomain(host, title),
                    }
                )

        tasks = [check_sub(h) for h in subdomains]
        await asyncio.gather(*tasks)

        # 2) HTML + JS для главной страницы
        main_status, main_html = await fetch_text(session, main_url)

        if main_status:
            js_urls = find_js_urls(main_html, main_url)

            js_texts = []

            for js_url in js_urls:
                try:
                    async with session.get(
                        js_url,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=True,
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="ignore")
                            js_texts.append(text)
                except Exception:
                    continue

            # Ищем эндпоинты в сконкатенированном тексте
            big_js_blob = "\n".join(js_texts)
            js_api_candidates = extract_api_endpoints(big_js_blob)

    # ----- Формируем красивый отчёт -----

    if not results and not js_api_candidates:
        await message.reply_text(
            "DeepRecon: ничего интересного не нашёл (поддомены не отвечают, "
            "в JS не увидел явных API/секретов).\n"
            "Руками всё равно стоит проверить цель.",
            parse_mode="HTML",
        )
        return

    # Сортировка поддоменов: сначала dev/api/admin, затем остальные
    kind_priority = {"dev": 0, "api": 1, "admin": 2, "common": 3}
    results_sorted = sorted(
        results,
        key=lambda r: (kind_priority.get(r["kind"], 9), r["status"] * -1, r["host"]),
    )

    # Группы поддоменов
    dev_like = [r for r in results_sorted if r["kind"] == "dev"]
    api_like = [r for r in results_sorted if r["kind"] == "api"]
    admin_like = [r for r in results_sorted if r["kind"] == "admin"]
    common = [r for r in results_sorted if r["kind"] == "common"]

    lines = []

    lines.append(
        f"🔥 <b>DeepRecon отчёт для:</b> <a href=\"https://{base_domain}\">{base_domain}</a>"
    )
    lines.append("")
    lines.append(f"Проверено поддоменов: <b>{len(subdomains)}</b>")
    lines.append(f"Ответили (живые): <b>{len(results_sorted)}</b>")
    lines.append("")

    def add_group(title: str, items: List[dict], limit: int = 6):
        if not items:
            return
        lines.append(title)
        for r in items[:limit]:
            host = r["host"]
            status = r["status"]
            length = r["length"]
            title_text = (r["title"] or "").strip()
            if len(title_text) > 80:
                title_text = title_text[:77] + "…"
            lines.append(
                f"• <a href=\"https://{host}\">{host}</a> "
                f"(HTTP {status}, len≈{length})"
                + (f" — <i>{title_text}</i>" if title_text else "")
            )
        if len(items) > limit:
            lines.append(f"… и ещё {len(items) - limit} поддомен(ов).")
        lines.append("")

    add_group("🧪 <b>Dev/Test/Staging кандидаты:</b>", dev_like)
    add_group("🧬 <b>API-поддомены:</b>", api_like)
    add_group("🛡 <b>Admin/панели управления:</b>", admin_like)
    add_group("🌐 <b>Остальные живые поддомены:</b>", common, limit=5)

    # JS / API endpoints
    if js_api_candidates:
        lines.append("🔑 <b>Подозрительные API/endpoint'ы из JS:</b>")
        for ep in js_api_candidates[:15]:
            # немножко обрежем для красоты
            short = ep
            if len(short) > 120:
                short = short[:117] + "…"
            lines.append(f"• <code>{short}</code>")
        if len(js_api_candidates) > 15:
            lines.append(f"… и ещё {len(js_api_candidates) - 15} возможных endpoint'ов.")
        lines.append("")

    lines.append(
        "🔍 Идеи для атаки (ничего не эксплуатируется автоматически):\n"
        "• Dev/Staging → часто более слабая защита (XSS/IDOR/old API).\n"
        "• API-поддомены → проверь auth-bypass, rate-limit, лишние данные.\n"
        "• Admin/панели → bruteforce, слабые роли/ACL.\n"
        "• JS-endpoint'ы → отличные цели для Burp, ffuf, nuclei и своих скриптов."
    )
    lines.append("")
    lines.append(
        "<i>Напоминание: используй результаты только в рамках "
        "легального pentest / bug bounty.</i>"
    )

    text = "\n".join(lines)
    # Telegram ограничен 4096 символами → аккуратно обрежем, если что
    if len(text) > 4000:
        text = text[:3990] + "\n…(обрезано, слишком длинный отчёт)"

    await message.reply_text(text, parse_mode="HTML", disable_web_page_preview=True)
