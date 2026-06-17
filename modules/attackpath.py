import re
import asyncio
from urllib.parse import urlparse

import httpx
from telegram import Update
from telegram.ext import ContextTypes


# --- Вспомогательные функции ---------------------------------


def normalize_target(raw: str) -> tuple[str, str]:
    """
    Приводим то, что пользователь ввёл, к:
    - чистому домену (wordpress.com)
    - базовому URL (https://wordpress.com)
    """
    raw = raw.strip()

    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)
    domain = parsed.netloc.lower()
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    return domain, base_url


def build_subdomain_candidates(domain: str) -> list[str]:
    """
    Самые частые "вкусные" поддомены.
    Здесь мы делаем именно атакующую карту, а не полный bruteforce.
    """
    prefixes = [
        "dev", "beta", "test", "staging", "stage",
        "api", "api-v1", "api-v2",
        "admin", "dashboard", "panel",
        "auth", "login", "sso",
        "internal", "intranet",
        "backup", "app",
    ]
    urls = []
    for p in prefixes:
        urls.append(f"https://{p}.{domain}")
    return urls


async def fetch_status(client: httpx.AsyncClient, url: str) -> tuple[str, int | None, int | None]:
    """
    Делаем GET и возвращаем:
    - финальный статус-код
    - примерную длину ответа
    """
    try:
        r = await client.get(url, timeout=8.0)
        return url, r.status_code, len(r.text or "")
    except Exception:
        return url, None, None


async def fetch_text(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        r = await client.get(url, timeout=10.0)
        if r.status_code in (200, 201, 302, 301):
            return r.text
        return None
    except Exception:
        return None


def extract_interesting_paths(html: str) -> list[str]:
    """
    Достаём из HTML вероятные API/авторизационные пути.
    Просто эвристики по /api, /v1, /auth, /login, /graphql и т.п.
    """
    candidates = set()

    # Ищем /что-то в кавычках
    for m in re.finditer(r"""["'](/[^"' \t\r\n]+)["']""", html):
        path = m.group(1)
        if len(path) > 2:
            candidates.add(path)

    interesting_keywords = [
        "/api", "/v1", "/v2", "/auth", "/login",
        "/oauth", "/graphql", "/user", "/admin",
        "/token", "/session", "/forgot", "/reset",
    ]

    interesting = [
        p for p in candidates
        if any(kw in p.lower() for kw in interesting_keywords)
    ]

    # сортируем, обрезаем до разумного количества
    interesting = sorted(set(interesting))[:20]
    return interesting


# --- Основная команда ----------------------------------------


async def attackpath_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /attackpath target.com

    Делает быструю карту атаки:
    - ищет интересные поддомены (dev/api/admin/auth/backup/internal…)
    - вытаскивает из главной страницы подозрительные пути (API / auth)
    - строит черновик exploit-цепочек
    """
    if not context.args:
        await update.message.reply_text(
            "⚔️ Kimura AttackPath\n\n"
            "Использование:\n"
            "`/attackpath target.com`\n\n"
            "Например:\n"
            "`/attackpath wordpress.com`",
            parse_mode="Markdown",
        )
        return

    raw_target = context.args[0]
    domain, base_url = normalize_target(raw_target)

    msg = await update.message.reply_text(
        f"🧠 Kimura AttackPath: строю карту атаки для `{domain}`…\n"
        f"Это займёт немного времени.",
        parse_mode="Markdown",
    )

    interesting_subs = {
        "dev": [],
        "api": [],
        "admin": [],
        "auth": [],
        "internal": [],
        "backup": [],
        "other": [],
    }

    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        # 1) Проверяем поддомены-кандидаты
        sub_urls = build_subdomain_candidates(domain)
        tasks = [fetch_status(client, u) for u in sub_urls]
        results = await asyncio.gather(*tasks)

        for url, status, length in results:
            if status and 200 <= status < 400:
                # определяем категорию
                lower = url.lower()
                if any(k in lower for k in ["dev.", "test.", "beta.", "staging.", "stage."]):
                    interesting_subs["dev"].append((url, status, length))
                elif ".api" in lower or "/api" in lower:
                    interesting_subs["api"].append((url, status, length))
                elif any(k in lower for k in [".admin.", "admin.", "dashboard.", "panel."]):
                    interesting_subs["admin"].append((url, status, length))
                elif any(k in lower for k in ["auth.", "login.", "sso."]):
                    interesting_subs["auth"].append((url, status, length))
                elif any(k in lower for k in ["internal.", "intranet."]):
                    interesting_subs["internal"].append((url, status, length))
                elif "backup." in lower:
                    interesting_subs["backup"].append((url, status, length))
                else:
                    interesting_subs["other"].append((url, status, length))

        # 2) Тянем HTML главной страницы и достаём пути
        main_html = await fetch_text(client, base_url)
        js_paths: list[str] = []
        if main_html:
            js_paths = extract_interesting_paths(main_html)

    # --- Формируем отчёт --------------------------------------

    lines: list[str] = []

    lines.append(f"🔥 *Kimura AttackPath отчёт для:* `{domain}`\n")
    lines.append(f"🌐 Базовый домен: `{base_url}`\n")

    # Поддомены (сильно режем, чтобы не было простыней)
    def fmt_subs(title: str, key: str):
        subs = interesting_subs[key][:5]
        if not subs:
            return
        lines.append(f"*{title}:*")
        for url, status, length in subs:
            lines.append(f"  • `{url}` (HTTP {status}, len≈{length})")
        lines.append("")

    fmt_subs("Dev/Test/Staging окружения", "dev")
    fmt_subs("API-поддомены", "api")
    fmt_subs("Admin / панели управления", "admin")
    fmt_subs("Auth / Login / SSO", "auth")
    fmt_subs("Внутренние/internal поддомены", "internal")
    fmt_subs("Backup-поддомены", "backup")
    fmt_subs("Прочие интересные поддомены", "other")

    # Подозрительные пути из HTML
    if js_paths:
        lines.append("🔑 *Подозрительные API/авторизационные пути (из HTML/JS):*")
        for p in js_paths[:15]:
            lines.append(f"  • `{p}`")
        lines.append("")

    # --- Черновик эксплойт-цепочек ---------------------------

    lines.append("🧬 *Черновики exploit-цепочек* (идеи, НИЧЕГО не эксплуатируется):")

    # Dev / staging
    if interesting_subs["dev"]:
        lines.append(
            "1️⃣ *Dev/Staging → прод*:\n"
            "   • Сначала проверь dev/staging поддомены на старые версии приложения.\n"
            "   • Ищи:\n"
            "     – устаревшие эндпоинты\n"
            "     – слабую авторизацию\n"
            "     – debug-панели, лишние логи."
        )
    # API
    if interesting_subs["api"] or any("/api" in p.lower() for p in js_paths):
        lines.append(
            "2️⃣ *API-цепочка*:\n"
            "   • Используй найденные `/api`/`/v1`/`/v2` пути.\n"
            "   • Проверь:\n"
            "     – доступ без токена (auth-bypass)\n"
            "     – IDOR (подмена ID, user_id, account_id)\n"
            "     – rate-limit (много запросов подряд)\n"
            "     – лишние поля в response (email, phone, internal id)."
        )
    # Admin
    if interesting_subs["admin"]:
        lines.append(
            "3️⃣ *Админка / панели*:\n"
            "   • Ищи слабую аутентификацию и доступ по прямой ссылке.\n"
            "   • Проверь:\n"
            "     – можно ли попасть без логина (401/403 → 200 при обходе)\n"
            "     – IDOR в действиях администратора\n"
            "     – CSRF на критичных действиях (смена email, пароля, прав)."
        )
    # Auth
    if interesting_subs["auth"] or any("login" in p.lower() or "auth" in p.lower() for p in js_paths):
        lines.append(
            "4️⃣ *Auth / Session цепочка*:\n"
            "   • Логин-формы, reset/forgot-функции, OAuth/SSO.\n"
            "   • Ищи:\n"
            "     – обход 2FA / MFA\n"
            "     – session fixation / reuse токенов\n"
            "     – утечки токенов в редиректах или логе URL."
        )
    # Internal / backup
    if interesting_subs["internal"] or interesting_subs["backup"]:
        lines.append(
            "5️⃣ *Internal / Backup*:\n"
            "   • Internal/backup поддомены часто содержат старые приложения и бекапы.\n"
            "   • Проверь:\n"
            "     – открытые директории\n"
            "     – старые панели / admin-скрипты\n"
            "     – .zip / .sql / .bak файлы."
        )

    # Общий финальный шаг
    lines.append(
        "6️⃣ *Финальная цепочка*:\n"
        "   • Собери данные из Recon (поддомены + API + формы).\n"
        "   • Выбери 1–2 самые слабые точки (обычно dev/API).\n"
        "   • Дальше прогоняй их через Burp, ffuf, свои скрипты и XSS/IDOR/CSRF-модули Kimura.\n"
    )

    lines.append(
        "\n⚠️ *Важно: используй Kimura AttackPath только на целях, где у тебя есть явное разрешение "
        "(легальный pentest / bug bounty).*"
    )

    text = "\n".join(lines)
    # Телеграм режет >4096, поэтому перестрахуемся
    if len(text) > 3900:
        text = text[:3900] + "\n\n…output truncated (слишком длинный отчёт)"

    await msg.edit_text(text, parse_mode="Markdown")
