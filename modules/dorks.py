from telegram import Update
from telegram.ext import ContextTypes


def normalize_domain(raw: str) -> str:
    raw = raw.strip()
    raw = raw.replace("https://", "").replace("http://", "")
    raw = raw.split("/")[0]
    return raw


async def dorks_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /dorks домен — генератор Google dorks и OSINT-запросов для домена.
    НИЧЕГО не сканирует, только помогает быстро копировать запросы.
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для генерации dorks.\n\n"
            "Пример:\n"
            "/dorks tesla.com"
        )
        return

    domain = normalize_domain(context.args[0])

    # Блоки dorks
    basic = [
        f'site:{domain}',
        f'"{domain}"',
        f'"{domain}" intitle:"index of"',
    ]

    dirs_files = [
        f'site:{domain} intitle:"index of" "backup"',
        f'site:{domain} intitle:"index of" "config"',
        f'site:{domain} intitle:"index of" "upload"',
        f'site:{domain} "parent directory" backup',
        f'site:{domain} "parent directory" .git',
    ]

    logins_admins = [
        f'site:{domain} inurl:login',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:auth',
        f'site:{domain} "sign in"',
        f'site:{domain} "reset password"',
    ]

    errors_debug = [
        f'site:{domain} "PHP Notice"',
        f'site:{domain} "PHP Warning"',
        f'site:{domain} "SQL syntax near"',
        f'site:{domain} "unhandled exception"',
        f'site:{domain} "stack trace"',
    ]

    backups_leaks = [
        f'site:{domain} ext:sql | ext:bak | ext:old | ext:log',
        f'site:{domain} ext:env | ext:ini | ext:cfg',
        f'site:{domain} "confidential" OR "internal use only"',
        f'site:{domain} "do not distribute"',
    ]

    github_block = [
        f'"{domain}" site:github.com',
        f'"{domain}" \"API key\" site:github.com',
        f'"{domain}" \"secret\" site:github.com',
        f'"{domain}" \"token\" site:github.com',
    ]

    pastebin_block = [
        f'"{domain}" site:pastebin.com',
        f'"{domain}" \"password\" site:pastebin.com',
    ]

    other_search = [
        f'"{domain}" site:gitlab.com',
        f'"{domain}" site:trello.com',
        f'"{domain}" site:jsdelivr.net',
        f'"{domain}" site:cdnjs.com',
    ]

    lines: list[str] = []

    lines.append(f"🔎 Google dorks и OSINT-запросы для: {domain}\n")
    lines.append("📌 Копируй и вставляй в Google / GitHub / др. поиски.\n")

    def add_block(title: str, items: list[str]):
        lines.append("")
        lines.append(f"📂 {title}:")
        for q in items:
            # используем бэктики, чтобы удобно копировать
            lines.append(f"{q}")

    add_block("Базовые запросы", basic)
    add_block("Папки и файлы (index of)", dirs_files)
    add_block("Логины / админки", logins_admins)
    add_block("Ошибки и debug-инфо", errors_debug)
    add_block("Бэкапы и потенциальные утечки", backups_leaks)
    add_block("GitHub / репозитории", github_block)
    add_block("Pastebin", pastebin_block)
    add_block("Другие источники", other_search)

    lines.append("")
    lines.append("❗ Используй dorks только для легального анализа своих целей или по официальному разрешению.")

    text = "\n".join(lines)

    # Сообщение может быть большим, поэтому отправим как несколько, если нужно
    # Telegram обычно пропускает до ~4000 символов, мы немного перестрахуемся
    chunk_size = 3500
    for i in range(0, len(text), chunk_size):
        chunk = text[i : i + chunk_size]
        await update.message.reply_text(
            chunk,
            parse_mode="Markdown",
            disable_web_page_preview=True,
        )
