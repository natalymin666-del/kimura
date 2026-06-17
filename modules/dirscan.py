import requests
import urllib3
from telegram import Update
from telegram.ext import ContextTypes

from modules.reports import save_report

# отключаем ворнинги про сертификаты (когда сканируем https без verify)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Словарь путей для лайтового dirscan
WORDLIST = [
    "/admin",
    "/admin/login",
    "/login",
    "/logon",
    "/dashboard",
    "/wp-admin",
    "/wp-login.php",
    "/cp",
    "/cpanel",
    "/user",
    "/users",
    "/account",
    "/manage",
    "/manager",
    "/panel",
    "/backend",
    "/config",
    "/config.php",
    "/.git",
    "/.env",
    "/api",
    "/api/v1",
    "/private",
    "/secret",
    "/test",
]


async def dirscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /dirscan домен — лёгкий dirb-подобный скан по небольшому словарю.
    Результат:
      – отправляем в Telegram
      – сохраняем в data/reports как текстовый отчёт
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для dirscan.\n\nПример:\n/dirscan tesla.com"
        )
        return

    domain = context.args[0].strip()

    # добавляем https, если пользователь написал просто tesla.com
    if not domain.startswith("http://") and not domain.startswith("https://"):
        base_url = "https://" + domain
    else:
        base_url = domain

    lines = []
    lines.append(f"🔍 Запускаю dirscan (лайт) для: {base_url}")
    lines.append(f"Количество путей в словаре: {len(WORDLIST)}")
    lines.append("")  # пустая строка

    for path in WORDLIST:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(
                url,
                timeout=8,
                allow_redirects=False,
                verify=False,  # чтобы не падать на кривых сертификатах
            )
            status = resp.status_code
            lines.append(f"• {path} — HTTP {status}")
        except Exception as e:
            # если какой-то путь не открылся — просто пишем ошибку и идём дальше
            lines.append(f"• {path} — error: {type(e)._name_}")

    result_text = "\n".join(lines)

    # 🔸 Сохраняем отчёт в файл
    save_report("dirscan", domain, result_text)

    # 🔸 Отправляем пользователю
    await update.message.reply_text(result_text)
