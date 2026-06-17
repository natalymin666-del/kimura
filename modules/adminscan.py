import requests

paths = [
    "admin", "login", "administrator", "dashboard",
    "wp-admin", "cpanel", "user", "panel", "manage",
    "system", "auth", "secure", "admin/login"
]

async def adminscan_command(update, context):
    target = " ".join(context.args)
    if not target:
        await update.message.reply_text("Использование: /adminscan tesla.com")
        return

    if not target.startswith("http"):
        base = f"https://{target}"
    else:
        base = target

    found = []
    await update.message.reply_text("🔍 Запускаю сканирование админ-панелей...")

    for p in paths:
        url = f"{base}/{p}"
        try:
            r = requests.get(url, timeout=4, allow_redirects=True)
            if r.status_code in [200, 301, 302, 403]:
                found.append(f"• /{p} — {r.status_code}")
        except:
            pass

    if not found:
        await update.message.reply_text("❌ Админ-панели не найдены.")
    else:
        result = "🛠 Найденные админ-панели:\n\n" + "\n".join(found)
        await update.message.reply_text(result)
