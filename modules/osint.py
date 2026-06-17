import requests
import socket

async def osint_command(update, context):
    if not context.args:
        await update.message.reply_text("Введите домен: /osint example.com")
        return

    domain = context.args[0]

    result = f"🕵️ OSINT для цели: {domain}\n\n"

    # --- IP Lookup ---
    try:
        ip = socket.gethostbyname(domain)
        result += f"• IP адрес: {ip}\n"
    except:
        result += "• IP адрес: не найден\n"

    # --- Headers ---
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        server = r.headers.get("Server", "неизвестно")
        powered = r.headers.get("X-Powered-By", "неизвестно")

        result += f"• Веб-сервер: {server}\n"
        result += f"• Технологии: {powered}\n"
    except:
        result += "• Невозможно получить заголовки\n"

    # --- Basic subdomain scan ---
    subdomains = ["www", "mail", "dev", "api", "test", "admin"]

    found = []
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            found.append(subdomain)
        except:
            pass

    if found:
        result += "\n• Найденные поддомены:\n"
        for s in found:
            result += f"   - {s}\n"
    else:
        result += "\n• Поддомены не найдены\n"

    await update.message.reply_text(result, parse_mode="Markdown")
