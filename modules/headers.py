import requests

async def headers_command(update, context):
    target = " ".join(context.args)
    if not target:
        await update.message.reply_text("Укажи домен: /headers tesla.com")
        return

    if not target.startswith("http"):
        url = f"https://{target}"
    else:
        url = target

    try:
        r = requests.get(url, timeout=5)
        headers = r.headers

        important = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        text = f"🔐 Security Headers for {target}\n\n"
        for h in important:
            value = headers.get(h)
            if value:
                text += f"• {h}: {value}\n"
            else:
                text += f"• {h}: ❌ отсутствует\n"

        await update.message.reply_text(text)

    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")
