import whois

async def whois_command(update, context):
    if len(context.args) == 0:
        await update.message.reply_text(
            "Укажи домен для WHOIS.\n\nПример:\n/whois tesla.com"
        )
        return

    domain = context.args[0]

    try:
        data = whois.whois(domain)

        registrar = data.registrar or "неизвестно"
        country = data.country or "неизвестно"

        created = data.creation_date
        expires = data.expiration_date

        # даты могут быть списками — фиксируем
        if isinstance(created, list):
            created = created[0]
        if isinstance(expires, list):
            expires = expires[0]

        dns_list = data.name_servers or []
        emails = data.emails or []

        # превращаем списки в красивые строки
        dns_text = "\n".join([f"• {d}" for d in dns_list])
        email_text = "\n".join([f"• {e}" for e in emails])

        text = f"""
🔍 WHOIS для: {domain}

* Регистратор: {registrar}
* Страна: {country}
* Дата регистрации: {created}
* Истекает: {expires}

* DNS:
{dns_text}

* Emails:
{email_text}
"""

        await update.message.reply_text(text)

    except Exception as e:
        await update.message.reply_text(f"Ошибка WHOIS: {e}")
