import re
import socket
import requests
from telegram import Update
from telegram.ext import ContextTypes

IP_REGEX = r"^\d{1,3}(\.\d{1,3}){3}$"


async def ipinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Укажи IP или домен.\n\nПримеры:\n"
            "/ipinfo 8.8.8.8\n"
            "/ipinfo tesla.com"
        )
        return

    target = context.args[0].strip()

    # 1) Если домен — резолвим в IP
    try:
        if re.match(IP_REGEX, target):
            ip = target
        else:
            ip = socket.gethostbyname(target)
    except Exception as e:
        await update.message.reply_text(f"Не удалось определить IP для {target}: {e}")
        return

    # 2) Берём данные из бесплатного API ip-api.com
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,"
                            "continent,country,regionName,city,isp,org,as,query,lat,lon")
        data = resp.json()
    except Exception as e:
        await update.message.reply_text(f"Ошибка запроса к IP API: {e}")
        return

    if data.get("status") != "success":
        await update.message.reply_text(f"IP API вернул ошибку: {data.get('message')}")
        return

    text = (
        f"🌍 IP-информация для цели: {target} (IP: {data.get('query')})\n\n"
        f"• Континент: {data.get('continent')}\n"
        f"• Страна: {data.get('country')}\n"
        f"• Регион/город: {data.get('regionName')}, {data.get('city')}\n"
        f"• Координаты: {data.get('lat')}, {data.get('lon')}\n\n"
        f"• ISP: {data.get('isp')}\n"
        f"• Организация: {data.get('org')}\n"
        f"• AS: {data.get('as')}\n"
    )

    await update.message.reply_text(text, parse_mode="Markdown")
