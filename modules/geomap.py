import socket
import requests
from telegram import Update
from telegram.ext import ContextTypes


async def geomap_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """GeoIP + точка на карте для домена."""

    if not context.args:
        await update.message.reply_text(
            "Укажи домен для GeoIP-карты.\n\n"
            "Пример:\n"
            "/geomap tesla.com"
        )
        return

    domain = context.args[0].strip()

    # Убираем протокол, если вдруг напишут https://
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    # 1) Резолвим домен в IP
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        await update.message.reply_text(
            f"Не удалось получить IP для {domain}:\n{e}"
        )
        return

    # 2) GeoIP через публичное API (ip-api.com)
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query",
            timeout=5,
        )
        data = resp.json()

        if data.get("status") != "success":
            raise Exception(data.get("message", "unknown error"))

    except Exception as e:
        await update.message.reply_text(
            f"Не удалось получить GeoIP для {ip}:\n{e}"
        )
        return

    lat = data.get("lat")
    lon = data.get("lon")

    if lat is None or lon is None:
        await update.message.reply_text(
            f"Сервис GeoIP не вернул координаты для {ip}."
        )
        return

    # 3) Сначала отправляем точку на карте (Telegram сам рисует карту)
    await update.message.reply_location(latitude=lat, longitude=lon)

    # 4) Потом текстовый отчёт + ссылки на карты
    text = (
        f"🗺 GeoIP для цели: {domain} ({ip})\n\n"
        f"• Страна: {data.get('country')}\n"
        f"• Регион/город: {data.get('regionName')}, {data.get('city')}\n"
        f"• ISP: {data.get('isp')}\n"
        f"• Организация: {data.get('org')}\n"
        f"• AS: {data.get('as')}\n\n"
        f"🔗 Google Maps: https://www.google.com/maps?q={lat},{lon}\n"
        f"🔗 OpenStreetMap: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=10/{lat}/{lon}"
    )

    await update.message.reply_text(text)
