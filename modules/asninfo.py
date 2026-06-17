import socket
import requests
from telegram import Update
from telegram.ext import ContextTypes


async def asninfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # проверяем аргументы
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\nПример: /asninfo tesla.com"
        )
        return

    raw_target = context.args[0].strip()

    # убираем http/https, если пользователь вставил URL
    raw_target = raw_target.replace("http://", "").replace("https://", "").strip("/")
    domain = raw_target

    # 1) резолвим домен в IP
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        await update.message.reply_text(
            f"Не удалось получить IP для домена: {domain}"
        )
        return

    # 2) запрашиваем BGPView по IP
    api_url = f"https://api.bgpview.io/ip/{ip}"

    try:
        resp = requests.get(api_url, timeout=6)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        await update.message.reply_text(
            "Не удалось получить данные ASN. "
            "Возможно, BGP-API сейчас недоступно."
        )
        return

    if data.get("status") != "ok" or "data" not in data:
        await update.message.reply_text(
            "BGP-сервис вернул некорректный ответ. "
            "Попробуй позже или с другим доменом."
        )
        return

    ip_data = data["data"]

    asn_info = ip_data.get("asn", {}) or {}
    as_number = asn_info.get("asn")
    as_name = asn_info.get("name")
    as_country = asn_info.get("country_code")

    prefixes = ip_data.get("prefixes", []) or []

    # собираем списки префиксов IPv4 / IPv6
    ipv4_prefixes = [p.get("prefix") for p in prefixes if p.get("ip_version") == 4]
    ipv6_prefixes = [p.get("prefix") for p in prefixes if p.get("ip_version") == 6]

    # ограничим вывод, чтобы не заваливать чат
    max_show = 5
    ipv4_show = ipv4_prefixes[:max_show]
    ipv6_show = ipv6_prefixes[:max_show]

    lines: list[str] = []

    lines.append(f"🛰 ASN-анализ для цели: {domain} (IP: {ip})")
    lines.append("")

    if as_number:
        lines.append(f"• ASN: AS{as_number}")
    else:
        lines.append("• ASN: неизвестен")

    lines.append(f"• Организация: {as_name or 'неизвестно'}")
    lines.append(f"• Страна: {as_country or 'неизвестна'}")
    lines.append("")

    # IPv4 префиксы
    if ipv4_show:
        lines.append(f"📡 IPv4-префиксы (первые {len(ipv4_show)}):")
        for p in ipv4_show:
            lines.append(f"  – {p}")
    else:
        lines.append("📡 IPv4-префиксы: не найдены")

    lines.append("")

    # IPv6 префиксы
    if ipv6_show:
        lines.append(f"🛰 IPv6-префиксы (первые {len(ipv6_show)}):")
        for p in ipv6_show:
            lines.append(f"  – {p}")
    else:
        lines.append("🛰 IPv6-префиксы: не найдены")

    # ссылки на BGP-инструменты
    if as_number:
        lines.append("")
        lines.append("🔗 Полезные ссылки для дальнейшего анализа:")
        lines.append(f"  • BGPView: https://bgpview.io/asn/{as_number}")
        lines.append(f"  • bgp.he.net: https://bgp.he.net/AS{as_number}")

    lines.append("")
    lines.append("Режим: demo, через публичный BGP-API.")
    lines.append("Используй как старт для поиска связанных подсетей и сервисов.")

    await update.message.reply_text("\n".join(lines))
