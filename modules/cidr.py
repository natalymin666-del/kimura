import requests
import socket
from telegram import Update
from telegram.ext import ContextTypes


TIMEOUT = 8


def get_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def get_asn_info(ip: str) -> dict | None:
    """Используем бесплатный API ipinfo.io (без токена — ограничено, но работает)."""
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=TIMEOUT)
        return resp.json()
    except Exception:
        return None


def get_cidr_by_asn(asn: str) -> list[str]:
    """
    Получаем CIDR через API bgpview.io.
    Стабильный бесплатный источник.
    """
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        data = resp.json()
        blocks = []

        # IPv4
        for p in data.get("data", {}).get("ipv4_prefixes", []):
            blocks.append(p.get("prefix"))

        # IPv6 тоже можно, оставим как расширение:
        # for p in data.get("data", {}).get("ipv6_prefixes", []):
        #     blocks.append(p.get("prefix"))

        return blocks
    except Exception:
        return []


async def cidr_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /cidr домен — получить CIDR подсети и AS организации.
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/cidr tesla.com"
        )
        return

    domain = context.args[0].strip()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    await update.message.reply_text(f"🔍 Определяю IP и ASN для: {domain} ...")

    ip = get_ip(domain)
    if not ip:
        await update.message.reply_text("❌ Не удалось получить IP-адрес.")
        return

    asn_info = get_asn_info(ip)
    if not asn_info or "org" not in asn_info:
        await update.message.reply_text(
            f"IP: {ip}\n"
            "❌ ASN-информация не найдена."
        )
        return

    org = asn_info.get("org", "Unknown").strip()
    asn = None

    # org может быть вида "AS123 Tesla Inc"
    if org.lower().startswith("as"):
        parts = org.split()
        if parts:
            asn = parts[0][2:]  # "AS123" → "123"

    if not asn:
        await update.message.reply_text(
            f"IP: {ip}\n"
            f"Организация: {org}\n"
            "❌ Номер AS не найден."
        )
        return

    # Получаем CIDR
    cidr_blocks = get_cidr_by_asn(asn)

    if not cidr_blocks:
        await update.message.reply_text(
            f"IP: {ip}\n"
            f"Организация: {org}\n"
            f"ASN: AS{asn}\n\n"
            "❌ CIDR-блоки не найдены."
        )
        return

    max_show = 50
    show = cidr_blocks[:max_show]

    lines = []
    lines.append(f"🌐 CIDR scan для: {domain}")
    lines.append(f"IP: {ip}")
    lines.append(f"Организация: {org}")
    lines.append(f"ASN: AS{asn}")
    lines.append("")
    lines.append(f"Найдено подсетей: {len(cidr_blocks)}")
    if len(cidr_blocks) > max_show:
        lines.append(f"(показаны первые {max_show})")
    lines.append("")

    for block in show:
        lines.append(f"• {block}")

    lines.append("")
    lines.append(
        "Используй CIDR для картирования инфраструктуры,\n"
        "поиска сервисов и пентест-исследований."
    )

    await update.message.reply_text(
        "\n".join(lines),
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )
