from telegram import Update
from telegram.ext import ContextTypes

import socket
import requests
import dns.resolver
import whois


COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-alt",
}


def _safe_dns(domain: str, rtype: str):
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [a.to_text() for a in answers]
    except Exception:
        return []


def _resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _check_ports(ip: str):
    open_ports = []
    for port, name in COMMON_PORTS.items():
        try:
            with socket.create_connection((ip, port), timeout=0.5):
                open_ports.append((port, name))
        except Exception:
            continue
    return open_ports


def _ip_info(ip: str):
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,org,isp,as",
            timeout=5,
        )
        data = resp.json()
        if data.get("status") != "success":
            return None
        return data
    except Exception:
        return None


def _safe_whois(domain: str):
    try:
        w = whois.whois(domain)
        return {
            "registrar": getattr(w, "registrar", None),
            "country": getattr(w, "country", None),
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
        }
    except Exception:
        return None


async def fullscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для полного скана.\n\n"
            "Пример:\n"
            "/fullscan tesla.com"
        )
        return

    domain = context.args[0].strip()
    lines: list[str] = []
    lines.append(f"🧪 Kimura Full Scan для цели: {domain}\n")

    # 1. Домен → IP
    ip = _resolve_ip(domain)
    if ip:
        lines.append(f"🔹 IP адрес: {ip}")
    else:
        lines.append("⚠ Не удалось получить IP для домена.")
        await update.message.reply_text("\n".join(lines))
        return

    # 2. IP-информация
    info = _ip_info(ip)
    if info:
        lines.append("")
        lines.append("🌍 IP-информация:")
        if info.get("country"):
            lines.append(f"• Страна: {info['country']}")
        if info.get("regionName") or info.get("city"):
            lines.append(
                "• Регион/город: "
                f"{info.get('regionName','')} {info.get('city','')}".strip()
            )
        if info.get("org"):
            lines.append(f"• Организация: {info['org']}")
        if info.get("isp"):
            lines.append(f"• ISP: {info['isp']}")
        if info.get("as"):
            lines.append(f"• AS: {info['as']}")

    # 3. DNS (кратко)
    a_records = _safe_dns(domain, "A")
    mx_records = _safe_dns(domain, "MX")
    ns_records = _safe_dns(domain, "NS")

    if any([a_records, mx_records, ns_records]):
        lines.append("")
        lines.append("🧬 DNS-краткий обзор:")
        if a_records:
            lines.append(f"• A-записей: {len(a_records)} (первые 3):")
            for r in a_records[:3]:
                lines.append(f"  – {r}")
        if mx_records:
            lines.append(f"• MX-записей: {len(mx_records)} (первые 3):")
            for r in mx_records[:3]:
                lines.append(f"  – {r}")
        if ns_records:
            lines.append(f"• NS-серверов: {len(ns_records)} (первые 3):")
            for r in ns_records[:3]:
                lines.append(f"  – {r}")

    # 4. WHOIS (кратко)
    w = _safe_whois(domain)
    if w:
        lines.append("")
        lines.append("📜 WHOIS (кратко):")
        if w.get("registrar"):
            lines.append(f"• Регистратор: {w['registrar']}")
        if w.get("country"):
            lines.append(f"• Страна: {w['country']}")
        if w.get("creation_date"):
            lines.append(f"• Дата регистрации: {w['creation_date']}")
        if w.get("expiration_date"):
            lines.append(f"• Истекает: {w['expiration_date']}")

    # 5. Быстрый скан портов
    ports = _check_ports(ip)
    lines.append("")
    lines.append("🔓 Быстрый скан популярных портов:")
    if ports:
        for port, name in ports:
            lines.append(f"• {port}/tcp — {name}")
    else:
        lines.append("• Открытых портов из списка не найдено.")

    text = "\n".join(lines)
    if len(text) > 3900:
        text = text[:3900] + "\n\n(Обрезано: отчёт слишком длинный)"

    await update.message.reply_text(text)
