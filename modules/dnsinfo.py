from telegram import Update
from telegram.ext import ContextTypes
import dns.resolver


def _safe_query(domain: str, rtype: str):
    """Безопасно делает DNS-запрос, всегда возвращает список строк."""
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [ans.to_text() for ans in answers]
    except Exception:
        return []


async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для DNS-анализа.\n\n"
            "Пример:\n"
            "/dns tesla.com\n"
            "/dns yandex.ru"
        )
        return

    domain = context.args[0].strip()

    lines = [f"🌐 DNS-информация для цели: {domain}\n"]
    # A / AAAA
    a_records = _safe_query(domain, "A")
    if a_records:
        lines.append("A-записи (IPv4):")
        for r in a_records:
            lines.append(f"• {r}")
        lines.append("")

    aaaa_records = _safe_query(domain, "AAAA")
    if aaaa_records:
        lines.append("AAAA-записи (IPv6):")
        for r in aaaa_records:
            lines.append(f"• {r}")
        lines.append("")

    # MX
    mx_records = _safe_query(domain, "MX")
    if mx_records:
        lines.append("MX-записи (почтовые сервера):")
        for r in mx_records:
            lines.append(f"• {r}")
        lines.append("")

    # NS
    ns_records = _safe_query(domain, "NS")
    if ns_records:
        lines.append("NS-записи (DNS-серверы):")
        for r in ns_records:
            lines.append(f"• {r}")
        lines.append("")

    # TXT (SPF / DMARC)
    txt_records = _safe_query(domain, "TXT")
    if txt_records:
        lines.append("TXT-записи:")
        for r in txt_records:
            lines.append(f"• {r}")
        lines.append("")

        spf = [r for r in txt_records if "v=spf1" in r.lower()]
        dmarc = [r for r in txt_records if "v=dmarc1" in r.lower()]

        if spf:
            lines.append("🔐 SPF-политика:")
            for r in spf:
                lines.append(f"• {r}")
            lines.append("")

        if dmarc:
            lines.append("🛡 DMARC-политика:")
            for r in dmarc:
                lines.append(f"• {r}")
            lines.append("")

    if len(lines) == 1:
        lines.append("Не удалось получить DNS-записи. Возможно, домен не существует или DNS закрыт.")

    text = "\n".join(lines)
    # На всякий случай ограничим длину сообщения
    if len(text) > 3900:
        text = text[:3900] + "\n\n(Обрезано: вывод слишком длинный)"

    await update.message.reply_text(text, parse_mode="Markdown")
