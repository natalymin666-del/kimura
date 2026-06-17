import requests
from telegram import Update
from telegram.ext import ContextTypes

DNS_API = "https://dns.google/resolve"


def _get_txt_records(name: str):
    """Возвращает список TXT-записей через публичный DNS API."""
    try:
        resp = requests.get(
            DNS_API,
            params={"name": name, "type": "TXT"},
            timeout=6,
        )
        resp.raise_for_status()
        data = resp.json()
        answers = data.get("Answer", [])
        txts = []

        for ans in answers:
            if ans.get("type") == 16:  # TXT
                txt = ans.get("data", "").strip('"')
                txts.append(txt)

        return txts
    except Exception:
        return []


def _analyze_spf(txt_records: list[str]) -> str:
    spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not spf_records:
        return "• SPF: ❌ SPF-запись не найдена."

    lines = ["• SPF: ✅ найдена SPF-запись."]
    for rec in spf_records:
        lines.append(f"  SPF: {rec}")

    # простые подсказки
    if any(" ~all" in r or " -all" in r for r in spf_records):
        lines.append("  ℹ Политика завершения (all) задана.")
    else:
        lines.append("  ⚠ В SPF нет явного ~all или -all — стоит проверить политику.")

    return "\n".join(lines)


def _analyze_dmarc(dmarc_txt: list[str]) -> str:
    if not dmarc_txt:
        return "• DMARC: ❌ запись _dmarc. не найдена."

    lines = ["• DMARC: ✅ найдена DMARC-запись."]
    for rec in dmarc_txt:
        lines.append(f"  DMARC: {rec}")

        rec_lower = rec.lower()
        # очень грубый разбор policy
        if "p=reject" in rec_lower:
            lines.append("  ✅ Политика p=reject — строгая защита от спуфинга.")
        elif "p=quarantine" in rec_lower:
            lines.append("  ⚠ Политика p=quarantine — частичная защита, можно усилить до reject.")
        elif "p=none" in rec_lower:
            lines.append("  ❌ Политика p=none — мониторинг без блокировки, слабая защита.")
    return "\n".join(lines)


async def mailsec_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /mailsec домен — проверка SPF + DMARC.
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для анализа почтовой безопасности.\n\n"
            "Пример:\n"
            "/mailsec tesla.com"
        )
        return

    domain = context.args[0].strip()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    await update.message.reply_text(
        f"📡 Анализ SPF/DMARC для: {domain} ...\n"
        "Запрашиваю DNS TXT-записи…"
    )

    # TXT домена (SPF и прочее)
    txt_root = _get_txt_records(domain)
    # DMARC TXT
    txt_dmarc = _get_txt_records(f"_dmarc.{domain}")

    lines: list[str] = []
    lines.append(f"📨 Mail Security для: {domain}\n")

    # SPF
    lines.append(_analyze_spf(txt_root))
    lines.append("")

    # DMARC
    lines.append(_analyze_dmarc(txt_dmarc))
    lines.append("")

    if not txt_root and not txt_dmarc:
        lines.append("⚠ Ни одна TXT-запись не найдена. Возможно, домен не настроен или сервис DNS не отвечает.")
    else:
        lines.append("Используй это как быстрый чек перед глубоким анализом (SPF/DMARC-тесты, почтовые отчёты и т.п.).")

    text = "\n".join(lines)

    await update.message.reply_text(
        text,
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )
