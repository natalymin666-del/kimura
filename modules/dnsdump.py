import dns.resolver
import dns.reversename
from telegram import Update
from telegram.ext import ContextTypes

async def dnsdump_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    if not context.args:
        await update.message.reply_text("Укажи домен.\nПример: /dnsdump tesla.com")
        return

    domain = context.args[0].strip().lower()

    await update.message.reply_text(f"🔍 Выполняю расширенный DNS-анализ: {domain} ...")

    def query(record_type):
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except:
            return []

    a_records = query("A")
    aaaa_records = query("AAAA")
    mx_records = query("MX")
    ns_records = query("NS")
    txt_records = query("TXT")
    cname_records = query("CNAME")
    soa_records = query("SOA")

    # PTR для первого IP A-записи
    ptr_name = None
    if a_records:
        try:
            rev = dns.reversename.from_address(a_records[0])
            ptr_res = dns.resolver.resolve(rev, "PTR")
            ptr_name = str(ptr_res[0])
        except:
            ptr_name = None

    lines = []
    lines.append(f"🧠 DNSDump для домена: {domain}")
    lines.append("")

    lines.append("A-записи:")
    lines.extend([f" • {x}" for x in a_records] or [" • нет"])

    lines.append("\nAAAA-записи:")
    lines.extend([f" • {x}" for x in aaaa_records] or [" • нет"])

    lines.append("\nMX-записи:")
    lines.extend([f" • {x}" for x in mx_records] or [" • нет"])

    lines.append("\nNS-серверы:")
    lines.extend([f" • {x}" for x in ns_records] or [" • нет"])

    lines.append("\nTXT:")
    lines.extend([f" • {x}" for x in txt_records] or [" • нет"])

    lines.append("\nCNAME:")
    lines.extend([f" • {x}" for x in cname_records] or [" • нет"])

    lines.append("\nSOA:")
    lines.extend([f" • {x}" for x in soa_records] or [" • нет"])

    lines.append("\nPTR (reverse lookup):")
    lines.append(f" • {ptr_name}" if ptr_name else " • нет")

    await update.message.reply_text("\n".join(lines))
