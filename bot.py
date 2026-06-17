import os
from dotenv import load_dotenv
load_dotenv()
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

from modules.subdomains import subdomains_command
from modules.osint import osint_command
from modules.leaks import leaks_command
from modules.whois_module import whois_command
from modules.ipinfo import ipinfo_command
from modules.tech import tech_command
from modules.ports import ports_command
from modules.dnsinfo import dns_command
from modules.headers import headers_command
from modules.adminscan import adminscan_command
from modules.fullscan import fullscan_command
from modules.robots import robots_command
from modules.wayback import wayback_command
from modules.screenshot import screenshot_command
from modules.sslscan import ssl_command
from modules.email_osint import emailosint_command
from modules.dirscan import dirscan_command
from modules.geomap import geomap_command
from modules.reverseip import reverseip_command
from modules.revip import revip_command
from modules.risk import risk_command
from modules.trace import trace_command
from modules.dorks import dorks_command
from modules.mailsec import mailsec_command
from modules.jsfind import jsfind_command
from modules.subscan import subscan_command
from modules.techscan import techscan_command
from modules.cidr import cidr_command
from modules.dnsdump import dnsdump_command
from modules.asninfo import asninfo_command
from modules.httpinfo import httpinfo_command
from modules.subnet import subnet_command
from modules.urls import urls_command, deepurls_command
from modules.deepattack import deepattack_command
from modules.apihunter import apihunt_command
from modules.secrets import secrets_command
from modules.deepsecrets import deepsecrets_command
from modules.fuzzer import fuzz_command, fuzzplus_command
from modules.xssdeep import xssdeep_command
from modules.autopoc import autopoc_command
from modules.chainhunt import chainhunt_command
from modules.attack import attack_command
from modules.autorecon import autorecon_command
from modules.sqli import sqli_command
from modules.redirects import redirects_command
from modules.corsscan import corsscan_command
from modules.deeprecon import deeprecon_command
from modules.attackpath import attackpath_command

TOKEN = os.getenv("BOT_TOKEN")


# ---------- выбор языка ----------

def get_user_lang(update: Update) -> str:
    """
    Возвращает 'ru', если язык Telegram у пользователя русский,
    иначе 'en' (по умолчанию).
    """
    code = (update.effective_user.language_code or "").lower()
    if code.startswith("ru"):
        return "ru"
    return "en"


# ---------- команды ----------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    lang = get_user_lang(update)

    if lang == "ru":
        text = "Kimura активирован. 👾"
    else:
        text = "Kimura activated. 👾"

    await update.message.reply_text(text)


async def deepsecrets_scan(update, context):
    try:
        domain = update.message.text.split()[1]
    except:
        await update.message.reply_text("❗ Укажи домен: /deepsecrets example.com")
        return

    await update.message.reply_text(f"🔍 Secrets Hunter (aggressive) для: {domain}\nИщу расширенный набор секретов…")

    # вызываем твою основную логику сканирования
    result = deepsecrets_main(domain)

    await update.message.reply_text(result)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "📚 Доступные команды:\n"
        "/start — активировать Kimura\n"
        "/help — показать это меню\n"
        "/osint домен — базовый OSINT-профиль\n"
        "/leaks email — проверка утечек (demo)\n"
        "/whois домен — WHOIS-информация\n"
        "/ipinfo домен — данные об IP (geo, ISP, AS)\n"
        "/tech домен — анализ технологий сайта (demo)\n"
        "/ports домен — быстрый скан популярных портов\n"
        "/dns домен — DNS-записи (A/MX/NS/TXT)\n"
        "/headers домен — анализ security headers\n"
        "/adminscan домен — поиск админ-панелей\n"
        "/fullscan домен — Kimura Full Scan\n"
        "/robots домен — анализ robots.txt\n"
        "/wayback домен — снимок из Wayback Machine\n"
        "/screenshot домен — скриншот главной страницы\n"
        "/ssl домен — анализ SSL-сертификата\n"
        "/emailosint email — расширенный email OSINT (demo)\n"
        "/dirscan домен — поиск скрытых директорий\n"
        "/geomap домен — точка на карте по GeoIP\n"
        "/reverseip цель — обратный DNS (PTR)\n"
        "/revip домен — Reverse IP (домены на одном IP, demo)\n"
        "/risk домен — быстрый security-чек сайта по заголовкам\n"
        "/trace домен/URL – HTTP-трассировка и проверка редиректов\n"
        "/dorks домен — генератор Google dorks для OSINT\n"
        "/mailsec домен – SPF/DMARC-проверка почтовой безопасности\n"
        "/jsfind домен – поиск JS-файлов на главной странице\n"
        "/subscan домен – поиск поддоменов (multi-source, demo)\n"
        "/techscan домен – определение технологий сайта (whatweb-lite)\n"
        "/cidr домен – получить ASN и все CIDR-подсети организации\n"
        "/dnsdump домен – расширенный DNS-анализ (A, MX, NS, TXT, SOA…)\n"
        "/asninfo домен — анализ ASN и префиксов подсетей\n"
        "/httpinfo домен — HTTP-информация и баннер\n"
        "/subnet сеть — расширение подсети (CIDR → список IP)\n"
        "/urls домен – сбор URL (Wayback + sitemap + главная страница)\n"
        "/deepurls домен – глубокий сбор URL (спайдер + JS-эндпоинты)\n"
        "/deepattack домен – анализ интересных URL (статусы, заголовки)\n"
        "/apihunt домен – поиск API-эндпоинтов в JS/HTML (для bug bounty)\n"
        "/secrets домен – поиск потенциальных секретов в JS/HTML (API-ключи, токены, JWT)\n"

        "/deepsecrets домен – агрессивный поиск секретов (Stripe, Slack, Discord, .env, high-entropy)\n"
        "/fuzz URL-с-FUZZ — быстрый fuzzer по URL (ищет 500/403/ошибки)\n"

        "/xssdeep URL(FUZZ) – умный XSS-поиск по URL с плейсхолдером FUZZ\n"
        "/autopoc URL – сгенерировать черновики PoC (линк, JS, curl)\n"
        "/chainhunt URL – анализ заголовков/куки и идеи exploit-цепочек\n"
    )
    await update.message.reply_text(text)

app = ApplicationBuilder().token(TOKEN).build()

# обработчики команд
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("help", help_command))
app.add_handler(CommandHandler("subdomains", subdomains_command))
app.add_handler(CommandHandler("osint", osint_command))
app.add_handler(CommandHandler("leaks", leaks_command))
app.add_handler(CommandHandler("whois", whois_command))
app.add_handler(CommandHandler("ipinfo", ipinfo_command))
app.add_handler(CommandHandler("tech", tech_command))
app.add_handler(CommandHandler("ports", ports_command))
app.add_handler(CommandHandler("dns", dns_command))
app.add_handler(CommandHandler("fullscan", fullscan_command))
app.add_handler(CommandHandler("headers", headers_command))
app.add_handler(CommandHandler("adminscan", adminscan_command))
app.add_handler(CommandHandler("robots", robots_command))
app.add_handler(CommandHandler("wayback", wayback_command))
app.add_handler(CommandHandler("screenshot", screenshot_command))
app.add_handler(CommandHandler("ssl", ssl_command))
app.add_handler(CommandHandler("emailosint", emailosint_command))
app.add_handler(CommandHandler("dirscan", dirscan_command))
app.add_handler(CommandHandler("geomap", geomap_command))
app.add_handler(CommandHandler("reverseip", reverseip_command))
app.add_handler(CommandHandler("revip", revip_command))
app.add_handler(CommandHandler("risk", risk_command))
app.add_handler(CommandHandler("trace", trace_command))
app.add_handler(CommandHandler("dorks", dorks_command))
app.add_handler(CommandHandler("mailsec", mailsec_command))
app.add_handler(CommandHandler("jsfind", jsfind_command))
app.add_handler(CommandHandler("subscan", subscan_command))
app.add_handler(CommandHandler("techscan", techscan_command))
app.add_handler(CommandHandler("cidr", cidr_command))
app.add_handler(CommandHandler("dnsdump", dnsdump_command))
app.add_handler(CommandHandler("asninfo", asninfo_command))
app.add_handler(CommandHandler("httpinfo", httpinfo_command))
app.add_handler(CommandHandler("subnet", subnet_command))
app.add_handler(CommandHandler("urls", urls_command))
app.add_handler(CommandHandler("deepurls", deepurls_command))
app.add_handler(CommandHandler("deepattack", deepattack_command))
app.add_handler(CommandHandler("apihunt", apihunt_command))
app.add_handler(CommandHandler("secrets", secrets_command))
app.add_handler(CommandHandler("deepsecrets", deepsecrets_command))
app.add_handler(CommandHandler("fuzz", fuzz_command))
app.add_handler(CommandHandler("fuzzplus", fuzzplus_command))
app.add_handler(CommandHandler("xssdeep", xssdeep_command))
app.add_handler(CommandHandler("autopoc", autopoc_command))
app.add_handler(CommandHandler("chainhunt", chainhunt_command))
app.add_handler(CommandHandler("attack", attack_command))
app.add_handler(CommandHandler("autorecon", autorecon_command))
app.add_handler(CommandHandler("sqli", sqli_command))
app.add_handler(CommandHandler("redir", redirects_command))
app.add_handler(CommandHandler("cors", corsscan_command))
app.add_handler(CommandHandler("deeprecon", deeprecon_command))
app.add_handler(CommandHandler("attackpath", attackpath_command))

app.run_polling()
