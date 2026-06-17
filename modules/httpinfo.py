import requests
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ContextTypes


def build_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


async def httpinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    if not context.args:
        await update.message.reply_text(
            "Укажи домен или URL.\nПример: /httpinfo tesla.com"
        )
        return

    raw_target = context.args[0]
    url = build_url(raw_target)

    await update.message.reply_text(f"🔍 Запрашиваю HTTP-информацию для: {url} ...")

    try:
        resp = requests.get(
            url,
            timeout=7,
            allow_redirects=True,
            verify=True,
            headers={"User-Agent": "Kimura-HTTPinfo/1.0"},
        )
    except requests.exceptions.SSLError:
        # если проблемы с SSL — пробуем http://
        try:
            url_http = "http://" + raw_target.strip().lstrip("http://").lstrip("https://")
            resp = requests.get(
                url_http,
                timeout=7,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "Kimura-HTTPinfo/1.0"},
            )
            url = url_http
        except Exception as e:
            await update.message.reply_text(f"❌ Ошибка SSL/HTTP: {e}")
            return
    except Exception as e:
        await update.message.reply_text(f"❌ Не удалось получить ответ: {e}")
        return

    final_url = resp.url
    code = resp.status_code
    reason = resp.reason

    history = resp.history or []
    redirects = []
    for h in history:
        redirects.append(f"{h.status_code} → {h.headers.get('Location', '')[:80]}")

    h_server = resp.headers.get("Server", "—")
    h_powered = resp.headers.get("X-Powered-By", "—")
    h_tech = resp.headers.get("X-AspNet-Version") or resp.headers.get("X-Generator")

    parsed = urlparse(final_url)
    scheme_host = f"{parsed.scheme}://{parsed.netloc}"

    lines = []
    lines.append(f"🌐 HTTP-информация для: {scheme_host}")
    lines.append(f"URL ответа: {final_url}")
    lines.append("")
    lines.append(f"Статус: {code} {reason}")
    lines.append("")

    if redirects:
        lines.append("🔁 Цепочка редиректов:")
        for r in redirects:
            lines.append(f" • {r}")
        lines.append("")
    else:
        lines.append("🔁 Редиректы: нет\n")

    lines.append("📦 Ключевые заголовки:")
    lines.append(f" • Server: {h_server}")
    lines.append(f" • X-Powered-By: {h_powered}")
    if h_tech:
        lines.append(f" • Tech: {h_tech}")
    lines.append(f" • Content-Type: {resp.headers.get('Content-Type', '—')}")
    lines.append(f" • Content-Length: {resp.headers.get('Content-Length', '—')}")
    lines.append("")
    lines.append("Используй это как быстрый чек баннера/технологий перед более глубоким анализом (Burp, nikto, nuclei).")

    await update.message.reply_text("\n".join(lines))
