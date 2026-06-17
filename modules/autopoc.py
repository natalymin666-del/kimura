from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode


async def autopoc_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /autopoc URL_С_PAYLOAD

    Пример:
    /autopoc "http://testphp.vulnweb.com/artists.php?artist=<script>alert(1)</script>"
    """
    if not context.args:
        await update.message.reply_text(
            "Формат: /autopoc URL_С_PAYLOAD\n"
            "Например:\n"
            '/autopoc "http://site.com/page?q=<script>alert(1)</script>"'
        )
        return

    raw_url = context.args[0].strip().strip('"').strip("'")

    link_poc = f'<a href="{raw_url}">Click me</a>'
    js_poc = f'<script>location.href="{raw_url}";</script>'
    curl_poc = f'curl -k "{raw_url}"'

    text = (
        f"🧪 AutoPoC для:\n{raw_url}\n\n"
        "Черновики PoC (используй только в рамках легального pentest / bug bounty):\n\n"
        "1️⃣ HTML-линк:\n"
        f"```html\n{link_poc}\n```\n\n"
        "2️⃣ JS-редирект:\n"
        f"```html\n{js_poc}\n```\n\n"
        "3️⃣ cURL-запрос:\n"
        f"```bash\n{curl_poc}\n```"
    )

    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)
