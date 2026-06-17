import requests
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ContextTypes

TIMEOUT = 7


def build_domain_url(domain: str) -> str:
    domain = domain.strip()
    if not domain.startswith("http://") and not domain.startswith("https://"):
        # начинаем с https по умолчанию
        domain = "https://" + domain
    return domain


def format_hop(index: int, resp: requests.Response) -> str:
    url = resp.url
    code = resp.status_code
    parsed = urlparse(url)
    scheme = parsed.scheme
    host = parsed.netloc
    path = parsed.path or "/"
    return f"{index}) {scheme}://{host}{path} — HTTP {code}"


def analyze_chain(responses: list[requests.Response], original_url: str) -> str:
    lines: list[str] = []
    lines.append(f"🚦 HTTP-трассировка для: {original_url}\n")

    # Цепочка переходов
    history = responses[:-1]
    final_resp = responses[-1]

    if not history:
        lines.append("• Редиректов нет, ответ сразу от исходного URL.\n")
    else:
        lines.append("• Цепочка редиректов:")
        for i, r in enumerate(history, start=1):
            lines.append("  " + format_hop(i, r))
        lines.append("")

    # Финальный ответ
    lines.append("🏁 Финальный ответ:")
    lines.append("  " + format_hop(len(responses), final_resp))
    lines.append("")

    # Анализ HTTPS
    start_scheme = urlparse(original_url).scheme or "https"
    final_scheme = urlparse(final_resp.url).scheme

    if start_scheme == "http" and final_scheme == "https":
        lines.append("✅ HTTP → HTTPS: сайт принудительно перенаправляет на HTTPS.")
    elif start_scheme == "https" and final_scheme == "https":
        lines.append("✅ HTTPS остаётся HTTPS.")
    elif final_scheme == "http":
        lines.append("❌ Финальный URL использует HTTP — возможные риски для трафика.")
    else:
        lines.append(f"ℹ️ Итоговая схема: {final_scheme}")

    # Некоторые советы
    code = final_resp.status_code
    if code == 200:
        lines.append("✅ Статус 200: страница успешно отдается.")
    elif code in (301, 302, 303, 307, 308):
        lines.append(f"⚠️ Финальный статус {code}: постоянный/временный редирект.")
    elif code == 404:
        lines.append("❌ Финальный статус 404: страница не найдена.")
    elif 400 <= code < 600:
        lines.append(f"❌ Финальный статус {code}: ошибка на стороне клиента/сервера.")

    lines.append("")
    lines.append("Используй это как быстрый чек поведения сайта перед более глубоким анализом (Burp, браузер, proxy).")

    return "\n".join(lines)


async def trace_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text(
            "Укажи домен или URL.\n\nПример:\n"
            "/trace tesla.com\n"
            "/trace http://example.com"
        )
        return

    domain = " ".join(context.args)
    original_url = build_domain_url(domain)

    try:
        await update.message.reply_text(f"🔍 Запускаю HTTP-трассировку для: {original_url} ...")

        resp = requests.get(
            original_url,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=True,
        )

        # Собираем всю цепочку: history + финальный ответ
        responses: list[requests.Response] = list(resp.history) + [resp]

        text = analyze_chain(responses, original_url)
        await update.message.reply_text(text)

    except requests.exceptions.SSLError:
        await update.message.reply_text(
            "❌ Ошибка SSL при подключении к цели. "
            "Попробуй указать домен без http/https или проверь сертификат."
        )
    except requests.exceptions.RequestException as e:
        await update.message.reply_text(
            f"❌ Не удалось выполнить запрос к {original_url}.\n"
            f"Ошибка: {e}"
        )
