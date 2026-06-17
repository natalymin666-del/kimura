import socket
import ssl
from datetime import datetime, timezone

from telegram import Update
from telegram.ext import ContextTypes


def _parse_openssl_date(date_str: str) -> datetime:
    """
    Преобразуем строки формата 'Nov  3 05:00:00 2026 GMT'
    в объект datetime с UTC.
    """
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


async def ssl_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Проверяем, что пользователь указал домен
    if not context.args:
        await update.message.reply_text(
            "Укажи домен для SSL-анализа.\n\n"
            "Пример:\n"
            "/ssl tesla.com"
        )
        return

    raw_target = context.args[0].strip()

    # Убираем схемы типа https://
    if raw_target.startswith("http://"):
        host = raw_target[len("http://") :]
    elif raw_target.startswith("https://"):
        host = raw_target[len("https://") :]
    else:
        host = raw_target

    # Обрезаем путь, если вдруг написали что-то вроде tesla.com/login
    host = host.split("/")[0]

    try:
        # Устанавливаем TLS-соединение и вытаскиваем сертификат
        context_ssl = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()  # (name, protocol, bits)

    except Exception as e:
        await update.message.reply_text(
            f"Не удалось получить SSL-сертификат для {host}.\n"
            f"Возможные причины:\n"
            f"• сайт недоступен\n"
            f"• нет HTTPS на 443/tcp\n"
            f"• фильтрация трафика или блокировка\n\n"
            f"Техническая ошибка: {type(e)._name_}"
        )
        return

    # Разбор сертификата
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    common_name = subject.get("commonName", "—")
    issuer_cn = issuer.get("commonName", "—")

    not_before_raw = cert.get("notBefore")
    not_after_raw = cert.get("notAfter")

    try:
        not_before = _parse_openssl_date(not_before_raw) if not_before_raw else None
        not_after = _parse_openssl_date(not_after_raw) if not_after_raw else None
    except Exception:
        not_before = not_after = None

    now = datetime.now(timezone.utc)
    days_left_text = "неизвестно"
    status_emoji = "❔"

    if not_after:
        delta = (not_after - now).days
        days_left_text = f"{delta} дн."
        if delta < 0:
            status_emoji = "🔥"  # сертификат истёк
        elif delta < 15:
            status_emoji = "⚠️"  # скоро истечёт
        else:
            status_emoji = "✅"

    san_list = []
    for typ, val in cert.get("subjectAltName", []):
        if typ == "DNS":
            san_list.append(val)

    san_display = ", ".join(san_list[:5]) if san_list else "—"

    cipher_name, cipher_proto, cipher_bits = cipher_info

    msg = (
        f"🔐 SSL-анализ для цели: {host}\n\n"
        f"• Статус сертификата: {status_emoji} (осталось: {days_left_text})\n"
        f"• Выдан для (CN): {common_name}\n"
        f"• Издатель (CA): {issuer_cn}\n"
    )

    if not_before_raw and not_after_raw:
        msg += (
            f"• Действителен с: {not_before_raw}\n"
            f"• Действителен до: {not_after_raw}\n"
        )

    msg += (
        f"• Шифр: {cipher_name} ({cipher_bits} бит), протокол: {cipher_proto}\n"
        f"• SAN (часть списка): {san_display}\n\n"
        f"Используй это как быстрый чек SSL перед более глубоким анализом "
        f"(sslyze, testssl.sh, burp)."
    )

    await update.message.reply_text(msg)
