from telegram import Update
from telegram.ext import ContextTypes
import ipaddress


async def subnet_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # если ничего не передали
    if not context.args:
        await update.message.reply_text(
            "Укажи подсеть в формате CIDR.\n"
            "Пример: /subnet 192.168.0.0/30"
        )
        return

    cidr = context.args[0].strip()

    # пробуем разобрать подсеть
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        await update.message.reply_text(
            "Некорректный формат подсети.\n"
            "Используй формат CIDR, например:\n"
            "/subnet 192.168.0.0/30"
        )
        return

    hosts = list(network.hosts())

    # чтобы бот не спамил сотнями IP
    max_hosts = 32
    if len(hosts) > max_hosts:
        await update.message.reply_text(
            f"Подсеть {network.with_prefixlen} содержит {len(hosts)} адресов — это слишком много для вывода.\n"
            "Попробуй более узкую сеть, например с маской /28 или /30."
        )
        return

    lines = [
        f"🧩 Subnet info: {network.with_prefixlen}",
        f"• Network: {network.network_address}",
        f"• Netmask: {network.netmask}",
        f"• Broadcast: {network.broadcast_address}",
        f"• Hosts ({len(hosts)}):"
    ]

    for ip in hosts:
        lines.append(f"  – {ip}")

    await update.message.reply_text("\n".join(lines))
