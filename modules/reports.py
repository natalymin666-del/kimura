import os
from datetime import datetime
from pathlib import Path

# Базовая папка проекта (~/kimura)
BASE_DIR = Path(__file__).resolve().parent.parent

# Папка для отчётов: ~/kimura/data/reports
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def save_report(command: str, target: str, content: str) -> str:
    """
    Сохраняет текстовый отчёт в data/reports.
    Возвращает путь к файлу (на будущее).
    """
    if not target:
        target = "unknown"

    # чуть-чуть чистим строку, чтобы получилось нормальное имя файла
    safe_target = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(" ", "_")
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}{command}{safe_target}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"Command: {command}\n")
        f.write(f"Target:  {target}\n")
        f.write(f"Time:    {timestamp} (UTC)\n")
        f.write("\n")
        f.write(content)

    return filepath
