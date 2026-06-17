#!/usr/bin/env python3
import socket
import json
from pathlib import Path
from datetime import datetime, timezone


BASE = Path(__file__).resolve().parents[1]

INFRA_DIR = BASE / "data" / "cache" / "infra"
INPUT_HOSTS = INFRA_DIR / "interesting.txt"

OUT_TXT = INFRA_DIR / "ssh_exposed.txt"
OUT_JSON = INFRA_DIR / "ssh_report.json"

INFRA_DIR.mkdir(parents=True, exist_ok=True)


def resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def check_ssh(ip: str, timeout: int = 3) -> str | None:
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner
    except Exception:
        return None


def main():
    if not INPUT_HOSTS.exists():
        print("[!] interesting.txt not found — run infra_discovery first")
        return

    hosts = [h.strip() for h in INPUT_HOSTS.read_text().splitlines() if h.strip()]

    results = []
    exposed = []

    print(f"[+] Checking SSH on {len(hosts)} hosts")

    for host in hosts:
        ip = resolve_ip(host)
        if not ip:
            continue

        banner = check_ssh(ip)
        if banner:
            exposed.append(f"{host} ({ip})")
            results.append({
                "host": host,
                "ip": ip,
                "banner": banner
            })
            print(f"[!] SSH OPEN: {host} → {banner}")

    OUT_TXT.write_text("\n".join(exposed) + ("\n" if exposed else ""))
    OUT_JSON.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(results),
        "results": results
    }, indent=2))

    print(f"[✓] Saved: {OUT_TXT}")
    print(f"[✓] Saved: {OUT_JSON}")
    print(f"[i] SSH exposed: {len(results)}")


if __name__ == "__main__":
    main()
