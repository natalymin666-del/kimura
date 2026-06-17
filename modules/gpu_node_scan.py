#!/usr/bin/env python3
import socket
import json
from pathlib import Path
from datetime import datetime, timezone


BASE = Path(__file__).resolve().parents[1]
INFRA_DIR = BASE / "data" / "cache" / "infra"

INPUT_HOSTS = INFRA_DIR / "interesting.txt"

OUT_TXT = INFRA_DIR / "gpu_nodes.txt"
OUT_JSON = INFRA_DIR / "gpu_report.json"

INFRA_DIR.mkdir(parents=True, exist_ok=True)

GPU_PORTS = {
    8888: "jupyter",
    8889: "jupyter-alt",
    6006: "tensorboard",
    8000: "ml-api",
    5000: "ml-api-alt",
    8265: "ray-dashboard",
}


def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def check_port(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def main():
    if not INPUT_HOSTS.exists():
        print("[!] interesting.txt not found")
        return

    hosts = [h.strip() for h in INPUT_HOSTS.read_text().splitlines() if h.strip()]
    results = []

    print(f"[+] Checking GPU / ML ports on {len(hosts)} hosts")

    for host in hosts:
        ip = resolve_ip(host)
        if not ip:
            continue

        for port, label in GPU_PORTS.items():
            if check_port(ip, port):
                print(f"[!] GPU/ML service: {host}:{port} ({label})")
                results.append({
                    "host": host,
                    "ip": ip,
                    "port": port,
                    "service": label
                })

    OUT_TXT.write_text(
        "\n".join([f"{r['host']}:{r['port']} ({r['service']})" for r in results]) +
        ("\n" if results else "")
    )

    OUT_JSON.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(results),
        "results": results
    }, indent=2))

    print(f"[✓] Saved: {OUT_TXT}")
    print(f"[✓] Saved: {OUT_JSON}")
    print(f"[i] GPU/ML nodes found: {len(results)}")


if __name__ == "__main__":
    main()
