#!/usr/bin/env python3
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime


BASE = Path(__file__).resolve().parents[1]  # ~/kimura

TARGET_FILE = BASE / "data" / "targets" / "target.txt"
CACHE_DIR = BASE / "data" / "cache" / "infra"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

OUT_SUBDOMAINS = CACHE_DIR / "subdomains.txt"
OUT_INTERESTING = CACHE_DIR / "interesting.txt"
OUT_LIVE_HTTP = CACHE_DIR / "live_http.txt"
OUT_MAP_JSON = CACHE_DIR / "infra_map.json"


FOCUS_KEYWORDS = [
    # AI / GPU
    "gpu", "a100", "h100", "cuda", "nvidia", "ml", "ai", "llm", "inference", "model",
    "jupyter", "notebook", "ray", "triton", "kserve", "seldon",
    # Crypto
    "wallet", "rpc", "node", "validator", "staking", "miner", "mining", "pool",
    "eth", "sol", "btc", "polygon", "chain", "bridge",
    # Management / access
    "admin", "console", "panel", "manage", "mgmt", "bastion", "jump", "vpn", "ssh", "rdp",
    "grafana", "prometheus", "kibana", "elastic", "loki", "tempo",
    "vault", "consul",
    # K8s / Docker / infra
    "k8s", "kube", "kubernetes", "api", "gateway", "ingress",
    "docker", "registry", "harbor",
    # Dev / staging
    "dev", "staging", "stage", "test", "uat", "preprod", "old", "legacy",
]


def sh(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def ensure_tool(name: str) -> None:
    # bash -lc helps find tools in PATH that come from ~/.bashrc
    p = sh(["bash", "-lc", f"command -v {name} >/dev/null 2>&1 && echo OK"])
    if "OK" not in (p.stdout or ""):
        print(f"[!] Tool not found: {name}")
        raise SystemExit(1)


def normalize_lines(text: str) -> list[str]:
    lines = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        # remove weird prefixes/spaces
        s = re.sub(r"\s+", "", s)
        lines.append(s.lower())
    # dedupe while keeping order
    seen = set()
    out = []
    for x in lines:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def is_interesting(host: str) -> bool:
    h = host.lower()
    return any(k in h for k in FOCUS_KEYWORDS)


def run_subfinder(domain: str) -> list[str]:
    ensure_tool("subfinder")
    print(f"[+] subfinder -d {domain}")
    p = sh(["subfinder", "-d", domain])
    if p.returncode != 0:
        err = (p.stderr or "").strip()
        print("[!] subfinder error:", err[:400] if err else "(no stderr)")
        return []
    return normalize_lines(p.stdout)


def run_httpx(hosts: list[str]) -> list[str]:
    """
    Pure python HTTP/HTTPS liveness check.
    """
    import ssl
    from urllib.request import Request, urlopen

    live = []

    for host in hosts:
        for scheme in ("https://", "http://"):
            url = scheme + host
            try:
                req = Request(url, headers={"User-Agent": "kimura"})
                with urlopen(req, timeout=5, context=ssl.create_default_context()) as r:
                    if r.status < 500:
                        live.append(url)
                        break
            except Exception:
                pass

    return live


def main() -> None:
    TARGET_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not TARGET_FILE.exists():
        print(f"[!] Target file not found: {TARGET_FILE}")
        print("    Create it: nano ~/kimura/data/targets/target.txt")
        raise SystemExit(1)

    domain = TARGET_FILE.read_text(encoding="utf-8").strip()
    if not domain:
        print("[!] target.txt is empty (put a domain, e.g. example.com)")
        raise SystemExit(1)

    # 1) Discover
    subdomains = run_subfinder(domain)
    OUT_SUBDOMAINS.write_text("\n".join(subdomains) + ("\n" if subdomains else ""), encoding="utf-8")

    # 2) Focus filter
    interesting = [h for h in subdomains if is_interesting(h)]
    OUT_INTERESTING.write_text("\n".join(interesting) + ("\n" if interesting else ""), encoding="utf-8")

    # 3) Live HTTP check (prioritize interesting first, then all if small)
    # To keep it fast, we check interesting; if none, check top N from all.
    to_check = interesting if interesting else subdomains[:300]
    live = run_httpx(to_check)
    OUT_LIVE_HTTP.write_text("\n".join(live) + ("\n" if live else ""), encoding="utf-8")

    # 4) Map JSON
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": domain,
        "counts": {
            "subdomains": len(subdomains),
            "interesting": len(interesting),
            "live_http_checked": len(to_check),
            "live_http_found": len(live),
        },
        "files": {
            "subdomains": str(OUT_SUBDOMAINS),
            "interesting": str(OUT_INTERESTING),
            "live_http": str(OUT_LIVE_HTTP),
        },
        "sample": {
            "interesting": interesting[:50],
            "live_http": live[:50],
        },
    }
    OUT_MAP_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[✓] Saved: {OUT_SUBDOMAINS}")
    print(f"[✓] Saved: {OUT_INTERESTING}")
    print(f"[✓] Saved: {OUT_LIVE_HTTP}")
    print(f"[✓] Saved: {OUT_MAP_JSON}")
    print(f"[i] Target: {domain}")
    print(f"[i] Subdomains: {len(subdomains)} | Interesting: {len(interesting)} | Live HTTP: {len(live)}")


if __name__ == "__main__":
    main()
