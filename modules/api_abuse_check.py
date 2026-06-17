#!/usr/bin/env python3
import json
import re
import ssl
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


BASE = Path(__file__).resolve().parents[1]
INFRA_DIR = BASE / "data" / "cache" / "infra"

LIVE_HTTP = INFRA_DIR / "live_http.txt"
INTERESTING = INFRA_DIR / "interesting.txt"

OUT_TXT = INFRA_DIR / "api_endpoints.txt"
OUT_JSON = INFRA_DIR / "api_report.json"

INFRA_DIR.mkdir(parents=True, exist_ok=True)

# What we probe (safe, common discovery endpoints)
PROBE_PATHS = [
    # API roots
    "/api", "/api/", "/v1", "/v1/", "/v2", "/v2/", "/graphql", "/graphql/", "/gql",
    # Docs / schema
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/", "/swagger/index.html",
    "/api-docs", "/api-docs/", "/openapi", "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml", "/redoc", "/redoc/", "/docs", "/docs/",
    # Management / debug / health
    "/health", "/status", "/metrics", "/prometheus", "/actuator", "/actuator/",
    "/actuator/health", "/actuator/info", "/actuator/metrics",
    "/debug", "/debug/", "/admin", "/admin/", "/console", "/console/",
    "/manage", "/manage/", "/internal", "/internal/",
    # Cloud / k8s-ish (often blocked, but worth a safe GET)
    "/.well-known/openid-configuration",
]

SENSITIVE_HINTS = [
    "swagger", "openapi", "redoc", "graphql",
    "metrics", "prometheus", "actuator",
    "admin", "manage", "internal", "debug",
]

UA = "CyberKimura/1.0 (safe-recon; api_abuse_check)"


def read_lines(p: Path) -> list[str]:
    if not p.exists():
        return []
    return [x.strip() for x in p.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]


def normalize_base_urls(lines: list[str]) -> list[str]:
    out = []
    for s in lines:
        s = s.strip()
        if not s:
            continue
        # if it's a plain host, assume https
        if not s.startswith("http://") and not s.startswith("https://"):
            s = "https://" + s
        # remove trailing slash
        s = s.rstrip("/")
        out.append(s)
    # dedupe keep order
    seen = set()
    res = []
    for u in out:
        if u not in seen:
            seen.add(u)
            res.append(u)
    return res


def fetch(url: str, timeout: int = 8) -> dict:
    """
    Safe GET request: returns status, content-type, title (if html), and a short fingerprint.
    """
    # --- FIX: skip IPv6 bracket URLs like http://[2606:...]/... (urllib может падать) ---
    if "[" in url and "]" in url:
        return {"ok": False, "error": "skip_ipv6_bracket_url", "url": url} 

    ctx = ssl.create_default_context()
    req = Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout, context=ctx) as r:
            status = getattr(r, "status", 200)
            headers = dict(r.headers.items())
            ctype = headers.get("Content-Type", "")
            raw = r.read(20000)  # read only first 20KB (safe)
            text = raw.decode(errors="ignore")

            title = ""
            if "text/html" in ctype.lower():
                m = re.search(r"<title>\s*(.*?)\s*</title>", text, re.IGNORECASE | re.DOTALL)
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:140]

            fingerprint = (text[:200] or "").replace("\n", " ").replace("\r", " ")
            fingerprint = re.sub(r"\s+", " ", fingerprint).strip()[:200]

            return {
                "ok": True,
                "status": status,
                "content_type": ctype[:120],
                "title": title,
                "bytes_read": len(raw),
                "fingerprint": fingerprint,
            }
    except HTTPError as e:
        return {"ok": True, "status": e.code, "content_type": "", "title": "", "bytes_read": 0, "fingerprint": ""}
    except URLError as e:
        return {"ok": False, "error": str(e)[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def is_interesting_path(path: str) -> bool:
    p = path.lower()
    return any(k in p for k in SENSITIVE_HINTS)


def main():
    # Prefer live_http URLs; fallback to interesting hosts (https)
    bases = normalize_base_urls(read_lines(LIVE_HTTP))
    if not bases:
        bases = normalize_base_urls(read_lines(INTERESTING))

    if not bases:
        print("[!] No inputs found. Run infra_discovery first (live_http.txt or interesting.txt).")
        raise SystemExit(1)

    findings = []
    total_requests = 0

    print(f"[+] API/Management check on {len(bases)} base targets")
    print(f"[i] Probing {len(PROBE_PATHS)} paths each (safe GET, limited read)")

    for base in bases:
        for path in PROBE_PATHS:
            url = base + path
            total_requests += 1
            r = fetch(url)

            if not r.get("ok"):
                continue

            status = r.get("status", 0)

            # Keep only meaningful hits
            if status in (200, 204, 301, 302, 307, 308, 401, 403):
                item = {
                    "base": base,
                    "url": url,
                    "path": path,
                    "status": status,
                    "content_type": r.get("content_type", ""),
                    "title": r.get("title", ""),
                    "bytes_read": r.get("bytes_read", 0),
                    "hint": "interesting" if is_interesting_path(path) else "",
                }
                findings.append(item)
                tag = "★" if item["hint"] else "-"
                print(f"[{tag}] {status} {url}")

    # Write outputs
    OUT_TXT.write_text(
        "\n".join([f"{f['status']} {f['url']}" + (f"  ({f['title']})" if f.get("title") else "") for f in findings]) +
        ("\n" if findings else ""),
        encoding="utf-8"
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets_checked": len(bases),
        "requests_total": total_requests,
        "findings_total": len(findings),
        "findings_interesting": sum(1 for f in findings if f.get("hint") == "interesting"),
        "files": {
            "api_endpoints": str(OUT_TXT),
            "api_report": str(OUT_JSON),
        },
        "top_findings": findings[:50],
    }
    OUT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[✓] Saved: {OUT_TXT}")
    print(f"[✓] Saved: {OUT_JSON}")
    print(f"[i] Findings: {len(findings)} (★ interesting: {report['findings_interesting']})")


if __name__ == "__main__":
    main()
