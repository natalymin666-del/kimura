import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qsl

import requests
from telegram import Update
from telegram.ext import ContextTypes

# Берём вспомогательные функции из urls-модуля
from modules.urls import (
    normalize_domain,
    fetch_wayback_urls,
    fetch_sitemap_urls,
    fetch_mainpage_urls,
    spider_domain,
    extract_js_endpoints,
    clean_urls,
    is_static_asset,
)

TIMEOUT = 10

# Сколько URL активно "пробивать"
MAX_PROBED_URLS = 60

# Эвристики для "вкусных" URL
SENSITIVE_KEYWORDS = [
    "admin", "login", "signin", "sign-in", "auth",
    "debug", "test", "dev", "staging",
    "backup", "bak", "dump",
    "old", "beta",
    "phpinfo", "config", ".git", ".svn",
]

SENSITIVE_EXT = [
    ".zip", ".rar", ".7z", ".tar", ".tar.gz",
    ".sql", ".bak", ".old", ".log",
]

COMMON_PATHS = [
    "admin",
    "admin/login",
    "administrator",
    "login",
    "auth",
    "debug",
    "test",
    "dev",
    "staging",
    "backup",
    "backup.zip",
    "db.sql",
    "phpinfo.php",
    ".git/config",
    ".env",
]

WAF_SIGNATURES = [
    "cloudflare",
    "akamai",
    "akamai ghost",
    "akamaighost",
    "imperva",
    "incapsula",
    "sucuri",
    "f5 big-ip",
    "barracuda",
    "mod_security",
    "modsecurity",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url",
    "next", "url", "dest", "destination",
    "return", "continue",
]


def looks_interesting(path: str) -> bool:
    path_low = path.lower()

    for kw in SENSITIVE_KEYWORDS:
        if kw in path_low:
            return True

    for ext in SENSITIVE_EXT:
        if path_low.endswith(ext):
            return True

    return False


def build_candidate_urls(domain: str) -> list[str]:
    """
    Делает deep-recon (как /deepurls), а потом выбирает
    самые 'интересные' URL + добавляет немного словаря.
    """
    all_urls: list[str] = []

    # 1) Wayback + sitemap + главная
    wb = fetch_wayback_urls(domain)
    if wb:
        all_urls.extend(wb)

    sm = fetch_sitemap_urls(domain)
    if sm:
        all_urls.extend(sm)

    mp = fetch_mainpage_urls(domain)
    if mp:
        all_urls.extend(mp)

    # 2) Спайдер
    spider_raw = spider_domain(domain) or []
    if spider_raw:
        all_urls.extend(spider_raw)

    # 3) JS-эндпоинты
    html_like = []
    for u in spider_raw[:15]:
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https"):
            continue
        if not parsed.netloc.endswith(domain):
            continue
        if is_static_asset(parsed.path or "/"):
            continue
        html_like.append(u)

    js_eps = extract_js_endpoints(domain, html_like)
    if js_eps:
        all_urls.extend(js_eps)

    # чистим и нормализуем
    cleaned = clean_urls(all_urls, domain)

    # отбираем вкусное по ключевым словам/расширениям
    interesting = []
    for u in cleaned:
        parsed = urlparse(u)
        path = parsed.path or "/"
        if looks_interesting(path):
            interesting.append(u)

    # если мало "вкусного" — добавляем немного обычных URL
    if len(interesting) < 30:
        for u in cleaned:
            if u in interesting:
                continue
            interesting.append(u)
            if len(interesting) >= 40:
                break

    # добавляем словарь общих путей
    for p in COMMON_PATHS:
        interesting.append(f"https://{domain}/{p}")
        interesting.append(f"http://{domain}/{p}")

    # убираем дубли
    uniq = []
    seen = set()
    for u in interesting:
        if u not in seen:
            uniq.append(u)
            seen.add(u)

    return uniq[:MAX_PROBED_URLS]


def detect_waf(headers: dict) -> str | None:
    """
    Простое определение WAF по заголовкам/Server.
    """
    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()
    via = headers.get("via", "").lower()

    joined = " ".join([server, powered, via])

    for sig in WAF_SIGNATURES:
        if sig in joined:
            return sig

    for k in headers:
        if "cloudflare" in k.lower():
            return "cloudflare"
        if "akamai" in k.lower():
            return "akamai"

    return None


def analyze_cors(headers: dict, origin: str | None = None) -> list[str]:
    issues: list[str] = []

    aco = headers.get("access-control-allow-origin")
    acc = headers.get("access-control-allow-credentials")
    acao = aco.strip() if aco else None
    accv = acc.strip().lower() if acc else None

    if not acao:
        return issues

    if acao == "*" and accv == "true":
        issues.append("🔴 CORS: ACAO='*' вместе с Credentials=True (опасная конфигурация)")
    elif acao == "*":
        issues.append("🟡 CORS: ACAO='*' (любой Origin, потенциальный риск)")

    if origin and acao == origin:
        issues.append("🟡 CORS: Origin отражается в ACAO (проверь на CORS-bypass)")

    return issues


def analyze_cookies(headers: dict) -> list[str]:
    issues: list[str] = []
    cookies = headers.get("set-cookie")
    if not cookies:
        return issues

    if isinstance(cookies, list):
        raw_list = cookies
    else:
        raw_list = [cookies]

    for raw in raw_list:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name_val = parts[0]
        flags = [p.lower() for p in parts[1:]]

        has_secure = any(f.startswith("secure") for f in flags)
        has_httponly = any(f.startswith("httponly") for f in flags)
        has_samesite = any("samesite" in f for f in flags)

        cookie_name = name_val.split("=")[0]

        if not has_secure:
            issues.append(f"⚠ Cookie '{cookie_name}' без флага Secure")
        if not has_httponly:
            issues.append(f"⚠ Cookie '{cookie_name}' без флага HttpOnly")
        if not has_samesite:
            issues.append(f"⚠ Cookie '{cookie_name}' без флага SameSite")

    return issues


def analyze_cache(headers: dict) -> list[str]:
    issues: list[str] = []

    cache_control = headers.get("cache-control", "")
    pragma = headers.get("pragma", "")

    cc_low = cache_control.lower()
    pr_low = pragma.lower()

    if not cache_control and not pragma:
        issues.append("🟡 Нет Cache-Control/Pragma (проверь кэширование чувствительных страниц)")
        return issues

    if "no-store" not in cc_low and "private" not in cc_low:
        issues.append("🟡 Cache-Control без 'no-store'/'private' (проверь, не кэшируются ли данные пользователя)")

    return issues


def analyze_methods(url: str) -> list[str]:
    """
    OPTIONS-запрос + разбор Allow.
    """
    issues: list[str] = []
    try:
        resp = requests.options(url, timeout=TIMEOUT)
    except Exception:
        return issues

    allow = resp.headers.get("Allow") or resp.headers.get("allow")
    if not allow:
        return issues

    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    if not methods:
        return issues

    if "TRACE" in methods:
        issues.append("🟡 HTTP метод TRACE разрешён (потенциальный риск для XST/старых атак)")
    if "PUT" in methods:
        issues.append("🟡 HTTP метод PUT разрешён (проверь возможность загрузки/overwrite)")
    if "DELETE" in methods:
        issues.append("🟡 HTTP метод DELETE разрешён (проверь, можно ли что-то удалить)")

    issues.append(f"ℹ Разрешённые методы: {', '.join(methods)}")
    return issues


def analyze_redirect(resp, base_domain: str) -> list[str]:
    """
    Если есть редирект на внешний домен + подозрительные параметры — помечаем как
    возможный open redirect.
    """
    issues: list[str] = []

    if not (300 <= resp.status_code < 400):
        return issues

    location = resp.headers.get("Location") or resp.headers.get("location")
    if not location:
        return issues

    final = urljoin(resp.url, location)
    parsed = urlparse(final)
    if not parsed.netloc:
        return issues

    dest_domain = normalize_domain(parsed.netloc)
    if not dest_domain.endswith(base_domain):
        q = parsed.query.lower()
        if any(p + "=" in q for p in REDIRECT_PARAMS):
            issues.append(
                f"🟡 Возможный open redirect: редирект на внешний домен {dest_domain}"
            )

    return issues


def check_reflection(url: str) -> list[str]:
    """
    Эвристика: проверяем, отражается ли наш параметр в ответе.
    Может указать на потенциальную reflected XSS (нужно ручное подтверждение).
    """
    issues: list[str] = []

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return issues

    marker = "KimuraXssTest123"
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    qs.append(("kimura_test", marker))
    new_qs = urlencode(qs, doseq=True)
    test_url = parsed._replace(query=new_qs).geturl()

    try:
        resp = requests.get(test_url, timeout=TIMEOUT)
    except Exception:
        return issues

    try:
        body = resp.text
    except Exception:
        return issues

    if marker in body:
        issues.append(
            "🟡 Параметры отражаются в ответе (возможна reflected XSS, проверь вручную)"
        )

    return issues


def detect_tech_stack(headers: dict, body: str | None) -> list[str]:
    """
    Пытаемся угадать backend, CMS и JS-фреймворки по заголовкам и HTML/JS.
    Возвращаем список строк с эмодзи ℹ (инфо-уровень).
    """
    notes: list[str] = []

    server = headers.get("server", "").lower()
    xpowered = headers.get("x-powered-by", "").lower()

    # -------- Backend / Web-server --------
    backend_parts = []

    if "php" in xpowered or "php" in server:
        backend_parts.append("PHP")
    if "asp.net" in xpowered or "microsoft-iis" in server:
        backend_parts.append("ASP.NET/IIS")
    if "express" in xpowered or "node" in xpowered or "express" in server:
        backend_parts.append("Node.js/Express")
    if "nginx" in server:
        backend_parts.append("nginx")
    if "apache" in server:
        backend_parts.append("Apache")
    if "tomcat" in server:
        backend_parts.append("Apache Tomcat")
    if "gunicorn" in server:
        backend_parts.append("Gunicorn (Python)")
    if "uwsgi" in server:
        backend_parts.append("uWSGI (Python)")

    if backend_parts:
        uniq_back = sorted(set(backend_parts))
        notes.append("ℹ Backend: " + ", ".join(uniq_back))

    # Если контента нет — дальше не анализируем
    if not body:
        return notes

    body_low = body.lower()

    # -------- CMS detection --------
    cms = None
    if "wp-content" in body_low or "wp-includes" in body_low or "wordpress" in body_low:
        cms = "WordPress"
    elif "drupal.settings" in body_low or "drupal-settings-json" in body_low:
        cms = "Drupal"
    elif 'content="joomla!' in body_low:
        cms = "Joomla"
    elif "shopify" in body_low and "cdn.shopify.com" in body_low:
        cms = "Shopify"
    elif "magento" in body_low:
        cms = "Magento"

    if cms:
        notes.append(f"ℹ CMS: {cms}")

    # -------- JS frameworks / SPA --------
    js_stack = []

    # React / Next.js
    if "react-dom" in body_low or "data-reactroot" in body_low:
        js_stack.append("React")
    if "__next" in body_low or "__next_data__" in body_low:
        js_stack.append("Next.js")

    # Angular
    if "ng-version" in body_low or "angular.min.js" in body_low:
        js_stack.append("Angular")

    # Vue
    if "vue.runtime" in body_low or "vue.js" in body_low or "vuex" in body_low:
        js_stack.append("Vue.js")

    # Svelte
    if "svelte" in body_low and "data-svelte" in body_low:
        js_stack.append("Svelte")

    if js_stack:
        uniq_js = sorted(set(js_stack))
        notes.append("ℹ JS-фреймворки: " + ", ".join(uniq_js))

    return notes


def issue_severity(issue: str) -> str:
    """
    Определяем уровень важности по эмодзи/тексту.
    Возвращает: critical / high / medium / low / info
    """
    # 🔴 — реально подтверждённые жёсткие проблемы
    if issue.startswith("🔴"):
        return "critical"
    # ❌ — ошибки подключения/таймауты: важно, но не критично
    if issue.startswith("❌"):
        return "high"
    # 🔥 — очень подозрительные пути (admin/backup/phpinfo/env/etc)
    if issue.startswith("🔥"):
        return "high"
    # 🟡 / ⚠ — средний уровень (CORS, методы, заголовки и т.п.)
    if issue.startswith("🟡") or issue.startswith("⚠"):
        return "medium"
    # 🟢 — низкий приоритет
    if issue.startswith("🟢"):
        return "low"
    # ℹ и всё остальное — просто информация
    return "info"


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def aggregate_severity(issues: list[str]) -> str:
    """
    Берём максимальный уровень важности из списка issues.
    """
    max_level = -1
    max_sev = "info"
    for i in issues:
        sev = issue_severity(i)
        if SEVERITY_ORDER[sev] > max_level:
            max_level = SEVERITY_ORDER[sev]
            max_sev = sev
    return max_sev


def probe_url(url: str, domain: str) -> dict:
    """
    HEAD/GET + OPTIONS + базовый анализ заголовков, CORS, cookies, cache,
    методов, WAF, open redirect, отражения параметров и стека технологий.
    """
    info = {
        "url": url,
        "final_url": url,
        "status": None,
        "reason": "",
        "headers": {},
        "issues": [],
        "severity": "info",
    }

    headers_lower: dict[str, str] = {}
    body_text: str | None = None

    try:
        # сначала HEAD, если не получилось — GET
        try:
            resp = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
            if resp.status_code >= 400 or len(resp.headers) == 0:
                raise Exception("fallback to GET")
        except Exception:
            resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)

        info["final_url"] = resp.url
        info["status"] = resp.status_code
        info["reason"] = resp.reason

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        info["headers"] = headers_lower

        # если это HTML/JS/JSON — пытаемся взять тело ответа
        ctype = headers_lower.get("content-type", "").lower()
        if any(t in ctype for t in ["text/html", "javascript", "json"]):
            try:
                body_text = resp.text
            except Exception:
                body_text = None
    except Exception as e:
        issue = f"❌ не удалось подключиться: {e}"
        info["issues"].append(issue)
        info["severity"] = aggregate_severity(info["issues"])
        return info

    code = info["status"] or 0
    url_low = info["final_url"].lower()
    parsed = urlparse(info["final_url"])
    path = parsed.path or "/"
    base_domain = normalize_domain(domain)

    # статусы
    if 500 <= code < 600:
        info["issues"].append("🔴 5xx server error")
    elif code == 403:
        info["issues"].append("🟡 403 Forbidden (может быть интересная цель)")
    elif code == 401:
        info["issues"].append("🟡 401 Unauthorized (защищённый ресурс, может быть интересным)")
    elif code == 200:
        info["issues"].append("🟢 200 OK")
    elif 300 <= code < 400:
        info["issues"].append(f"ℹ Redirect ({code})")

    # security headers
    if "strict-transport-security" not in headers_lower and info["final_url"].startswith("https://"):
        info["issues"].append("⚠ нет HSTS (Strict-Transport-Security)")

    if "x-frame-options" not in headers_lower:
        info["issues"].append("⚠ нет X-Frame-Options")

    if "x-content-type-options" not in headers_lower:
        info["issues"].append("⚠ нет X-Content-Type-Options")

    if "content-security-policy" not in headers_lower:
        info["issues"].append("⚠ нет Content-Security-Policy")

    # WAF
    waf = detect_waf(headers_lower)
    if waf:
        info["issues"].append(f"ℹ WAF: {waf}")

    # Cookies / Cache / CORS / методы
    info["issues"].extend(analyze_cookies(headers_lower))
    info["issues"].extend(analyze_cache(headers_lower))
    info["issues"].extend(analyze_cors(headers_lower))
    info["issues"].extend(analyze_methods(info["final_url"]))

    # подозрительный путь
    if looks_interesting(path):
        info["issues"].append("🔥 подозрительный путь/файл (admin/backup/test/dev/etc)")

    # подозрительные параметры в URL
    if any(p in url_low for p in ["debug=", "test=", "admin=", "password="]):
        info["issues"].append("🔥 подозрительные параметры в URL")

    # возможный open redirect
    try:
        r_no_redirect = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        info["issues"].extend(analyze_redirect(r_no_redirect, base_domain))
    except Exception:
        pass

    # эвристика на отражение параметров (reflected XSS candidate)
    info["issues"].extend(check_reflection(info["final_url"]))

    # определяем стек технологий (backend/CMS/JS)
    tech_notes = detect_tech_stack(headers_lower, body_text)
    info["issues"].extend(tech_notes)

    # финальный уровень
    info["severity"] = aggregate_severity(info["issues"])

    return info


async def deepattack_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /deepattack домен — делает deep-recon и "умный" прозвон интересных URL.
    Это НЕ эксплуатация, а подготовка отчёта для легального пентеста / bug bounty.
    """
    if not context.args:
        await update.message.reply_text(
            "Укажи домен.\n\nПример:\n"
            "/deepattack tesla.com"
        )
        return

    domain = normalize_domain(context.args[0])

    await update.message.reply_text(
        f"💣 DeepAttack для: {domain}\n"
        "Собираю интересные URL и проверяю статусы, заголовки, CORS, cookies, методы, редиректы…\n"
        "Используй только на целях, где у тебя есть разрешение!"
    )

    candidates = build_candidate_urls(domain)
    if not candidates:
        await update.message.reply_text(
            "Не удалось собрать достаточно URL для анализа. "
            "Попробуй сначала /deepurls и /urls."
        )
        return

    results = []
    for u in candidates:
        info = probe_url(u, domain)
        results.append(info)

    # сортируем по важности
    def sort_key(item):
        return SEVERITY_ORDER.get(item["severity"], 0)

    results_sorted = sorted(results, key=sort_key, reverse=True)

    # считаем количество по уровням
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for r in results:
        counts[r["severity"]] += 1

    lines = []
    lines.append(f"🔥 DeepAttack отчёт для: {domain}")
    lines.append(f"Проверено URL: {len(results)}")
    lines.append(
        "Сводка по уровням:\n"
        f"  Critical: {counts['critical']}\n"
        f"  High:     {counts['high']}\n"
        f"  Medium:   {counts['medium']}\n"
        f"  Low:      {counts['low']}\n"
        f"  Info:     {counts['info']}\n"
    )
    lines.append("Ниже показаны только самые интересные находки (по убыванию важности):\n")

    interesting_count = 0
    for r in results_sorted:
        issues = [i for i in r["issues"] if not i.startswith("🟢 200 OK")]
        if not issues:
            continue

        interesting_count += 1
        status_part = f"[{r['status']}]" if r["status"] is not None else "[??]"
        sev = r["severity"].upper()
        lines.append(f"{interesting_count}. ({sev}) {status_part} {r['final_url']}")
        for issue in issues:
            lines.append(f"   • {issue}")
        lines.append("")

        if interesting_count >= 30:
            break

    if interesting_count == 0:
        lines.append("Я не увидел явных интересных проблем по эвристикам.\n"
                     "Но это только автоматический чек — руками всё равно надо смотреть.")

    lines.append("")
    lines.append(
        "Напоминание: используй результаты только в рамках легального пентеста/bug bounty.\n"
        "Дальше можно вручную проверить эти URL в Burp, ffuf, kxss, nuclei и своими скриптами."
    )

    text = "\n".join(lines)

    chunk_size = 3500
    for i in range(0, len(text), chunk_size):
        await update.message.reply_text(
            text[i:i + chunk_size],
            disable_web_page_preview=True,
        )
