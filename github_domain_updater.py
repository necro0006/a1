import asyncio
import json
import os
import re
import sys
import warnings
from dataclasses import dataclass
from urllib.parse import urlparse
from typing import Callable

import nodriver as uc

warnings.filterwarnings("ignore", category=ResourceWarning)

DOMAIN_TXT_PATH = "domain.txt"
REPORT_PATH = "address_updater_report.json"

EXCLUDED_KEYS = {
    "rectv",
    "inatbox",
    "tmdb",
    "vidsrc",
    "ultimate",
    "imdb",
}

EXCLUDED_URL_MARKERS = [
    "themoviedb.org",
    "tmdb",
    "imdb.com",
    "github.com",
    "raw.githubusercontent.com",
    "localhost",
    "127.0.0.1",
    "google.com",
]

SUSPICIOUS_PATH_MARKERS = [
    "/login",
    "/giris",
    "/engel",
    "/blocked",
    "/parking",
    "/account",
    "/watch-it-legally",
    "/cdn-cgi/access/login",
]

SUSPICIOUS_CONTENT_MARKERS = [
    "domain expired",
    "domain suspended",
    "under construction",
    "site blocked",
    "this domain may be for sale",
    "buy this domain",
    "hugedomains",
    "watch it legally",
    "alliance for creativity",
    "copyright infringement",
    "parked",
    "domain has been seized",
    "sedo",
    "afternic",
]

TRANSIENT_ERROR_MARKERS = [
    "timeout",
    "awaiting headers",
    "request canceled",
    "temporary error",
    "connection reset",
]


@dataclass
class PageResult:
    requested_url: str
    final_url: str
    final_origin: str
    body: str


@dataclass
class CheckResult:
    key: str
    current: str
    status: str
    checker: str
    resolved: str = ""
    reason: str = ""


def normalize_domain(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""

    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"

    parsed = urlparse(raw)
    if not parsed.netloc:
        return raw.rstrip("/")

    scheme = parsed.scheme or "https"
    host = parsed.netloc.lower()
    return f"{scheme}://{host}"


def normalize_provider_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""

    lower = raw.lower()
    if (
        "raw.githubusercontent.com" in lower
        or "api.themoviedb.org/3" in lower
        or lower.endswith(".m3u")
        or lower.endswith(".m3u8")
    ):
        if not raw.startswith(("http://", "https://")):
            raw = f"https://{raw}"
        return raw.rstrip("/")

    return normalize_domain(raw)


def should_auto_update(key: str, url: str) -> tuple[bool, str]:
    normalized = normalize_provider_url(url)
    lower_key = (key or "").lower()
    lower_url = normalized.lower()

    if not normalized:
        return False, "empty url"
    if lower_key in EXCLUDED_KEYS:
        return False, "excluded provider"
    if "tmdb" in lower_key:
        return False, "static provider"

    for marker in EXCLUDED_URL_MARKERS:
        if marker in lower_url:
            return False, f"excluded url: {marker}"

    return True, ""


def is_transient_error(message: str) -> bool:
    lower = (message or "").lower()
    return any(marker in lower for marker in TRANSIENT_ERROR_MARKERS)


def extract_numeric_family(url: str, pattern: str) -> tuple[str, int] | None:
    match = re.search(pattern, url, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(0), int(match.group(1))


def replace_first_number(url: str, old_number: int, new_number: int) -> str:
    return re.sub(str(old_number), str(new_number), url, count=1)


async def fetch_page(browser, target: str, wait_seconds: float = 5.5) -> PageResult:
    requested = normalize_domain(target)
    if not requested:
        raise ValueError("invalid target url")

    page = await browser.get(requested)
    await asyncio.sleep(wait_seconds)

    final_url = page.target.url.rstrip("/")
    body = ""
    try:
        body = await page.get_content()
    except Exception:
        body = ""

    return PageResult(
        requested_url=requested,
        final_url=final_url,
        final_origin=normalize_domain(final_url),
        body=body,
    )


def reject_suspicious_page(page: PageResult) -> str | None:
    if not page.final_origin:
        return "invalid final origin"

    parsed = urlparse(page.final_url)
    lower_path = (parsed.path or "").lower()
    for marker in SUSPICIOUS_PATH_MARKERS:
        if marker in lower_path:
            return f"suspicious path: {parsed.path}"

    body = (page.body or "").lower()
    for marker in SUSPICIOUS_CONTENT_MARKERS:
        if marker in body:
            return f"suspicious content: {marker}"

    return None


def has_any_marker(page: PageResult, markers: list[str], label: str) -> str | None:
    suspicious = reject_suspicious_page(page)
    if suspicious:
        return suspicious

    body = (page.body or "").lower()
    if any(marker in body for marker in markers):
        return None

    return f"{label} marker not found"


async def check_redirects(browser, current_url: str) -> str:
    page = await fetch_page(browser, current_url)
    suspicious = reject_suspicious_page(page)
    if suspicious:
        raise ValueError(suspicious)
    return page.final_origin


async def check_candidate_markers(
    browser,
    candidates: list[str],
    validator: Callable[[PageResult], str | None],
) -> str:
    last_error = "validation failed"
    for candidate in candidates:
        try:
            page = await fetch_page(browser, candidate)
        except Exception as exc:
            last_error = str(exc)
            continue

        validation_error = validator(page)
        if validation_error is None:
            return page.final_origin
        last_error = validation_error

    raise ValueError(last_error)


async def check_dizipal_numeric_family(
    browser,
    current_url: str,
    lookahead: int = 30,
) -> str:
    try:
        page = await fetch_page(browser, current_url)
        validation_error = validate_dizipal(page)
        if validation_error is None:
            return page.final_origin
    except Exception:
        pass

    family = extract_numeric_family(current_url, r"dizipal(\d+)")
    if family is None:
        raise ValueError("dizipal numeric host not found")

    _, current_number = family
    for offset in range(1, lookahead + 1):
        candidate = normalize_domain(replace_first_number(current_url, current_number, current_number + offset))
        try:
            page = await fetch_page(browser, candidate, wait_seconds=4.5)
        except Exception:
            continue
        if validate_dizipal(page) is None:
            return page.final_origin

    raise ValueError("no valid dizipal domain found")


async def check_dizipal(browser, current_url: str) -> str:
    return await check_dizipal_numeric_family(browser, current_url)


def validate_dizipal(page: PageResult) -> str | None:
    suspicious = reject_suspicious_page(page)
    if suspicious:
        return suspicious

    final_url = (page.final_url or "").lower()
    final_origin = (page.final_origin or "").lower()
    if "dizipal" not in final_url and "dizipal" not in final_origin:
        return "dizipal host not found"

    body = (page.body or "").lower()
    strong_markers = [
        "wp-content/themes/filmvedizi",
        'og:site_name" content="dizipal',
        "og:site_name' content='dizipal",
        '"name":"dizipal"',
        "film, dizi ve anime izle",
        "favicon_d.png",
    ]
    if any(marker in body for marker in strong_markers):
        return None

    wordpress_markers = [
        "/wp-json/",
        "/wp-content/uploads/",
        "yoast seo",
        "swiper-bundle",
        "flowbite.min.css",
    ]
    if sum(1 for marker in wordpress_markers if marker in body) >= 3:
        return None

    return "dizipal marker not found"


def validate_dizibox(page: PageResult) -> str | None:
    return has_any_marker(page, ["dizibox", "dwls_search", "tum-bolumler", "article-series-poster"], "dizibox")


def validate_diziwatch(page: PageResult) -> str | None:
    return has_any_marker(page, ["diziwatch", "ckey", "cvalue", "episodes?page=", "swiper-slide"], "diziwatch")


def validate_webteizle(page: PageResult) -> str | None:
    return has_any_marker(page, ["webteizle", "filmhead", "dataalternatif3.asp", "tavsiye-filmler"], "webteizle")


def validate_turkish123(page: PageResult) -> str | None:
    return has_any_marker(page, ["turkish123", "series-list", "episodes-list"], "turkish123")


def validate_hdnetflix(page: PageResult) -> str | None:
    return has_any_marker(page, ["hdnetflix", "poster-long-image", "movie-item", "search?q=", "fulhdfilmizle"], "hdnetflix")


def validate_roketdizi(page: PageResult) -> str | None:
    return has_any_marker(page, ["roketdizi", "x-requested-with", "ajax"], "roketdizi")


def validate_dizist(page: PageResult) -> str | None:
    return has_any_marker(page, ["dizist", "appckey", "yabanci-diziler", "asyadizileri"], "dizist")


def validate_filmekseni(page: PageResult) -> str | None:
    return has_any_marker(page, ["filmekseni", 'div class="poster"', "netflix yap"], "filmekseni")


def validate_setfilmizle(page: PageResult) -> str | None:
    return has_any_marker(page, ["setfilmizle", "yerli-filmler", "x-requested-with", "mini-dizi"], "setfilmizle")


def validate_yabancidizi(page: PageResult) -> str | None:
    return has_any_marker(page, ["yabancidizi", "/search?qr=", "/uploads/series/"], "yabancidizi")


def validate_dizikorea(page: PageResult) -> str | None:
    return has_any_marker(page, ["dizikorea", "yeni-bolumler", "trendler", "kore dizileri"], "dizikorea")


def validate_sezonlukdizi(page: PageResult) -> str | None:
    return has_any_marker(page, ["sezonlukdizi", "sezon", "bolum", "dizi"], "sezonlukdizi")


async def check_sezonlukdizi(browser, current_url: str) -> str:
    seed = "https://sezonlukdizi8.com"
    candidates = [current_url, seed]
    last_error = "validation failed"

    for candidate in candidates:
        try:
            page = await fetch_page(browser, candidate)
        except Exception as exc:
            last_error = str(exc)
            if normalize_domain(candidate) == seed and is_transient_error(last_error):
                return seed
            continue

        validation_error = validate_sezonlukdizi(page)
        if validation_error is None:
            return page.final_origin
        last_error = validation_error

    if normalize_domain(current_url) == seed:
        return seed
    raise ValueError(last_error)


async def check_dizibox(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://www.dizibox.live"], validate_dizibox)


async def check_diziwatch(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://diziwatch.ac", "https://diziwatch.to"], validate_diziwatch)


async def check_webteizle(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://webteizle3.xyz", "https://webteizle.info"], validate_webteizle)


async def check_turkish123(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://ahs.turkish123.com", "https://turkish123.ac"], validate_turkish123)


async def check_hdnetflix(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://fulhdfilmizle.pro", "https://fulhdfilmizle.net"], validate_hdnetflix)


async def check_roketdizi(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://roketdizi.to"], validate_roketdizi)


async def check_dizist(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://dizist.live"], validate_dizist)


async def check_filmekseni(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://filmekseni.cc"], validate_filmekseni)


async def check_setfilmizle(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://www.setfilmizle.uk"], validate_setfilmizle)


async def check_yabancidizi(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://yabancidizi.life"], validate_yabancidizi)


async def check_dizikorea(browser, current_url: str) -> str:
    return await check_candidate_markers(browser, [current_url, "https://dizikorea3.com"], validate_dizikorea)


CHECKERS: dict[str, Callable] = {
    "dizipal": check_dizipal,
    "dizipalorjinal": check_dizipal,
    "dizipalorjinal2": check_dizipal,
    "dizibox": check_dizibox,
    "diziwatch": check_diziwatch,
    "webteizle": check_webteizle,
    "turkish123": check_turkish123,
    "hdnetflix": check_hdnetflix,
    "roketdizi": check_roketdizi,
    "dizist": check_dizist,
    "filmekseni": check_filmekseni,
    "setfilmizle": check_setfilmizle,
    "yabancidizi": check_yabancidizi,
    "dizikorea": check_dizikorea,
    "sezonlukdizi": check_sezonlukdizi,
}


async def resolve_provider(browser, key: str, current_url: str) -> CheckResult:
    normalized_current = normalize_provider_url(current_url)
    should_check, reason = should_auto_update(key, normalized_current)
    if not should_check:
        return CheckResult(key=key, current=normalized_current, status="skipped", checker="", reason=reason)

    checker = CHECKERS.get(key)
    checker_name = key if checker else "redirect"

    try:
        if checker:
            resolved = await checker(browser, normalized_current)
        else:
            resolved = await check_redirects(browser, normalized_current)
    except Exception as exc:
        return CheckResult(
            key=key,
            current=normalized_current,
            status="rejected",
            checker=checker_name,
            reason=str(exc),
        )

    resolved = normalize_provider_url(resolved)
    if not resolved:
        return CheckResult(
            key=key,
            current=normalized_current,
            status="rejected",
            checker=checker_name,
            reason="empty resolved domain",
        )

    status = "updated" if resolved != normalized_current else "unchanged"
    return CheckResult(
        key=key,
        current=normalized_current,
        status=status,
        checker=checker_name,
        resolved=resolved,
    )


def write_report(results: list[CheckResult]) -> None:
    summary = {
        "total": len(results),
        "updated": sum(1 for result in results if result.status == "updated"),
        "unchanged": sum(1 for result in results if result.status == "unchanged"),
        "skipped": sum(1 for result in results if result.status == "skipped"),
        "rejected": sum(1 for result in results if result.status == "rejected"),
    }
    payload = {
        "summary": summary,
        "items": [
            {
                "key": result.key,
                "checker": result.checker,
                "status": result.status,
                "current": result.current,
                "resolved": result.resolved,
                "reason": result.reason,
            }
            for result in results
        ],
    }
    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


async def main() -> None:
    print("--- StreamHub GitHub Domain Updater ---")

    if not os.path.exists(DOMAIN_TXT_PATH):
        print(f"Error: {DOMAIN_TXT_PATH} not found.")
        sys.exit(1)

    domains = {}
    with open(DOMAIN_TXT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and ":" in line:
                k, v = line.split(":", 1)
                domains[k.strip()] = v.strip()

    if not domains:
        print("No domains found in domain.txt.")
        return

    browser = await uc.start(headless=True, no_sandbox=True)
    results: list[CheckResult] = []
    domains_updated = 0

    try:
        for key, url in domains.items():
            result = await resolve_provider(browser, key, url)
            results.append(result)
            write_report(results)

            message = result.reason or result.resolved or result.current
            print(f"[{key}] {result.status}: {message}")

            if result.status in ("updated", "unchanged"):
                resolved_val = result.resolved if result.resolved else result.current
                if resolved_val:
                    if domains[key] != resolved_val:
                        domains[key] = resolved_val
                        domains_updated += 1

    finally:
        browser.stop()

    write_report(results)

    if domains_updated > 0:
        with open(DOMAIN_TXT_PATH, "w", encoding="utf-8") as f:
            for key in sorted(domains.keys()):
                f.write(f"{key}:{domains[key]}\n")
        print(f"Successfully updated {domains_updated} domains in {DOMAIN_TXT_PATH}.")
    else:
        print("No changes needed for domain.txt.")


if __name__ == "__main__":
    asyncio.run(main())
