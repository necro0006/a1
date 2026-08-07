import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import cloudscraper

DOMAIN_TXT_PATH = "domain.txt"
BLACKLIST_PATH = "domain_blacklist.txt"

EXCLUDED_KEYS = {
    "rectv", "inatbox", "tmdb", "vidsrc", "ultimate", "imdb",
}

EXCLUDED_URL_MARKERS = [
    "themoviedb.org", "tmdb", "imdb.com", "github.com",
    "raw.githubusercontent.com", "localhost", "127.0.0.1", "google.com",
]

SUSPICIOUS_CONTENT_MARKERS = [
    "domain expired", "domain suspended", "under construction",
    "site blocked", "this domain may be for sale", "buy this domain",
    "hugedomains", "watch it legally", "alliance for creativity",
    "copyright infringement", "parked", "domain has been seized",
    "sedo", "afternic",
]

SUSPICIOUS_PATH_MARKERS = [
    "/login", "/giris", "/engel", "/blocked", "/parking",
    "/account", "/watch-it-legally", "/cdn-cgi/access/login",
]


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


def should_skip(key: str, url: str) -> tuple[bool, str]:
    lower_key = (key or "").lower()
    lower_url = (url or "").lower()

    if not url:
        return True, "empty url"
    if lower_key in EXCLUDED_KEYS:
        return True, "excluded provider"
    if "tmdb" in lower_key:
        return True, "static provider"
    for marker in EXCLUDED_URL_MARKERS:
        if marker in lower_url:
            return True, f"excluded url: {marker}"
    return False, ""


def load_blacklist() -> set[str]:
    blacklist = set()
    if not os.path.exists(BLACKLIST_PATH):
        return blacklist
    try:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domain = line.replace("https://", "").replace("http://", "").replace("www.", "").strip("/")
                    blacklist.add(domain)
    except Exception:
        pass
    return blacklist


def is_blacklisted(url: str, blacklist: set[str]) -> bool:
    if not blacklist:
        return False
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        return domain in blacklist
    except Exception:
        return False


def is_suspicious(text: str, final_url: str) -> str | None:
    parsed = urlparse(final_url)
    lower_path = (parsed.path or "").lower()
    for marker in SUSPICIOUS_PATH_MARKERS:
        if marker in lower_path:
            return f"suspicious path: {parsed.path}"

    lower_text = (text or "").lower()
    for marker in SUSPICIOUS_CONTENT_MARKERS:
        if marker in lower_text:
            return f"suspicious content: {marker}"
    return None


def check_domain(scraper, url: str, blacklist: set[str]) -> tuple[str | None, str]:
    """Returns (new_url_or_None, reason).
    None means keep the current address unchanged."""
    try:
        resp = scraper.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
        )
    except Exception as e:
        return None, f"connection error: {e}"

    if resp.status_code >= 400:
        return None, f"http {resp.status_code}"

    final_url = resp.url.rstrip("/")
    parsed = urlparse(final_url)
    clean_url = f"{parsed.scheme}://{parsed.netloc}"

    if is_blacklisted(final_url, blacklist):
        return None, f"redirect landed on blacklisted domain: {clean_url}"

    suspicious = is_suspicious(resp.text, final_url)
    if suspicious:
        return None, suspicious

    return clean_url, "ok"


def main() -> None:
    print("--- StreamHub GitHub Domain Updater (cloudscraper) ---", flush=True)

    if not os.path.exists(DOMAIN_TXT_PATH):
        print(f"Error: {DOMAIN_TXT_PATH} not found.")
        sys.exit(1)

    # Load domains
    domains: dict[str, str] = {}
    with open(DOMAIN_TXT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and ":" in line:
                k, v = line.split(":", 1)
                domains[k.strip()] = v.strip()

    if not domains:
        print("No domains found.")
        return

    blacklist = load_blacklist()
    if blacklist:
        print(f"Blacklist loaded: {len(blacklist)} entries", flush=True)

    scraper = cloudscraper.create_scraper()

    updated_count = 0
    checked_count = 0
    skipped_count = 0
    kept_count = 0

    for key, current_url in domains.items():
        skip, reason = should_skip(key, current_url)
        if skip:
            print(f"  [{key}] ⏭ skipped: {reason}", flush=True)
            skipped_count += 1
            continue

        print(f"  [{key}] Checking {current_url} ... ", end="", flush=True)
        checked_count += 1

        new_url, reason = check_domain(scraper, current_url, blacklist)

        if new_url is None:
            # Could not reach or suspicious -> keep current address
            print(f"⚠ kept (reason: {reason})", flush=True)
            kept_count += 1
            continue

        current_normalized = normalize_domain(current_url)
        new_normalized = normalize_domain(new_url)

        if current_normalized == new_normalized:
            print(f"✓ unchanged", flush=True)
        else:
            print(f"✓ UPDATED {current_normalized} → {new_normalized}", flush=True)
            domains[key] = new_normalized
            updated_count += 1

    # Write back
    with open(DOMAIN_TXT_PATH, "w", encoding="utf-8") as f:
        for key in sorted(domains.keys()):
            f.write(f"{key}:{domains[key]}\n")

    print(f"\n--- Summary ---", flush=True)
    print(f"  Total: {len(domains)}", flush=True)
    print(f"  Checked: {checked_count}", flush=True)
    print(f"  Skipped: {skipped_count}", flush=True)
    print(f"  Kept (unreachable): {kept_count}", flush=True)
    print(f"  Updated: {updated_count}", flush=True)


if __name__ == "__main__":
    main()
