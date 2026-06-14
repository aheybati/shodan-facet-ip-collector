#!/usr/bin/env python3
"""
Shodan Facet IP Collector — aheybati Scanner v3.1
================================================
Extracts IP addresses from Shodan using facet pages (no API credits needed).
Uses smart sub-querying to bypass the 1000-result facet limit.

v3.1 — NEGATION STRATEGY:
  Instead of iterating every small city/org/net one by one, we now:
  1. Get facet values WITH counts
  2. Process large items (>999) with sub-queries
  3. Subtract processed counts from the parent total
  4. When remaining < 999, NEGATE already-processed items and grab
     ALL remaining IPs in a SINGLE request!

  Example: DE has 2,926 IPs
    Frankfurt:  1,500  → sub-query (big)
    Berlin:       800  → sub-query (medium)
    Remaining:    626  → ONE request: query -city:"Frankfurt" -city:"Berlin"
    Instead of 50+ requests for tiny cities, just 1!

v3.0 — GLOBAL PORT STRATEGY:
  Gets global port list first, then for each port:
  - Quick path: if < 1000 IPs, ONE request gets all
  - Full path: if >= 1000, countries → cities → IPs with negation

Requirements:
  pip install requests beautifulsoup4 python-dotenv
  FlareSolverr running on http://localhost:8191
"""

import requests as http_requests
from bs4 import BeautifulSoup
from urllib.parse import quote, unquote
import time
import os
import re
import json
import argparse
import logging
from datetime import datetime

# Optional: python-dotenv for .env file support
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env is optional

# ─── Configuration ───────────────────────────────────────────────────────────

FLARE_URL = "http://localhost:8191/v1"
DEFAULT_OUTPUT = "ips.txt"
DEFAULT_OUTPUT_PORTS = "ips_ports.txt"
PROGRESS_FILE = "progress.json"
DEFAULT_DELAY = 3
FACET_CAP = 1000  # Shodan facet pages return max ~1000 results

MAX_NEGATE_PER_REQUEST = 480  # Max ports to negate per Shodan request (URL length ~7000 chars)
SHODAN_LOGIN_URL = "https://account.shodan.io/login"

# ─── Logging Setup ───────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("abbas_scanner")


# ─── FlareSolverr ────────────────────────────────────────────────────────────

def flaresolverr_get(url: str, max_timeout: int = 120000, retries: int = 3) -> tuple:
    """Bypass Cloudflare using FlareSolverr with retry and progressive backoff."""
    for attempt in range(1, retries + 1):
        payload = {"cmd": "request.get", "url": url, "maxTimeout": max_timeout}
        try:
            http_timeout = (max_timeout / 1000) + 60
            resp = http_requests.post(FLARE_URL, json=payload, timeout=http_timeout)
            result = resp.json()
            if result.get("status") == "ok":
                sol = result["solution"]
                cookies = {c["name"]: c["value"] for c in sol.get("cookies", [])}
                user_agent = sol.get("userAgent", "")
                html = sol["response"]
                if "Just a moment" in html and attempt < retries:
                    log.warning("FlareSolverr returned challenge page, retrying (%d/%d)...", attempt, retries)
                    time.sleep(10 * attempt)
                    continue
                return html, cookies, user_agent
            else:
                err_msg = result.get("message", "unknown")
                log.warning("FlareSolverr error (attempt %d/%d): %s", attempt, retries, err_msg)
                if attempt < retries:
                    wait = 15 * attempt
                    log.info("Retrying in %d seconds...", wait)
                    time.sleep(wait)
                    continue
                return None, {}, ""
        except http_requests.exceptions.Timeout:
            log.error("FlareSolverr timeout (attempt %d/%d)", attempt, retries)
            if attempt < retries:
                wait = 15 * attempt
                log.info("Retrying in %d seconds...", wait)
                time.sleep(wait)
                continue
            return None, {}, ""
        except http_requests.exceptions.ConnectionError:
            log.error("FlareSolverr connection error (attempt %d/%d) — is it running?", attempt, retries)
            if attempt < retries:
                wait = 20 * attempt
                log.info("Retrying in %d seconds...", wait)
                time.sleep(wait)
                continue
            return None, {}, ""
        except Exception as e:
            log.error("FlareSolverr request error (attempt %d/%d): %s", attempt, retries, e)
            if attempt < retries:
                time.sleep(10 * attempt)
                continue
            return None, {}, ""
    return None, {}, ""


# ─── Shodan Login ────────────────────────────────────────────────────────────

def login_shodan(username: str, password: str) -> tuple:
    """Login to Shodan and return (cookies, user_agent)."""
    log.info("Logging in to Shodan as %s", username)

    html, cookies, user_agent = flaresolverr_get(SHODAN_LOGIN_URL)
    if not html:
        log.error("Failed to reach login page!")
        return None, {}

    soup = BeautifulSoup(html, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    csrf_token = csrf_input["value"] if csrf_input else None
    if csrf_token:
        log.info("CSRF token: %s...", csrf_token[:20])
    else:
        log.warning("No CSRF token found!")
    log.info("Cloudflare bypassed — got %d cookies", len(cookies))

    headers = {
        "User-Agent": user_agent,
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": SHODAN_LOGIN_URL,
        "Origin": "https://account.shodan.io",
    }
    post_data = {
        "username": username,
        "password": password,
        "grant_type": "password",
        "continue": "https://www.shodan.io",
    }
    if csrf_token:
        post_data["csrf_token"] = csrf_token

    try:
        resp = http_requests.post(
            SHODAN_LOGIN_URL, data=post_data,
            cookies=cookies, headers=headers,
            allow_redirects=True, timeout=30,
        )
    except Exception as e:
        log.error("Login POST error: %s", e)
        return None, {}

    all_cookies = dict(cookies)
    for name, value in resp.cookies.items():
        all_cookies[name] = value

    if "dashboard" in resp.url or ("shodan.io" in resp.url and "login" not in resp.url.lower()):
        log.info("Login successful! Redirected to: %s", resp.url)
        log.info("Session cookies: %d", len(all_cookies))
        return all_cookies, user_agent

    if "Invalid" in resp.text or "incorrect" in resp.text.lower():
        log.error("Invalid credentials!")
        return None, {}

    log.warning("Unexpected response. URL: %s", resp.url)
    return None, {}


# ─── HTTP Get with Cloudflare Fallback ────────────────────────────────────────

_login_state = {"username": "", "password": ""}


def shodan_get(url: str, cookies: dict, user_agent: str) -> tuple:
    """GET a Shodan page, with Cloudflare fallback and auto re-login on session expiry."""
    headers = {"User-Agent": user_agent, "Referer": "https://www.shodan.io/"}
    for attempt in range(1, 3):
        try:
            resp = http_requests.get(
                url, cookies=cookies, headers=headers,
                allow_redirects=True, timeout=30,
            )
            if resp.status_code == 403 or "Just a moment" in resp.text:
                log.info("Cloudflare challenge detected, using FlareSolverr...")
                html, new_cookies, user_agent = flaresolverr_get(url)
                if html:
                    cookies.update(new_cookies)
                    return html, cookies, user_agent
                return None, cookies, user_agent
            if resp.status_code == 302 and "login" in resp.headers.get("Location", "").lower():
                log.warning("Session expired (redirected to login). Attempt %d/2", attempt)
                if attempt == 1 and _login_state["username"]:
                    log.info("Auto re-login...")
                    new_cookies, user_agent = login_shodan(_login_state["username"], _login_state["password"])
                    if new_cookies:
                        cookies.clear()
                        cookies.update(new_cookies)
                        log.info("Re-login successful! Retrying request...")
                        continue
                    log.error("Auto re-login failed!")
                return None, cookies, user_agent
            if "csrf_token" in resp.text and "login" in resp.text.lower() and "password" in resp.text.lower():
                log.warning("Session expired (login page in response). Attempt %d/2", attempt)
                if attempt == 1 and _login_state["username"]:
                    log.info("Auto re-login...")
                    new_cookies, user_agent = login_shodan(_login_state["username"], _login_state["password"])
                    if new_cookies:
                        cookies.clear()
                        cookies.update(new_cookies)
                        log.info("Re-login successful! Retrying request...")
                        continue
                    log.error("Auto re-login failed!")
                return None, cookies, user_agent
            return resp.text, cookies, user_agent
        except Exception as e:
            log.error("GET error: %s", e)
            return None, cookies, user_agent
    return None, cookies, user_agent


# ─── URL Builder ─────────────────────────────────────────────────────────────

def build_facet_url(query: str, facet: str, extra_filters: dict = None) -> str:
    """Build a Shodan facet URL with optional extra filters."""
    encoded_query = quote(query, safe=' ":')
    if extra_filters:
        for key, value in extra_filters.items():
            encoded_query += quote(f' {key}:"{value}"', safe=' ":')
    return f"https://www.shodan.io/search/facet?query={encoded_query}&facet={facet}"


# ─── Facet Parsers ────────────────────────────────────────────────────────────

def parse_facet_links(html: str, pattern: str) -> list:
    """Extract (value, display_text) from facet page links matching a URL pattern."""
    soup = BeautifulSoup(html, "html.parser")
    results = []
    seen = set()
    all_links = soup.find_all("a", href=True)
    for link in all_links:
        href = link.get("href", "")
        decoded = unquote(href)
        match = re.search(pattern, href)
        if not match:
            match = re.search(pattern, decoded)
        if match:
            value = match.group(1)
            if value not in seen:
                seen.add(value)
                results.append((value, link.get_text(strip=True)))
    return results


def parse_count_from_text(text: str) -> int:
    """Extract a numeric count from Shodan facet display text.
    
    Shodan shows: 'Frankfurt am Main 2,926' or '11434 16,512' etc.
    Returns the number part, or 0 if not found.
    """
    # Match a number at the end of the text (possibly with commas)
    m = re.search(r'([\d,]+)\s*$', text)
    if m:
        try:
            return int(m.group(1).replace(",", ""))
        except ValueError:
            pass
    return 0


def parse_facet_with_counts(html: str, pattern: str) -> list:
    """Extract (value, count) from a Shodan facet page.
    
    Uses the facet-row HTML structure where counts are in <div class="value">.
    Falls back to link text parsing if structure not found.
    
    Returns list of (value, count) tuples where count is the integer count.
    """
    soup = BeautifulSoup(html, "html.parser")
    results = []
    seen = set()
    
    # Primary approach: parse from facet-row structure
    # Shodan uses: <div class="facet-row"><div class="name"><a href="...">value</a></div><div class="value">count</div></div>
    facet_rows = soup.find_all("div", class_="facet-row")
    for row in facet_rows:
        name_div = row.find("div", class_="name")
        value_div = row.find("div", class_="value")
        if not name_div or not value_div:
            continue
        
        a_tag = name_div.find("a", href=True)
        if not a_tag:
            continue
        
        href = a_tag.get("href", "")
        decoded = unquote(href)
        match = re.search(pattern, href)
        if not match:
            match = re.search(pattern, decoded)
        if not match:
            continue
        
        value = match.group(1)
        if value in seen:
            continue
        seen.add(value)
        
        # Get count from value div
        count_text = value_div.get_text(strip=True)
        try:
            count = int(count_text.replace(",", ""))
        except ValueError:
            count = 0
        
        results.append((value, count))
    
    # Fallback: if no structured results, try link text approach
    if not results:
        raw = parse_facet_links(html, pattern)
        for value, text in raw:
            count = parse_count_from_text(text)
            results.append((value, count))
    
    return results


def parse_ips(html: str) -> list:
    """Extract IP addresses from a facet page."""
    soup = BeautifulSoup(html, "html.parser")
    ips = set()

    all_links = soup.find_all("a", href=True)
    for link in all_links:
        href = link.get("href", "")
        text = link.get_text(strip=True)
        if "ip%3A%22" in href or ('ip:"' in unquote(href)):
            ip_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", text)
            if ip_match:
                ips.add(ip_match.group(1))

    all_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", html)
    for ip in all_ips:
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            ips.add(ip)

    return list(ips)


# ─── Facet Data Extraction ────────────────────────────────────────────────────

def get_countries(cookies: dict, user_agent: str, query: str) -> tuple:
    """Get list of (country_code, count) from Shodan facet."""
    log.info("Fetching country list...")
    url = build_facet_url(query, "country")
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        log.error("Failed to get country list!")
        return [], cookies, user_agent

    results = parse_facet_with_counts(html, r'country%3A%22([A-Z]{2})%22')
    if not results:
        results = parse_facet_with_counts(html, r'country[^A-Za-z]*"([A-Z]{2})"')

    log.info("Found %d countries", len(results))
    return results, cookies, user_agent


def get_cities_with_counts(cookies: dict, user_agent: str, query: str, country_code: str) -> tuple:
    """Get list of (city_name, count) for a country from Shodan facet."""
    url = build_facet_url(query, "city", extra_filters={"country": country_code})
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent

    results = parse_facet_with_counts(html, r'city%3A%22(.+?)%22')
    if not results:
        results = parse_facet_with_counts(html, r'city[^A-Za-z]*"(.+?)"')
    return results, cookies, user_agent


def get_orgs_with_counts(cookies: dict, user_agent: str, query: str, country_code: str, city_name: str) -> tuple:
    """Get list of (org_name, count) for a city from Shodan facet."""
    url = build_facet_url(query, "org", extra_filters={"country": country_code, "city": city_name})
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent

    results = parse_facet_with_counts(html, r'org%3A%22(.+?)%22')
    if not results:
        results = parse_facet_with_counts(html, r'org[^A-Za-z]*"(.+?)"')
    return results, cookies, user_agent


def get_nets_with_counts(cookies: dict, user_agent: str, query: str, country_code: str, city_name: str, org_name: str) -> tuple:
    """Get list of (net_name, count) for an org from Shodan facet."""
    url = build_facet_url(
        query, "net",
        extra_filters={"country": country_code, "city": city_name, "org": org_name},
    )
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent

    results = parse_facet_with_counts(html, r'net%3A%22(.+?)%22')
    if not results:
        results = parse_facet_with_counts(html, r'net[^A-Za-z]*"(.+?)"')
    return results, cookies, user_agent


def get_ips_from_facet(cookies: dict, user_agent: str, query: str, extra_filters: dict) -> tuple:
    """Get IPs from a Shodan IP facet page with given filters."""
    url = build_facet_url(query, "ip", extra_filters=extra_filters)
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent
    ips = parse_ips(html)
    return ips, cookies, user_agent


def get_global_ports(cookies: dict, user_agent: str, query: str) -> tuple:
    """Get the global port list for a query from Shodan facet.
    
    If the query contains port negations that would make the URL too long,
    we batch the negations into multiple requests and merge the results.
    
    Returns a list of (port_number, count) tuples sorted by count descending.
    """
    # Check if URL would be too long (>7000 chars)
    # If so, we need to batch the port negations
    estimated_url_len = len(build_facet_url(query, "port"))
    
    if estimated_url_len > 6500:
        # URL too long — need to batch negations
        log.info("Query too long for single request (%d chars), using batched negation", estimated_url_len)
        return _get_global_ports_batched(cookies, user_agent, query), cookies, user_agent
    
    url = build_facet_url(query, "port")
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent

    ports, cookies, user_agent = _parse_ports_from_html(html, cookies, user_agent)
    return ports, cookies, user_agent


def _parse_ports_from_html(html, cookies, user_agent):
    """Parse port list from Shodan facet HTML. Returns (ports_list, cookies, user_agent)."""
    ports = []
    seen = set()
    
    raw = parse_facet_with_counts(html, r'port%3A%22(\d+)%22')
    if not raw:
        raw = parse_facet_with_counts(html, r'port%3A(\d+)')
    if not raw:
        raw = parse_facet_with_counts(html, r'port[^A-Za-z]*"(\d+)"')

    for port_str, count in raw:
        try:
            port_num = int(port_str)
            if port_num not in seen and 1 <= port_num <= 65535:
                seen.add(port_num)
                ports.append((port_num, count))
        except ValueError:
            pass

    # Fallback: parse from text
    if not ports:
        port_matches = re.findall(r'port["\']?:(\d{1,5})', html)
        for p in port_matches:
            try:
                port_num = int(p)
                if port_num not in seen and 1 <= port_num <= 65535:
                    seen.add(port_num)
                    ports.append((port_num, 0))
            except ValueError:
                pass

    log.info("Found %d ports", len(ports))
    return ports, cookies, user_agent


def _get_global_ports_batched(cookies, user_agent, query):
    """Get global ports when query is too long for a single request.
    
    Strategy: Split the negated ports into batches of ~480,
    make multiple requests, and merge the results.
    Each batch returns up to 1000 ports. We merge and deduplicate.
    """
    # Extract base query and negated ports from the query string
    # Query format: product:"Ollama" -port:"11434" -port:"443" ...
    base_query = query
    negated_ports = []
    neg_port_pattern = re.findall(r'-port:"(\d+)"', query)
    for p in neg_port_pattern:
        negated_ports.append(int(p))
        base_query = base_query.replace(f'-port:"{p}"', '', 1).strip()
    
    log.info("Batched negation: %d ports to negate in batches of %d", len(negated_ports), MAX_NEGATE_PER_REQUEST)
    
    all_ports = {}  # port_num -> count (deduplicated)
    batch_size = MAX_NEGATE_PER_REQUEST
    
    for i in range(0, len(negated_ports), batch_size):
        batch = negated_ports[i:i + batch_size]
        batch_query = base_query
        for p in batch:
            batch_query += f' -port:"{p}"'
        
        log.info("  Batch %d/%d: negating %d ports (query len: %d)", 
                 i // batch_size + 1, (len(negated_ports) + batch_size - 1) // batch_size,
                 len(batch), len(batch_query))
        
        url = build_facet_url(batch_query, "port")
        html, cookies, user_agent = shodan_get(url, cookies, user_agent)
        if not html:
            log.warning("  Batch failed, skipping")
            continue
        
        batch_ports, cookies, user_agent = _parse_ports_from_html(html, cookies, user_agent)
        for port_num, count in batch_ports:
            if port_num not in all_ports:
                all_ports[port_num] = count
    
    # Remove ports that are in our negated list (they might still appear due to batching)
    for p in negated_ports:
        all_ports.pop(p, None)
    
    result = sorted(all_ports.items(), key=lambda x: -x[1])
    log.info("Batched negation: total %d new ports found", len(result))
    return result
def get_remaining_ips_by_negation(
    cookies, user_agent, query, parent_total, processed_items, 
    facet_type, facet_key, delay, extra_filters=None,
    output_file=None, seen_results=None, total_ips=0, progress_state=None,
):
    """Get remaining IPs by negating already-processed items.
    
    When the total count minus processed items < FACET_CAP, we can get
    all remaining IPs in a SINGLE request by negating the processed items.
    
    Args:
        query: Base Shodan query
        parent_total: Total count from the parent facet (e.g., country count)
        processed_items: list of (value, count) already processed
        facet_type: 'city', 'org', or 'net'
        facet_key: the Shodan query key (same as facet_type usually)
        delay: delay between requests
        extra_filters: dict of additional filters (e.g., {"country": "DE"})
        output_file: file to write results incrementally
        seen_results: set of already-seen results
        total_ips: current total count
        progress_state: dict for saving progress
    
    Returns:
        (ips_set, cookies, user_agent, total_ips)
    """
    processed_count = sum(c for _, c in processed_items)
    remaining = parent_total - processed_count
    
    if remaining <= 0:
        log.info("      🎯 No remaining IPs after negation (processed %d/%d)", processed_count, parent_total)
        return set(), cookies, user_agent, total_ips
    
    if remaining >= FACET_CAP:
        log.info("      🎯 Remaining %d >= %d, negation won't help, skip", remaining, FACET_CAP)
        return set(), cookies, user_agent, total_ips
    
    log.info("      🎯 Negation strategy: %d remaining (processed %d, total %d) — ONE request!",
             remaining, processed_count, parent_total)
    
    # Build negation query
    neg_query = query
    if extra_filters:
        for key, value in extra_filters.items():
            neg_query += f' {key}:"{value}"'
    for value, _ in processed_items:
        neg_value = unquote(value).replace("+", " ")
        neg_query += f' -{facet_key}:"{neg_value}"' 
    
    log.info("      🎯 Negation query: %s", neg_query)
    
    time.sleep(delay)
    ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, neg_query, {})
    
    if ips:
        log.info("      🎯 Negation got %d IPs (expected ~%d)", len(ips), remaining)
        if output_file and seen_results is not None:
            append_results(output_file, set(ips) - seen_results, seen_results)
    else:
        log.info("      🎯 Negation got 0 IPs")
    
    return set(ips) if ips else set(), cookies, user_agent, total_ips


# ─── Smart IP Extraction with Negation (without ports) ───────────────────────

def extract_ips_smart(
    cookies, user_agent, query, country_code, city_name,
    total_ips, delay, completed_set, progress_state,
    output_file=None, seen_results=None,
):
    """Extract IPs for a city with smart sub-querying and negation strategy.
    
    Flow:
      1. Get IPs directly → if < 1000, done!
      2. If >= 1000, get orgs WITH counts
      3. Process each org, track processed count
      4. When remaining < 999, negate processed orgs → get ALL remaining in ONE request
      5. If still >= 999 after all orgs, for each org: net negation strategy
    """
    filters = {"country": country_code, "city": city_name}
    ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, filters)

    if len(ips) == 0:
        return set(), total_ips, cookies, user_agent

    if len(ips) < FACET_CAP:
        log.info("    📍 %s: %d IPs (complete)", city_name, len(ips))
        if output_file and seen_results is not None:
            append_results(output_file, set(ips), seen_results)
        return set(ips), total_ips, cookies, user_agent

    # ── IP cap hit → sub-query by org with negation strategy ──
    log.warning("    ⚠️ %s: hit %d IP cap → sub-querying by org...", city_name, FACET_CAP)

    # We need the total count for this city. We know it's >= FACET_CAP.
    # Use a heuristic: since we hit the cap, total >= 1000
    # We'll get the actual total from the org facet counts
    orgs_with_counts, cookies, user_agent = get_orgs_with_counts(cookies, user_agent, query, country_code, city_name)
    log.info("    🏢 Found %d organizations in %s", len(orgs_with_counts), city_name)

    if not orgs_with_counts:
        log.info("    📍 %s: %d IPs (no org sub-query available)", city_name, len(ips))
        if output_file and seen_results is not None:
            append_results(output_file, set(ips), seen_results)
        return set(ips), total_ips, cookies, user_agent

    # Calculate total from org counts (this gives us the real total)
    org_total = sum(c for _, c in orgs_with_counts)
    # If org_total < FACET_CAP, the facet page probably undercounts
    # In that case, use FACET_CAP as minimum (we know there are at least 1000)
    city_total = max(org_total, FACET_CAP) if org_total >= FACET_CAP else org_total
    log.info("    📊 %s: total from org counts = %d (using %d for negation)", city_name, org_total, city_total)

    all_ips = set()
    processed_orgs = []  # (org_name, count) for negation

    for org_name, org_count in orgs_with_counts:
        org_key = f"{country_code}:{city_name}:org:{org_name}"
        if org_key in completed_set:
            log.info("      ⏭️ Skipping org %s — already done", org_name)
            processed_orgs.append((org_name, org_count))
            continue

        time.sleep(delay)

        org_filters = {"country": country_code, "city": city_name, "org": org_name}
        org_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, org_filters)

        if len(org_ips) < FACET_CAP:
            log.info("      🏢 %s: %d IPs", org_name, len(org_ips))
            all_ips.update(org_ips)
            if output_file and seen_results is not None:
                append_results(output_file, set(org_ips) - seen_results, seen_results)
            processed_orgs.append((org_name, org_count))
            completed_set.add(org_key)
            _save_progress_inline(progress_state, total_ips + len(all_ips))
            
            # ── Check if we can use negation for remaining orgs ──
            processed_count = sum(c for _, c in processed_orgs)
            remaining = city_total - processed_count
            if 0 < remaining < FACET_CAP and processed_orgs:
                log.info("      🎯 %d remaining after %d processed orgs — trying negation!", remaining, len(processed_orgs))
                neg_ips, cookies, user_agent, total_ips = get_remaining_ips_by_negation(
                    cookies, user_agent, query, city_total, processed_orgs,
                    'org', 'org', delay,
                    extra_filters={"country": country_code, "city": city_name},
                    output_file=output_file, seen_results=seen_results,
                    total_ips=total_ips, progress_state=progress_state,
                )
                all_ips.update(neg_ips)
                # Mark all remaining orgs as done
                for remaining_org, remaining_count in orgs_with_counts:
                    rk = f"{country_code}:{city_name}:org:{remaining_org}"
                    if rk not in completed_set:
                        completed_set.add(rk)
                        processed_orgs.append((remaining_org, remaining_count))
                log.info("      🎯 Negation captured %d IPs, skipping remaining orgs", len(neg_ips))
                break
            continue

        # ── Org cap hit → sub-query by net with negation ──
        log.warning("      ⚠️ org %s hit %d IP cap → sub-querying by net...", org_name, FACET_CAP)
        nets_with_counts, cookies, user_agent = get_nets_with_counts(cookies, user_agent, query, country_code, city_name, org_name)
        log.info("      🌐 Found %d networks in %s/%s", len(nets_with_counts), city_name, org_name)

        if not nets_with_counts:
            log.info("      🏢 %s: %d IPs (no net sub-query available)", org_name, len(org_ips))
            all_ips.update(org_ips)
            processed_orgs.append((org_name, org_count))
            completed_set.add(org_key)
            _save_progress_inline(progress_state, total_ips + len(all_ips))
            continue

        net_total = max(sum(c for _, c in nets_with_counts), FACET_CAP) if len(nets_with_counts) >= FACET_CAP else sum(c for _, c in nets_with_counts)
        processed_nets = []

        for net_name, net_count in nets_with_counts:
            net_key = f"{country_code}:{city_name}:org:{org_name}:net:{net_name}"
            if net_key in completed_set:
                log.info("        ⏭️ Skipping net %s — already done", net_name)
                processed_nets.append((net_name, net_count))
                continue

            time.sleep(delay)

            net_filters = {"country": country_code, "city": city_name, "org": org_name, "net": net_name}
            net_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, net_filters)
            log.info("        🌐 %s/%s: %d IPs", org_name, net_name, len(net_ips))
            all_ips.update(net_ips)
            if output_file and seen_results is not None:
                append_results(output_file, set(net_ips) - seen_results, seen_results)
            processed_nets.append((net_name, net_count))
            completed_set.add(net_key)
            _save_progress_inline(progress_state, total_ips + len(all_ips))

            # ── Check if we can negate remaining nets ──
            net_processed = sum(c for _, c in processed_nets)
            net_remaining = net_total - net_processed
            if 0 < net_remaining < FACET_CAP and len(processed_nets) > 0:
                log.info("        🎯 %d remaining in org %s — negating %d nets!", net_remaining, org_name, len(processed_nets))
                neg_ips, cookies, user_agent, total_ips = get_remaining_ips_by_negation(
                    cookies, user_agent, query, net_total, processed_nets,
                    'net', 'net', delay,
                    extra_filters={"country": country_code, "city": city_name, "org": org_name},
                    output_file=output_file, seen_results=seen_results,
                    total_ips=total_ips, progress_state=progress_state,
                )
                all_ips.update(neg_ips)
                # Mark remaining nets as done
                for rn, rc in nets_with_counts:
                    rk = f"{country_code}:{city_name}:org:{org_name}:net:{rn}"
                    if rk not in completed_set:
                        completed_set.add(rk)
                break

        processed_orgs.append((org_name, org_count))
        completed_set.add(org_key)

    log.info("    📍 %s: %d total IPs (after sub-queries + negation)", city_name, len(all_ips))
    return all_ips, total_ips, cookies, user_agent


# ─── Port-Based Scan (with negation strategy) ────────────────────────────────

def scan_port_globally(
    port, cookies, user_agent, base_query,
    exclude_countries, delay, completed_set,
    output_file, seen_results, total_ips, progress_state,
):
    """Scan a single port globally with smart optimization.
    
    Strategy:
      1. Quick check: single facet=ip request. If < 1000, DONE!
      2. If >= 1000: full country→city→org→net path with negation strategy
    """
    port_query = base_query + f' port:"{port}"'
    log.info("  🔌 Scanning port %d", port)

    # ── Step 1: Quick check ──
    log.info("    🔍 Quick check: direct IP facet for port %d...", port)
    quick_ips, cookies, user_agent = get_ips_from_facet(
        cookies, user_agent, port_query, {}  # no extra filters = global
    )

    if quick_ips is not None and len(quick_ips) == 0:
        log.info("    ⏭️ Port %d: 0 IPs found — skipping", port)
        return set(), cookies, user_agent, total_ips

    if quick_ips and len(quick_ips) < FACET_CAP:
        port_results = {f"{ip}:{port}" for ip in quick_ips}
        if output_file and seen_results is not None:
            append_results(output_file, port_results - seen_results, seen_results)
        log.info("    ✅ Port %d: %d IPs in ONE request (quick path)", port, len(quick_ips))
        return port_results, cookies, user_agent, total_ips

    if quick_ips and len(quick_ips) >= FACET_CAP:
        log.warning("    ⚠️ Port %d hit %d IP cap on quick check → full sub-query path", port, FACET_CAP)

    # ── Step 2: Full path with negation ──
    log.info("    🌍 Port %d: entering full country→city path with negation", port)

    countries_with_counts, cookies, user_agent = get_countries(cookies, user_agent, port_query)
    if not countries_with_counts:
        log.warning("  ⚠️ No countries found for port %d", port)
        if quick_ips:
            port_results = {f"{ip}:{port}" for ip in quick_ips}
            if output_file and seen_results is not None:
                append_results(output_file, port_results - seen_results, seen_results)
            return port_results, cookies, user_agent, total_ips
        return set(), cookies, user_agent, total_ips

    if exclude_countries:
        countries_with_counts = [(code, count) for code, count in countries_with_counts
                                  if code not in exclude_countries]

    port_results = set()
    global_total = sum(c for _, c in countries_with_counts)
    processed_countries = []  # (country_code, count) for potential global negation

    for country_code, country_count in countries_with_counts:
        if exclude_countries and country_code in exclude_countries:
            continue

        country_key = f"port:{port}:country:{country_code}"
        if country_key in completed_set:
            log.info("    ⏭️ Skipping port %d country %s — already done", port, country_code)
            processed_countries.append((country_code, country_count))
            continue

        # ── Get cities with counts for this country ──
        cities_with_counts, cookies, user_agent = get_cities_with_counts(cookies, user_agent, port_query, country_code)
        if not cities_with_counts:
            processed_countries.append((country_code, country_count))
            completed_set.add(country_key)
            continue

        # Calculate country total from city counts
        country_total = sum(c for _, c in cities_with_counts)
        if country_total == 0:
            country_total = country_count  # fallback to facet count
        log.info("    🏴 %s: %d cities, ~%d IPs", country_code, len(cities_with_counts), country_total)

        # Handle city cap
        cities = [city for city, _ in cities_with_counts]
        if len(cities) >= FACET_CAP:
            log.warning("    ⚠️ Port %d country %s hit %d city cap → sub-querying by org...", port, country_code, FACET_CAP)
            orgs_for_country, cookies, user_agent = get_orgs_with_counts(cookies, user_agent, port_query, country_code, "")
            if orgs_for_country:
                extra_cities = set(c for c, _ in cities_with_counts)
                for org_name, org_count in orgs_for_country:
                    time.sleep(delay)
                    org_city_url = build_facet_url(port_query, "city", extra_filters={"country": country_code, "org": org_name})
                    org_city_html, cookies, user_agent = shodan_get(org_city_url, cookies, user_agent)
                    if org_city_html:
                        org_city_results = parse_facet_with_counts(org_city_html, r'city%3A%22(.+?)%22')
                        if not org_city_results:
                            org_city_results = parse_facet_with_counts(org_city_html, r'city[^A-Za-z]*"(.+?)"')
                        for city_val, city_cnt in org_city_results:
                            if city_val not in extra_cities:
                                extra_cities.add(city_val)
                                cities.append(city_val)
                                cities_with_counts.append((city_val, city_cnt))
                log.info("    ✅ Port %d %s: %d cities after org sub-query", port, country_code, len(cities))

        processed_cities = []  # (city_name, count) for negation

        for city_name, city_count in cities_with_counts:
            city_key = f"port:{port}:city:{country_code}:{city_name}"
            if city_key in completed_set:
                log.info("      ⏭️ Skipping port %d %s/%s — already done", port, country_code, city_name)
                processed_cities.append((city_name, city_count))
                continue

            time.sleep(delay)

            filters = {"country": country_code, "city": city_name}
            ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, port_query, filters)

            if len(ips) == 0:
                processed_cities.append((city_name, city_count))
                completed_set.add(city_key)
                _save_progress_inline(progress_state, total_ips + len(port_results))
                continue

            port_ip_results = {f"{ip}:{port}" for ip in ips}

            if len(ips) < FACET_CAP:
                port_results.update(port_ip_results)
                if output_file and seen_results is not None:
                    append_results(output_file, port_ip_results - seen_results, seen_results)
                log.info("      📍 Port %d %s/%s: %d IPs (complete)", port, country_code, city_name, len(ips))
                processed_cities.append((city_name, city_count))
                completed_set.add(city_key)
                _save_progress_inline(progress_state, total_ips + len(port_results))
                
                # ── Check negation opportunity for remaining cities ──
                city_processed = sum(c for _, c in processed_cities)
                city_remaining = country_total - city_processed
                if 0 < city_remaining < FACET_CAP and len(processed_cities) > 0:
                    log.info("      🎯 Port %d %s: %d remaining after %d cities — negation!", port, country_code, city_remaining, len(processed_cities))
                    neg_ips, cookies, user_agent, total_ips = get_remaining_ips_by_negation(
                        cookies, user_agent, port_query, country_total, processed_cities,
                        'city', 'city', delay,
                        extra_filters={"country": country_code},
                        output_file=output_file, seen_results=seen_results,
                        total_ips=total_ips, progress_state=progress_state,
                    )
                    port_results.update({f"{ip}:{port}" for ip in neg_ips})
                    # Mark remaining cities as done
                    for rem_city, rem_count in cities_with_counts:
                        rk = f"port:{port}:city:{country_code}:{rem_city}"
                        if rk not in completed_set:
                            completed_set.add(rk)
                            processed_cities.append((rem_city, rem_count))
                    break
                continue

            # ── IP cap hit for city → sub-query by org with negation ──
            log.warning("      ⚠️ Port %d %s/%s hit IP cap → org sub-query + negation", port, country_code, city_name)
            orgs_with_counts, cookies, user_agent = get_orgs_with_counts(cookies, user_agent, port_query, country_code, city_name)
            if not orgs_with_counts:
                port_results.update(port_ip_results)
                if output_file and seen_results is not None:
                    append_results(output_file, port_ip_results - seen_results, seen_results)
                processed_cities.append((city_name, city_count))
                completed_set.add(city_key)
                _save_progress_inline(progress_state, total_ips + len(port_results))
                continue

            org_total = sum(c for _, c in orgs_with_counts)
            org_total = max(org_total, FACET_CAP) if len(org_ips) >= FACET_CAP else org_total
            processed_orgs = []

            for org_name, org_count in orgs_with_counts:
                org_key = f"port:{port}:city:{country_code}:{city_name}:org:{org_name}"
                if org_key in completed_set:
                    processed_orgs.append((org_name, org_count))
                    continue
                time.sleep(delay)

                org_filters = {"country": country_code, "city": city_name, "org": org_name}
                org_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, port_query, org_filters)

                if len(org_ips) < FACET_CAP:
                    org_port_results = {f"{ip}:{port}" for ip in org_ips}
                    port_results.update(org_port_results)
                    if output_file and seen_results is not None:
                        append_results(output_file, org_port_results - seen_results, seen_results)
                    processed_orgs.append((org_name, org_count))
                    completed_set.add(org_key)
                    _save_progress_inline(progress_state, total_ips + len(port_results))
                    
                    # Check negation for remaining orgs
                    org_processed = sum(c for _, c in processed_orgs)
                    org_remaining = org_total - org_processed
                    if 0 < org_remaining < FACET_CAP and len(processed_orgs) > 0:
                        log.info("        🎯 %d remaining after %d orgs — negation!", org_remaining, len(processed_orgs))
                        neg_ips, cookies, user_agent, total_ips = get_remaining_ips_by_negation(
                            cookies, user_agent, port_query, org_total, processed_orgs,
                            'org', 'org', delay,
                            extra_filters={"country": country_code, "city": city_name},
                            output_file=output_file, seen_results=seen_results,
                            total_ips=total_ips, progress_state=progress_state,
                        )
                        port_results.update({f"{ip}:{port}" for ip in neg_ips})
                        for rem_org, rem_count in orgs_with_counts:
                            rk = f"port:{port}:city:{country_code}:{city_name}:org:{rem_org}"
                            if rk not in completed_set:
                                completed_set.add(rk)
                        break
                    continue

                # Org cap hit → net with negation
                log.warning("        ⚠️ Port %d %s/%s org %s hit IP cap → net + negation", port, country_code, city_name, org_name)
                nets_with_counts, cookies, user_agent = get_nets_with_counts(cookies, user_agent, port_query, country_code, city_name, org_name)
                if not nets_with_counts:
                    org_port_results = {f"{ip}:{port}" for ip in org_ips}
                    port_results.update(org_port_results)
                    if output_file and seen_results is not None:
                        append_results(output_file, org_port_results - seen_results, seen_results)
                    processed_orgs.append((org_name, org_count))
                    completed_set.add(org_key)
                    _save_progress_inline(progress_state, total_ips + len(port_results))
                    continue

                net_total = sum(c for _, c in nets_with_counts)
                net_total = max(net_total, FACET_CAP) if len(org_ips) >= FACET_CAP else net_total
                processed_nets = []

                for net_name, net_count in nets_with_counts:
                    net_key = f"port:{port}:city:{country_code}:{city_name}:org:{org_name}:net:{net_name}"
                    if net_key in completed_set:
                        processed_nets.append((net_name, net_count))
                        continue
                    time.sleep(delay)
                    net_filters = {"country": country_code, "city": city_name, "org": org_name, "net": net_name}
                    net_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, port_query, net_filters)
                    net_port_results = {f"{ip}:{port}" for ip in net_ips}
                    port_results.update(net_port_results)
                    if output_file and seen_results is not None:
                        append_results(output_file, net_port_results - seen_results, seen_results)
                    processed_nets.append((net_name, net_count))
                    completed_set.add(net_key)
                    _save_progress_inline(progress_state, total_ips + len(port_results))

                    # Check negation for remaining nets
                    net_processed = sum(c for _, c in processed_nets)
                    net_remaining = net_total - net_processed
                    if 0 < net_remaining < FACET_CAP and len(processed_nets) > 0:
                        log.info("          🎯 %d remaining after %d nets — negation!", net_remaining, len(processed_nets))
                        neg_ips, cookies, user_agent, total_ips = get_remaining_ips_by_negation(
                            cookies, user_agent, port_query, net_total, processed_nets,
                            'net', 'net', delay,
                            extra_filters={"country": country_code, "city": city_name, "org": org_name},
                            output_file=output_file, seen_results=seen_results,
                            total_ips=total_ips, progress_state=progress_state,
                        )
                        port_results.update({f"{ip}:{port}" for ip in neg_ips})
                        for rn, rc in nets_with_counts:
                            rk = f"port:{port}:city:{country_code}:{city_name}:org:{org_name}:net:{rn}"
                            if rk not in completed_set:
                                completed_set.add(rk)
                        break

                processed_orgs.append((org_name, org_count))
                completed_set.add(org_key)

            processed_cities.append((city_name, city_count))
            completed_set.add(city_key)

        processed_countries.append((country_code, country_count))
        completed_set.add(country_key)

    total_ips = len(seen_results) if seen_results else len(port_results)
    log.info("  ✅ Port %d done: %d IP:PORT entries collected", port, len(port_results))
    return port_results, cookies, user_agent, total_ips


# ─── Progress Management ─────────────────────────────────────────────────────

def _save_progress_inline(state: dict, total_ips: int):
    """Save progress inline during sub-queries."""
    state["total_ips"] = total_ips
    with open(state["progress_file"], "w") as f:
        json.dump(state, f, indent=2)


def save_progress(
    progress_file, completed_countries, completed_cities,
    completed_subqueries, total_ips, query, with_ports=False, output_file="",
    completed_ports=None, negated_ports=None,
):
    """Save full progress state to file."""
    progress = {
        "query": query,
        "with_ports": with_ports,
        "output_file": output_file,
        "completed_countries": sorted(list(completed_countries)),
        "completed_cities": {k: v for k, v in completed_cities.items()},
        "completed_subqueries": sorted(list(completed_subqueries)),
        "total_ips": total_ips,
        "last_updated": datetime.now().isoformat(),
    }
    if with_ports:
        progress["completed_ports"] = sorted(list(completed_ports)) if completed_ports else []
        progress["negated_ports"] = sorted(list(negated_ports)) if negated_ports else []
    with open(progress_file, "w") as f:
        json.dump(progress, f, indent=2)


def load_progress(progress_file: str, query: str) -> dict:
    """Load progress from file, validating query match."""
    if not os.path.exists(progress_file):
        return None
    try:
        with open(progress_file, "r") as f:
            progress = json.load(f)
        if progress.get("query") != query:
            log.warning("Progress file query mismatch. Starting fresh.")
            return None
        return progress
    except Exception as e:
        log.error("Error loading progress: %s", e)
        return None


def load_seen_results(output_file: str) -> tuple:
    """Load existing results from output file to avoid duplicates on resume."""
    seen = set()
    if not os.path.exists(output_file):
        return seen
    try:
        with open(output_file, "r") as f:
            for line in f:
                entry = line.strip()
                if entry:
                    seen.add(entry)
        log.info("Loaded %d existing results from %s", len(seen), output_file)
    except Exception as e:
        log.warning("Error reading output file: %s", e)
    return seen


def append_results(output_file: str, new_entries, seen_results: set) -> int:
    """Append new results to file and update seen set."""
    if not output_file or not new_entries:
        return 0
    actually_new = new_entries - seen_results
    if actually_new:
        with open(output_file, "a") as f:
            for entry in sorted(actually_new):
                f.write(entry + "\n")
        seen_results.update(actually_new)
    return len(actually_new)


def save_results(output_file: str, new_results, seen_results: set) -> tuple:
    """Append new (deduplicated) results to file."""
    actually_new = set(new_results) - seen_results
    if actually_new:
        with open(output_file, "a") as f:
            for entry in sorted(actually_new):
                f.write(entry + "\n")
    seen_results.update(actually_new)
    return len(actually_new), len(seen_results)


# ─── Main ─────────────────────────────────────────────────────────────────────

def handle_interrupt(signum, frame):
    """Handle Ctrl+C gracefully."""
    print("\n\n⚠️ Interrupted! Saving progress...")
    print("✅ Progress saved. Use --resume to continue later.")
    raise SystemExit(0)


def main():
    import signal
    signal.signal(signal.SIGINT, handle_interrupt)
    parser = argparse.ArgumentParser(
        description="Shodan Facet IP Collector — aheybati Scanner v3.1",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  shodan_facet_collector.py -u user@email -p pass -q 'port:"22"'
  shodan_facet_collector.py -u user@email -p pass -q 'port:"22"' --exclude IR,US
  shodan_facet_collector.py -u user@email -p pass -q 'port:"80" product:"nginx"' -d 5 -o output.txt
  shodan_facet_collector.py -u user@email -p pass -q 'port:"22"' --resume
  shodan_facet_collector.py -u user@email -p pass -q 'product:"nginx"' --with-ports

Smart Sub-Query + Negation Strategy (v3.1):
  When a city/org has >1000 results:
    1. Get facet values WITH counts
    2. Process large items with sub-queries
    3. Track processed count
    4. When remaining < 999, NEGATE processed items
    5. Get ALL remaining IPs in ONE request!

  This avoids iterating tiny cities/orgs one by one,
  saving hundreds of requests.

Port Strategy (v3.0):
  Gets global port list, then for each port:
    - Quick path: < 1000 IPs → ONE request
    - Full path: ≥ 1000 → countries → cities + negation

Estimates:
  Small services:                  ~95-99% coverage
  Large services (e.g. SSH ~18M): ~90-95% coverage with sub-queries
        """,
    )
    parser.add_argument("-u", "--username", default=os.environ.get("SHODAN_USERNAME", ""), help="Shodan username/email (or set SHODAN_USERNAME env var)")
    parser.add_argument("-p", "--password", default=os.environ.get("SHODAN_PASSWORD", ""), help="Shodan password (or set SHODAN_PASSWORD env var)")
    parser.add_argument("-q", "--query", required=True, help="Shodan query string")
    parser.add_argument("-x", "--exclude", default="", help="Country codes to EXCLUDE (e.g. IR,US)")
    parser.add_argument("-o", "--output", default=None, help="Output file (default: ips.txt or ips_ports.txt)")
    parser.add_argument("-d", "--delay", type=int, default=DEFAULT_DELAY, help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("-w", "--with-ports", action="store_true", help="Include port numbers in output (IP:PORT format) — uses global port strategy")
    parser.add_argument("--resume", action="store_true", help="Resume from previous progress")
    args = parser.parse_args()

    if not args.username:
        parser.error("Username required: use -u or set SHODAN_USERNAME env var")
    if not args.password:
        parser.error("Password required: use -p or set SHODAN_PASSWORD env var")

    query = args.query
    with_ports = args.with_ports

    if args.output:
        output_file = args.output
    else:
        output_file = DEFAULT_OUTPUT_PORTS if with_ports else DEFAULT_OUTPUT

    delay = args.delay

    exclude_countries = set()
    if args.exclude:
        exclude_countries = {c.strip().upper() for c in args.exclude.split(",")}

    # ── Print banner ──
    print("=" * 60)
    print("  🔍 Shodan Facet IP Collector — aheybati Scanner v3.1")
    print("=" * 60)
    print(f"  👤 User:       {args.username}")
    print(f"  🔑 Query:      {query}")
    print(f"  📁 Output:     {output_file}")
    print(f"  ⏱️  Delay:      {delay}s")
    print(f"  🔄 Sub-query:  Enabled (org → net + negation)")
    if with_ports:
        print(f"  🔌 With ports: YES (global port strategy)")
    if exclude_countries:
        print(f"  🚫 Exclude:    {', '.join(sorted(exclude_countries))}")
    print("=" * 60)

    # ── Login ──
    cookies, user_agent = login_shodan(args.username, args.password)
    if not cookies:
        log.error("Login failed! Exiting.")
        return
    _login_state["username"] = args.username
    _login_state["password"] = args.password

    # ── Load progress ──
    completed_countries = set()
    completed_cities = {}
    completed_subqueries = set()
    completed_ports = set()
    negated_ports = set()
    total_ips = 0
    seen_results = set()

    if args.resume:
        progress = load_progress(PROGRESS_FILE, query)
        if progress:
            completed_countries = set(progress.get("completed_countries", []))
            completed_cities = progress.get("completed_cities", {})
            completed_subqueries = set(progress.get("completed_subqueries", []))
            completed_ports = set(progress.get("completed_ports", []))
            negated_ports = set(progress.get("negated_ports", []))
            saved_output = progress.get("output_file")
            if saved_output and os.path.exists(saved_output):
                output_file = saved_output
                log.info("Using saved output file from progress: %s", output_file)
            if args.output:
                output_file = args.output
                log.info("Using -o output file: %s", output_file)
            seen_results = load_seen_results(output_file)
            total_ips = len(seen_results)
            log.info("Resuming: %d countries done, %d results collected so far", len(completed_countries), total_ips)
            if with_ports:
                log.info("Ports completed: %s", sorted(completed_ports))
                log.info("Ports negated: %s", sorted(negated_ports))
        else:
            log.warning("No matching progress file found. Starting fresh.")

    if not os.path.exists(output_file):
        open(output_file, "w").close()

    # ═══════════════════════════════════════════════════════════════════════
    # MODE: --with-ports  (Global Port Strategy + Negation)
    # ═══════════════════════════════════════════════════════════════════════
    if with_ports:
        print(f"\n🚀 Starting GLOBAL PORT scan...")
        print(f"   Strategy: Get ports → scan each port (quick or full) → negate → repeat")

        port_round = len(negated_ports) + 1
        all_port_results = set()

        while True:
            current_query = query
            for p in sorted(negated_ports):
                current_query += f' -port:"{p}"'
            
            print(f"\n{'─' * 60}")
            print(f"  📊 Port round {port_round}: fetching global port list")
            print(f"  🔍 Query: {current_query}")
            print(f"{'─' * 60}")

            port_list, cookies, user_agent = get_global_ports(cookies, user_agent, current_query)
            if not port_list:
                log.info("No more ports found. Port scan complete!")
                break

            remaining_ports = [(p, c) for p, c in port_list if p not in completed_ports]
            if not remaining_ports:
                log.info("All discovered ports already completed. Checking for more...")
                for p, c in port_list:
                    if p not in negated_ports:
                        negated_ports.add(p)
                port_round += 1
                continue

            print(f"  🔌 Found {len(port_list)} ports ({len(remaining_ports)} remaining to scan)")
            for p, c in remaining_ports[:10]:
                log.info(f"     Port {p} ({c})")
            if len(remaining_ports) > 10:
                log.info(f"     ... and {len(remaining_ports) - 10} more")

            for port_num, count_str in remaining_ports:
                if port_num in completed_ports:
                    log.info("  ⏭️ Skipping port %d — already completed", port_num)
                    continue

                print(f"\n  🔌{'=' * 50}")
                print(f"  🔌 Scanning PORT {port_num} (round {port_round})")
                print(f"  🔌{'=' * 50}")

                progress_state = {
                    "progress_file": PROGRESS_FILE,
                    "completed_countries": list(completed_countries),
                    "completed_cities": {k: v for k, v in completed_cities.items()},
                    "completed_subqueries": list(completed_subqueries),
                    "query": query,
                }

                port_results, cookies, user_agent, total_ips = scan_port_globally(
                    port_num, cookies, user_agent, query,
                    exclude_countries, delay, completed_subqueries,
                    output_file, seen_results, total_ips, progress_state,
                )

                all_port_results.update(port_results)
                completed_ports.add(port_num)

                save_progress(PROGRESS_FILE, completed_countries, completed_cities,
                             completed_subqueries, total_ips, query, True, output_file,
                             completed_ports, negated_ports)

                print(f"  ✅ Port {port_num}: {len(port_results)} new IP:PORT | Total: {len(seen_results)}")

            for p, c in port_list:
                if p not in negated_ports:
                    negated_ports.add(p)
            
            port_round += 1
            
            save_progress(PROGRESS_FILE, completed_countries, completed_cities,
                         completed_subqueries, total_ips, query, True, output_file,
                         completed_ports, negated_ports)

        print(f"\n{'=' * 60}")
        print(f"🏁 PORT SCAN ALL DONE!")
        print(f"📊 Total IP:PORT entries collected: {len(seen_results)}")
        print(f"🔌 Ports scanned: {len(completed_ports)}")
        print(f"📁 Saved to: {output_file}")
        return

    # ═══════════════════════════════════════════════════════════════════════
    # MODE: Normal (without --with-ports) — with negation strategy
    # ═══════════════════════════════════════════════════════════════════════
    
    countries_with_counts, cookies, user_agent = get_countries(cookies, user_agent, query)
    if not countries_with_counts:
        log.error("No countries found! Exiting.")
        return

    # Convert to format expected by the rest of the code
    countries = [(code, count) for code, count in countries_with_counts]
    
    if exclude_countries:
        before = len(countries)
        countries = [(code, count) for code, count in countries if code not in exclude_countries]
        excluded_count = before - len(countries)
        log.info("Excluded %d countries: %s", excluded_count, ", ".join(sorted(exclude_countries)))
        log.info("Scanning %d countries", len(countries))

    global_total = sum(c for _, c in countries)
    print(f"\n🚀 Starting scan of {len(countries)} countries (~{global_total:,} total IPs)")
    print(f"   Strategy: Sub-query + negation (skip tiny cities!)")

    processed_countries = []  # (country_code, count) for potential negation

    for country_code, country_count in countries:
        if country_code in completed_countries:
            log.info("⏭️ Skipping %s — already completed", country_code)
            processed_countries.append((country_code, country_count))
            continue

        print(f"\n{'=' * 60}")
        print(f"🏴 Processing country: {country_code} (~{country_count:,} IPs)")
        print(f"{'=' * 60}")

        # ── Get cities with counts ──
        cities_with_counts, cookies, user_agent = get_cities_with_counts(cookies, user_agent, query, country_code)
        if not cities_with_counts:
            log.warning("No cities found, skipping...")
            completed_countries.add(country_code)
            processed_countries.append((country_code, country_count))
            save_progress(PROGRESS_FILE, completed_countries, completed_cities,
                         completed_subqueries, total_ips, query, False, output_file)
            continue

        # Calculate actual country total from city counts
        country_total = sum(c for _, c in cities_with_counts)
        if country_total == 0:
            country_total = country_count
        log.info("Found %d cities in %s (~%s total IPs)", len(cities_with_counts), country_code, f"{country_total:,}")

        # Handle city cap — sub-query by org to find more cities
        if len(cities_with_counts) >= FACET_CAP:
            log.warning("⚠️ Country %s hit %d city cap → sub-querying by org...", country_code, FACET_CAP)
            orgs_with_counts, cookies, user_agent = get_orgs_with_counts(cookies, user_agent, query, country_code, "")
            if orgs_with_counts:
                extra_cities = set(c for c, _ in cities_with_counts)
                for org_name, org_count in orgs_with_counts:
                    time.sleep(delay)
                    org_city_url = build_facet_url(query, "city", extra_filters={"country": country_code, "org": org_name})
                    org_city_html, cookies, user_agent = shodan_get(org_city_url, cookies, user_agent)
                    if org_city_html:
                        org_city_results = parse_facet_with_counts(org_city_html, r'city%3A%22(.+?)%22')
                        if not org_city_results:
                            org_city_results = parse_facet_with_counts(org_city_html, r'city[^A-Za-z]*"(.+?)"')
                        for city_val, city_cnt in org_city_results:
                            if city_val not in extra_cities:
                                extra_cities.add(city_val)
                                cities_with_counts.append((city_val, city_cnt))
                log.info("  ✅ After org sub-query: %d cities total", len(cities_with_counts))

        processed_cities = []  # (city_name, count) for negation

        for city_name, city_count in cities_with_counts:
            city_list = completed_cities.get(country_code, [])
            if city_name in city_list:
                log.info("  ⏭️ Skipping %s — already completed", city_name)
                processed_cities.append((city_name, city_count))
                continue

            print(f"  📍 {city_name} (~{city_count:,} IPs)...", end=" ", flush=True)

            time.sleep(delay)

            progress_state = {
                "progress_file": PROGRESS_FILE,
                "completed_countries": list(completed_countries),
                "completed_cities": {k: v for k, v in completed_cities.items()},
                "completed_subqueries": list(completed_subqueries),
                "query": query,
            }

            new_results, total_ips, cookies, user_agent = extract_ips_smart(
                cookies, user_agent, query, country_code, city_name,
                total_ips, delay, completed_subqueries, progress_state,
                output_file=output_file, seen_results=seen_results,
            )

            new_count, total_seen = save_results(output_file, new_results, seen_results)
            total_ips = total_seen

            cities_done = sum(len(v) for v in completed_cities.values())
            print(f"{len(new_results)} IPs (new: {new_count}, total: {total_seen}, cities: {cities_done})")

            if country_code not in completed_cities:
                completed_cities[country_code] = []
            completed_cities[country_code].append(city_name)
            processed_cities.append((city_name, city_count))

            # ── Check negation opportunity for remaining cities ──
            city_processed = sum(c for _, c in processed_cities)
            city_remaining = country_total - city_processed
            if 0 < city_remaining < FACET_CAP and len(processed_cities) > 0:
                log.info("  🎯 %d remaining after %d cities — negation!", city_remaining, len(processed_cities))
                neg_ips, cookies, user_agent, total_ips = get_remaining_ips_by_negation(
                    cookies, user_agent, query, country_total, processed_cities,
                    'city', 'city', delay,
                    extra_filters={"country": country_code},
                    output_file=output_file, seen_results=seen_results,
                    total_ips=total_ips, progress_state=progress_state,
                )
                new_count, total_seen = save_results(output_file, neg_ips, seen_results)
                total_ips = total_seen
                # Mark remaining cities as done
                for rem_city, rem_count in cities_with_counts:
                    if country_code not in completed_cities:
                        completed_cities[country_code] = []
                    if rem_city not in completed_cities[country_code]:
                        completed_cities[country_code].append(rem_city)
                print(f"  🎯 Negation captured {len(neg_ips)} IPs! Skipping remaining tiny cities.")
                break

            save_progress(PROGRESS_FILE, completed_countries, completed_cities,
                         completed_subqueries, total_ips, query, False, output_file)

        completed_countries.add(country_code)
        processed_countries.append((country_code, country_count))
        save_progress(PROGRESS_FILE, completed_countries, completed_cities,
                     completed_subqueries, total_ips, query, False, output_file)
        print(f"  ✅ Country {country_code} done!")

    # ── Done ──
    total_countries_done = len(completed_countries)
    total_cities_done = sum(len(v) for v in completed_cities.values())
    print(f"\n{'=' * 60}")
    print(f"🏁 ALL DONE!")
    print(f"📊 Total unique IPs collected: {len(seen_results)}")
    print(f"🌍 Countries scanned: {total_countries_done}")
    print(f"🏙️ Cities scanned: {total_cities_done}")
    print(f"📁 Saved to: {output_file}")


if __name__ == "__main__":
    main()
