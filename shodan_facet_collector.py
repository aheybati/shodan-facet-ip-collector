#!/usr/bin/env python3
"""
Shodan Facet IP Collector — aheybati Scanner v2.1
================================================
Extracts IP addresses from Shodan using facet pages (no API credits needed).
Uses smart sub-querying to bypass the 1000-result facet limit.
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
                # Check if still on challenge page
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

# Global login state for auto re-login on session expiry
_login_state = {"username": "", "password": ""}


def shodan_get(url: str, cookies: dict, user_agent: str) -> tuple:
    """GET a Shodan page, with Cloudflare fallback and auto re-login on session expiry."""
    headers = {"User-Agent": user_agent, "Referer": "https://www.shodan.io/"}
    for attempt in range(1, 3):  # max 2 attempts: original + re-login
        try:
            resp = http_requests.get(
                url, cookies=cookies, headers=headers,
                allow_redirects=True, timeout=30,
            )
            # Cloudflare challenge
            if resp.status_code == 403 or "Just a moment" in resp.text:
                log.info("Cloudflare challenge detected, using FlareSolverr...")
                html, new_cookies, user_agent = flaresolverr_get(url)
                if html:
                    cookies.update(new_cookies)
                    return html, cookies, user_agent
                return None, cookies, user_agent
            # Session expired — redirected to login page
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
            # Check for login page in response body
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
    """Extract values from facet page links matching a URL pattern."""
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
    """Get list of countries from Shodan facet."""
    log.info("Fetching country list...")
    url = build_facet_url(query, "country")
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        log.error("Failed to get country list!")
        return [], cookies, user_agent

    countries = parse_facet_links(html, r'country%3A%22([A-Z]{2})%22')
    if not countries:
        countries = parse_facet_links(html, r'country[^A-Za-z]*"([A-Z]{2})"')

    log.info("Found %d countries", len(countries))
    return countries, cookies, user_agent


def get_cities(cookies: dict, user_agent: str, query: str, country_code: str) -> tuple:
    """Get list of cities for a country from Shodan facet."""
    url = build_facet_url(query, "city", extra_filters={"country": country_code})
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent

    results = parse_facet_links(html, r'city%3A%22(.+?)%22')
    if not results:
        results = parse_facet_links(html, r'city[^A-Za-z]*"(.+?)"')
    cities = [city for city, _ in results]
    return cities, cookies, user_agent


def get_ports(cookies: dict, user_agent: str, query: str, extra_filters: dict = None) -> tuple:
    """Get list of ports from Shodan facet."""
    url = build_facet_url(query, "port", extra_filters=extra_filters)
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent

    ports = set()
    soup = BeautifulSoup(html, "html.parser")
    all_links = soup.find_all("a", href=True)
    for link in all_links:
        href = link.get("href", "")
        decoded = unquote(href)
        match = re.search(r'port%3A(\d+)', href)
        if not match:
            match = re.search(r'port:(\d+)', decoded)
        if match:
            try:
                ports.add(int(match.group(1)))
            except ValueError:
                pass

    if not ports:
        results = parse_facet_links(html, r'port%3A%22(\d+)%22')
        if not results:
            results = parse_facet_links(html, r'port[^A-Za-z]*"(\d+)"')
        for port_str, _ in results:
            try:
                ports.add(int(port_str))
            except ValueError:
                pass

    if not ports:
        for link in all_links:
            text = link.get_text(strip=True)
            if re.match(r'^\d{1,5}$', text):
                try:
                    port_num = int(text)
                    if 1 <= port_num <= 65535:
                        ports.add(port_num)
                except ValueError:
                    pass

    if not ports:
        port_matches = re.findall(r'port["\']?:(\d{1,5})', html)
        for p in port_matches:
            try:
                port_num = int(p)
                if 1 <= port_num <= 65535:
                    ports.add(port_num)
            except ValueError:
                pass

    return sorted(ports), cookies, user_agent


def get_orgs(cookies: dict, user_agent: str, query: str, country_code: str, city_name: str) -> tuple:
    """Get list of organizations for a city from Shodan facet."""
    url = build_facet_url(query, "org", extra_filters={"country": country_code, "city": city_name})
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent

    results = parse_facet_links(html, r'org%3A%22(.+?)%22')
    if not results:
        results = parse_facet_links(html, r'org[^A-Za-z]*"(.+?)"')
    orgs = list(set(org for org, _ in results))
    return orgs, cookies, user_agent


def get_nets(cookies: dict, user_agent: str, query: str, country_code: str, city_name: str, org_name: str) -> tuple:
    """Get list of network ranges for an org from Shodan facet."""
    url = build_facet_url(
        query, "net",
        extra_filters={"country": country_code, "city": city_name, "org": org_name},
    )
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent

    results = parse_facet_links(html, r'net%3A%22(.+?)%22')
    if not results:
        results = parse_facet_links(html, r'net[^A-Za-z]*"(.+?)"')
    nets = list(set(net for net, _ in results))
    return nets, cookies, user_agent


def get_ips_from_facet(cookies: dict, user_agent: str, query: str, extra_filters: dict) -> tuple:
    """Get IPs from a Shodan IP facet page with given filters."""
    url = build_facet_url(query, "ip", extra_filters=extra_filters)
    html, cookies, user_agent = shodan_get(url, cookies, user_agent)
    if not html:
        return [], cookies, user_agent
    ips = parse_ips(html)
    return ips, cookies, user_agent


# ─── Smart IP Extraction (with Sub-Query) ─────────────────────────────────────

def extract_ips_smart(
    cookies, user_agent, query, country_code, city_name,
    total_ips, delay, completed_set, progress_state,
    output_file=None, seen_results=None,
    with_ports=False, ports_for_city=None
):
    """Extract IPs for a city with smart sub-querying.

    If with_ports=True, iterates over ports and returns IP:PORT pairs.
    If with_ports=False, returns plain IPs as before.
    """
    if with_ports and ports_for_city is not None:
        all_results = set()

        # Check if port list hit the cap — need to sub-query by org first
        if len(ports_for_city) >= FACET_CAP:
            log.warning("    ⚠️ %s: hit %d PORT cap → sub-querying by org...", city_name, FACET_CAP)
            orgs, cookies, user_agent = get_orgs(cookies, user_agent, query, country_code, city_name)
            log.info("    🏢 Found %d organizations in %s", len(orgs), city_name)

            if orgs:
                for org in orgs:
                    org_key = f"{country_code}:{city_name}:org:{org}"
                    if org_key in completed_set:
                        log.info("      ⏭️ Skipping org %s — already done", org)
                        continue
                    time.sleep(delay)

                    # Get ports for this org
                    org_filters = {"country": country_code, "city": city_name, "org": org}
                    org_ports, cookies, user_agent = get_ports(cookies, user_agent, query, org_filters)
                    log.info("      🏢 %s: %d ports", org, len(org_ports))

                    for port in org_ports:
                        log.info("        🔌 %s port %s/%s...", org, port, len(org_ports))
                        time.sleep(delay)

                        filters = {"country": country_code, "city": city_name, "org": org, "port": str(port)}
                        ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, filters)

                        if len(ips) == 0:
                            continue

                        port_results = {f"{ip}:{port}" for ip in ips}

                        if len(ips) < FACET_CAP:
                            all_results.update(port_results)
                            if output_file and seen_results is not None:
                                append_results(output_file, port_results - seen_results, seen_results)
                            log.info("          🔌 %s port %d: %d IPs", org, port, len(ips))
                            continue

                        # IP cap hit for this org+port — sub-query by net
                        log.warning("          ⚠️ %s port %d hit %d IP cap → sub-querying by net...", org, port, FACET_CAP)
                        nets, cookies, user_agent = get_nets(cookies, user_agent, query, country_code, city_name, org)
                        if not nets:
                            all_results.update(port_results)
                            if output_file and seen_results is not None:
                                append_results(output_file, port_results - seen_results, seen_results)
                            continue

                        for net in nets:
                            net_key = f"{country_code}:{city_name}:org:{org}:port:{port}:net:{net}"
                            if net_key in completed_set:
                                continue
                            time.sleep(delay)
                            net_filters = {"country": country_code, "city": city_name, "org": org, "port": str(port), "net": net}
                            net_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, net_filters)
                            net_port_results = {f"{ip}:{port}" for ip in net_ips}
                            all_results.update(net_port_results)
                            if output_file and seen_results is not None:
                                append_results(output_file, net_port_results - seen_results, seen_results)
                            completed_set.add(net_key)
                            log.info("            🌐 %s/%s port %d: %d IPs", org, net, port, len(net_ips))

                    completed_set.add(org_key)

                log.info("    📍 %s: %d IP:PORT entries (org sub-query, across %d orgs)", city_name, len(all_results), len(orgs))
                return all_results, total_ips, cookies, user_agent
            else:
                log.warning("    ⚠️ No orgs found for port sub-query, using available ports only")

        # Port list is under cap — iterate ports normally
        for port in ports_for_city:
            log.info("      🔌 Port %s/%s...", port, len(ports_for_city))
            time.sleep(delay)

            base_filters = {"country": country_code, "city": city_name, "port": str(port)}
            ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, base_filters)

            if len(ips) == 0:
                continue

            port_results = {f"{ip}:{port}" for ip in ips}

            if len(ips) < FACET_CAP:
                all_results.update(port_results)
                # Save incrementally after each port
                if output_file and seen_results is not None:
                    append_results(output_file, port_results - seen_results, seen_results)
                log.info("        🔌 Port %d: %d IPs (complete)", port, len(ips))
                continue

            # IP cap hit for this port — sub-query by org
            log.warning("        ⚠️ Port %d hit %d IP cap → sub-querying by org...", port, FACET_CAP)
            orgs, cookies, user_agent = get_orgs(cookies, user_agent, query, country_code, city_name)
            log.info("        🏢 Found %d orgs for port %d", len(orgs), port)

            if not orgs:
                all_results.update(port_results)
                if output_file and seen_results is not None:
                    append_results(output_file, port_results - seen_results, seen_results)
                continue

            for org in orgs:
                org_key = f"{country_code}:{city_name}:port:{port}:org:{org}"
                if org_key in completed_set:
                    continue
                time.sleep(delay)

                org_filters = {"country": country_code, "city": city_name, "port": str(port), "org": org}
                org_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, org_filters)

                if len(org_ips) < FACET_CAP:
                    org_port_results = {f"{ip}:{port}" for ip in org_ips}
                    all_results.update(org_port_results)
                    if output_file and seen_results is not None:
                        append_results(output_file, org_port_results - seen_results, seen_results)
                    completed_set.add(org_key)
                    log.info("          🏢 %s port %d: %d IPs", org, port, len(org_ips))
                    continue

                # IP cap hit again — sub-query by net
                log.warning("          ⚠️ org %s port %d hit cap → sub-querying by net...", org, port)
                nets, cookies, user_agent = get_nets(cookies, user_agent, query, country_code, city_name, org)
                if not nets:
                    all_results.update({f"{ip}:{port}" for ip in org_ips})
                    if output_file and seen_results is not None:
                        append_results(output_file, {f"{ip}:{port}" for ip in org_ips} - seen_results, seen_results)
                    completed_set.add(org_key)
                    continue

                for net in nets:
                    net_key = f"{country_code}:{city_name}:port:{port}:org:{org}:net:{net}"
                    if net_key in completed_set:
                        continue
                    time.sleep(delay)
                    net_filters = {"country": country_code, "city": city_name, "port": str(port), "org": org, "net": net}
                    net_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, net_filters)
                    net_port_results = {f"{ip}:{port}" for ip in net_ips}
                    all_results.update(net_port_results)
                    if output_file and seen_results is not None:
                        append_results(output_file, net_port_results - seen_results, seen_results)
                    completed_set.add(net_key)
                    log.info("            🌐 %s/%s port %d: %d IPs", org, net, port, len(net_ips))

                completed_set.add(org_key)

        log.info("    📍 %s: %d IP:PORT entries (across %d ports)", city_name, len(all_results), len(ports_for_city))
        return all_results, total_ips, cookies, user_agent

    # ── Normal mode (no ports) ──
    filters = {"country": country_code, "city": city_name}
    ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, filters)

    if len(ips) == 0:
        return set(), total_ips, cookies, user_agent

    if len(ips) < FACET_CAP:
        log.info("    📍 %s: %d IPs (complete)", city_name, len(ips))
        # Save incrementally
        if output_file and seen_results is not None:
            append_results(output_file, set(ips), seen_results)
        return set(ips), total_ips, cookies, user_agent

    log.warning("    ⚠️ %s: hit %d IP cap → sub-querying by org...", city_name, FACET_CAP)
    all_ips = set()

    orgs, cookies, user_agent = get_orgs(cookies, user_agent, query, country_code, city_name)
    log.info("    🏢 Found %d organizations in %s", len(orgs), city_name)

    if not orgs:
        log.info("    📍 %s: %d IPs (no org sub-query available)", city_name, len(ips))
        if output_file and seen_results is not None:
            append_results(output_file, set(ips), seen_results)
        return set(ips), total_ips, cookies, user_agent

    for org in orgs:
        org_key = f"{country_code}:{city_name}:org:{org}"
        if org_key in completed_set:
            log.info("      ⏭️ Skipping org %s — already done", org)
            continue

        time.sleep(delay)

        org_filters = {"country": country_code, "city": city_name, "org": org}
        org_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, org_filters)

        if len(org_ips) < FACET_CAP:
            log.info("      🏢 %s: %d IPs", org, len(org_ips))
            all_ips.update(org_ips)
            # Save incrementally
            if output_file and seen_results is not None:
                append_results(output_file, set(org_ips) - seen_results, seen_results)
            completed_set.add(org_key)
            _save_progress_inline(progress_state, total_ips + len(all_ips))
            continue

        log.warning("      ⚠️ org %s hit %d IP cap → sub-querying by net...", org, FACET_CAP)
        nets, cookies, user_agent = get_nets(cookies, user_agent, query, country_code, city_name, org)
        log.info("      🌐 Found %d networks in %s/%s", len(nets), city_name, org)

        if not nets:
            log.info("      🏢 %s: %d IPs (no net sub-query available)", org, len(org_ips))
            all_ips.update(org_ips)
            completed_set.add(org_key)
            _save_progress_inline(progress_state, total_ips + len(all_ips))
            continue

        for net in nets:
            net_key = f"{country_code}:{city_name}:org:{org}:net:{net}"
            if net_key in completed_set:
                log.info("        ⏭️ Skipping net %s — already done", net)
                continue

            time.sleep(delay)

            net_filters = {"country": country_code, "city": city_name, "org": org, "net": net}
            net_ips, cookies, user_agent = get_ips_from_facet(cookies, user_agent, query, net_filters)
            log.info("        🌐 %s/%s: %d IPs", org, net, len(net_ips))
            all_ips.update(net_ips)
            # Save incrementally
            if output_file and seen_results is not None:
                append_results(output_file, set(net_ips) - seen_results, seen_results)
            completed_set.add(net_key)
            _save_progress_inline(progress_state, total_ips + len(all_ips))

        completed_set.add(org_key)

    log.info("    📍 %s: %d total IPs (after sub-queries)", city_name, len(all_ips))
    return all_ips, total_ips, cookies, user_agent


# ─── Progress Management ─────────────────────────────────────────────────────

def _save_progress_inline(state: dict, total_ips: int):
    """Save progress inline during sub-queries."""
    state["total_ips"] = total_ips
    with open(state["progress_file"], "w") as f:
        json.dump(state, f, indent=2)


def save_progress(
    progress_file, completed_countries, completed_cities,
    completed_subqueries, total_ips, query, with_ports=False, output_file=""
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
    """Load existing results from output file to avoid duplicates on resume.
    Returns (seen_results set, total_count)."""
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
    """Append new results to file and update seen set. Returns count of new entries written."""
    if not output_file or not new_entries:
        return 0
    actually_new = new_entries - seen_results
    if actually_new:
        with open(output_file, "a") as f:
            for entry in sorted(actually_new):
                f.write(entry + "\n")
        seen_results.update(actually_new)
    return len(actually_new)

# ─── IP Deduplication & Saving ───────────────────────────────────────────────

def save_results(output_file: str, new_results, seen_results: set) -> tuple:
    """Append new (deduplicated) results to file. Returns (new_count, total_seen)."""
    actually_new = set(new_results) - seen_results
    if actually_new:
        with open(output_file, "a") as f:
            for entry in sorted(actually_new):
                f.write(entry + "\n")
    seen_results.update(actually_new)
    return len(actually_new), len(seen_results)


# ─── Main ─────────────────────────────────────────────────────────────────────

def handle_interrupt(signum, frame):
    """Handle Ctrl+C gracefully - save progress before exit."""
    print("\n\n⚠️ Interrupted! Saving progress...")
    # The progress is saved incrementally, so data is safe
    print("✅ Progress saved. Use --resume to continue later.")
    raise SystemExit(0)


def main():
    import signal
    signal.signal(signal.SIGINT, handle_interrupt)
    parser = argparse.ArgumentParser(
        description="Shodan Facet IP Collector — aheybati Scanner v2.1",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  shodan_facet_collector.py -u user@email -p pass -q 'port:"22"'
  shodan_facet_collector.py -u user@email -p pass -q 'port:"22"' --exclude IR,US
  shodan_facet_collector.py -u user@email -p pass -q 'port:"80" product:"nginx"' -d 5 -o output.txt
  shodan_facet_collector.py -u user@email -p pass -q 'port:"22"' --resume
  shodan_facet_collector.py -u user@email -p pass -q 'product:"nginx"' --with-ports

Smart Sub-Query:
  When a city has 1000+ IPs (Shodan's facet limit), the tool automatically
  sub-queries by organization (org) and then by network (net) to extract
  nearly all IPs.

  With --with-ports, the tool also iterates over ports per city,
  producing IP:PORT output instead of plain IPs.

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
    parser.add_argument("-w", "--with-ports", action="store_true", help="Include port numbers in output (IP:PORT format)")
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
    print("  🔍 Shodan Facet IP Collector — aheybati Scanner v2.1")
    print("=" * 60)
    print(f"  👤 User:       {args.username}")
    print(f"  🔑 Query:      {query}")
    print(f"  📁 Output:     {output_file}")
    print(f"  ⏱️  Delay:      {delay}s")
    print(f"  🔄 Sub-query:  Enabled (org → net)")
    if with_ports:
        print(f"  🔌 With ports: YES (IP:PORT format)")
    if exclude_countries:
        print(f"  🚫 Exclude:    {', '.join(sorted(exclude_countries))}")
    print("=" * 60)

    # ── Login ──
    cookies, user_agent = login_shodan(args.username, args.password)
    if not cookies:
        log.error("Login failed! Exiting.")
        return
    # Save credentials for auto re-login on session expiry
    _login_state["username"] = args.username
    _login_state["password"] = args.password

    # ── Load progress ──
    completed_countries = set()
    completed_cities = {}
    completed_subqueries = set()
    total_ips = 0
    seen_results = set()

    if args.resume:
        progress = load_progress(PROGRESS_FILE, query)
        if progress:
            completed_countries = set(progress.get("completed_countries", []))
            completed_cities = progress.get("completed_cities", {})
            completed_subqueries = set(progress.get("completed_subqueries", []))
            # Determine the correct output file:
            # Priority: 1) saved in progress, 2) user -o argument, 3) default
            saved_output = progress.get("output_file")
            if saved_output and os.path.exists(saved_output):
                output_file = saved_output
                log.info("Using saved output file from progress: %s", output_file)
            # If user explicitly passed -o, that takes priority
            if args.output:
                output_file = args.output
                log.info("Using -o output file: %s", output_file)
            # Load existing results to avoid duplicates
            seen_results = load_seen_results(output_file)
            total_ips = len(seen_results)
            log.info("Resuming: %d countries done, %d results collected so far", len(completed_countries), total_ips)
            log.info("Output file: %s (%d existing entries)", output_file, len(seen_results))
        else:
            log.warning("No matching progress file found. Starting fresh.")

    if not os.path.exists(output_file):
        open(output_file, "w").close()

    # ── Step 1: Get countries ──
    countries, cookies, user_agent = get_countries(cookies, user_agent, query)
    if not countries:
        log.error("No countries found! Exiting.")
        return

    if exclude_countries:
        before = len(countries)
        countries = [(code, name) for code, name in countries if code not in exclude_countries]
        excluded_count = before - len(countries)
        log.info("Excluded %d countries: %s", excluded_count, ", ".join(sorted(exclude_countries)))
        log.info("Scanning %d countries", len(countries))

    print(f"\n🚀 Starting scan of {len(countries)} countries...")

    # ── Step 2: Iterate countries → cities → IPs (or IP:PORTs) ──
    for country_code, country_name in countries:
        if country_code in completed_countries:
            log.info("⏭️ Skipping %s — already completed", country_code)
            continue

        print(f"\n{'=' * 60}")
        print(f"🏴 Processing country: {country_code} ({country_name})")
        print(f"{'=' * 60}")

        cities, cookies, user_agent = get_cities(cookies, user_agent, query, country_code)
        log.info("Found %d cities in %s", len(cities), country_code)

        if not cities:
            log.warning("No cities found, skipping...")
            completed_countries.add(country_code)
            save_progress(PROGRESS_FILE, completed_countries, completed_cities,
                         completed_subqueries, total_ips, query, with_ports, output_file)
            continue

        if len(cities) >= FACET_CAP:
            log.warning("⚠️ Country %s hit %d city cap → sub-querying by org...", country_code, FACET_CAP)
            orgs_for_country, cookies, user_agent = get_orgs(cookies, user_agent, query, country_code, "")
            log.info("  🏢 Found %d organizations in %s (city cap fallback)", len(orgs_for_country), country_code)
            if orgs_for_country:
                # Get city lists per org and merge unique cities
                extra_cities = set(cities)
                for org in orgs_for_country:
                    time.sleep(delay)
                    org_city_url = build_facet_url(query, "city", extra_filters={"country": country_code, "org": org})
                    org_city_html, cookies, user_agent = shodan_get(org_city_url, cookies, user_agent)
                    if org_city_html:
                        org_city_results = parse_facet_links(org_city_html, r'city%3A%22(.+?)%22')
                        if not org_city_results:
                            org_city_results = parse_facet_links(org_city_html, r'city[^A-Za-z]*"(.+?)"')
                        for city_val, _ in org_city_results:
                            if city_val not in extra_cities:
                                extra_cities.add(city_val)
                                cities.append(city_val)
                log.info("  ✅ After org sub-query: %d cities total", len(cities))

        for city in cities:
            city_list = completed_cities.get(country_code, [])
            if city in city_list:
                log.info("  ⏭️ Skipping %s — already completed", city)
                continue

            print(f"  📍 {city}...", end=" ", flush=True)

            ports_for_city = None
            if with_ports:
                time.sleep(delay)
                city_filters = {"country": country_code, "city": city}
                ports_for_city, cookies, user_agent = get_ports(cookies, user_agent, query, city_filters)
                log.info("    🔌 Found %d ports in %s", len(ports_for_city), city)

            time.sleep(delay)

            progress_state = {
                "progress_file": PROGRESS_FILE,
                "completed_countries": list(completed_countries),
                "completed_cities": {k: v for k, v in completed_cities.items()},
                "completed_subqueries": list(completed_subqueries),
                "query": query,
            }

            new_results, total_ips, cookies, user_agent = extract_ips_smart(
                cookies, user_agent, query, country_code, city,
                total_ips, delay, completed_subqueries, progress_state,
                output_file=output_file, seen_results=seen_results,
                with_ports=with_ports, ports_for_city=ports_for_city,
            )

            # Results are already saved incrementally, but do a final dedup save
            new_count, total_seen = save_results(output_file, new_results, seen_results)
            total_ips = total_seen

            cities_done = sum(len(v) for v in completed_cities.values())
            if with_ports:
                print(f"{len(new_results)} IP:PORT (new: {new_count}, total: {total_seen}, cities: {cities_done})")
            else:
                print(f"{len(new_results)} IPs (new: {new_count}, total: {total_seen}, cities: {cities_done})")

            if country_code not in completed_cities:
                completed_cities[country_code] = []
            completed_cities[country_code].append(city)

            save_progress(PROGRESS_FILE, completed_countries, completed_cities,
                         completed_subqueries, total_ips, query, with_ports, output_file)

        completed_countries.add(country_code)
        save_progress(PROGRESS_FILE, completed_countries, completed_cities,
                     completed_subqueries, total_ips, query, with_ports, output_file)
        print(f"  ✅ Country {country_code} done!")

    # ── Done ──
    result_label = "IP:PORT entries" if with_ports else "unique IPs"
    total_countries_done = len(completed_countries)
    total_cities_done = sum(len(v) for v in completed_cities.values())
    print(f"\n{'=' * 60}")
    print(f"🏁 ALL DONE!")
    print(f"📊 Total {result_label} collected: {len(seen_results)}")
    print(f"🌍 Countries scanned: {total_countries_done}")
    print(f"🏙️ Cities scanned: {total_cities_done}")
    print(f"📁 Saved to: {output_file}")


if __name__ == "__main__":
    main()
