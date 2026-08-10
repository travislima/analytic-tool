#!/usr/bin/env python3
"""
Plainsight — a tiny, privacy-first web analytics server. One process, one
SQLite file, zero dependencies (Python 3.9+ standard library only).

  python3 app.py            # serves ingest + dashboard on PORT (default 8000)

Privacy model
-------------
* No cookies, no client-side IDs, no fingerprinting.
* Visitors are counted with a hash of (daily random salt + site + IP + UA),
  computed server-side. The salt rotates every day and old salts are deleted,
  so yesterday's hashes can never be linked to a person. Raw IPs are never
  written anywhere.
* Country comes from the browser's timezone (sent by the snippet) or a
  CDN-provided country header — no GeoIP database, no IP geolocation.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import threading
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------- #
# Configuration (.env, overridable by real environment variables)
# --------------------------------------------------------------------------- #

def load_env(path):
    env = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                env[key.strip()] = val.strip().strip("'\"")
    except OSError:
        pass
    return env

ENV = load_env(os.path.join(BASE_DIR, ".env"))
ENV.update(os.environ)

HOST = ENV.get("HOST", "0.0.0.0")
PORT = int(ENV.get("PORT", "8000"))
DB_PATH = ENV.get("DB_PATH", os.path.join(BASE_DIR, "analytics.db"))
DASH_USER = ENV.get("DASH_USER", "")
DASH_PASS = ENV.get("DASH_PASS", "")

SESSION_GAP = 30 * 60          # a visit ends after 30 idle minutes
MAX_BODY = 4096                # ingest payload cap, bytes

# --------------------------------------------------------------------------- #
# Bot filtering (obvious bots by user-agent; empty UA is treated as a bot)
# --------------------------------------------------------------------------- #

BOT_RE = re.compile(
    r"bot|crawl|spider|slurp|preview|headless|phantom|selenium|playwright|"
    r"python|curl|wget|go-http|java/|libwww|httpclient|okhttp|scrapy|"
    r"facebookexternalhit|whatsapp|telegram|discord|embedly|quora link|"
    r"monitor|pingdom|uptime|statuscake|lighthouse|gtmetrix|pagespeed|"
    r"ahrefs|semrush|mj12|dotbot|petalbot|yandex|baiduspider|bytespider|"
    r"duckduckgo|sogou|exabot|ia_archiver|archive\.org|feedfetcher|feedburner",
    re.I,
)

def is_bot(ua):
    return not ua or bool(BOT_RE.search(ua))

# --------------------------------------------------------------------------- #
# Screen classes
# --------------------------------------------------------------------------- #

def screen_class(width):
    try:
        w = int(width)
    except (TypeError, ValueError):
        return "Unknown"
    if w <= 0:
        return "Unknown"
    if w < 576:
        return "Mobile"
    if w < 992:
        return "Tablet"
    if w < 1440:
        return "Laptop"
    return "Desktop"

# --------------------------------------------------------------------------- #
# Country from browser timezone (privacy-friendly: no IP geolocation).
# A CDN country header (Cloudflare's CF-IPCountry etc.) wins when present.
# --------------------------------------------------------------------------- #

TZ_PREFIX = {
    "America/Argentina/": "AR", "America/Indiana/": "US", "America/Kentucky/": "US",
    "America/North_Dakota/": "US", "Australia/": "AU",
}

TZ_COUNTRY = {
    # North America
    "America/New_York": "US", "America/Chicago": "US", "America/Denver": "US",
    "America/Los_Angeles": "US", "America/Phoenix": "US", "America/Anchorage": "US",
    "America/Detroit": "US", "America/Boise": "US", "America/Juneau": "US",
    "Pacific/Honolulu": "US", "America/Adak": "US",
    "America/Toronto": "CA", "America/Vancouver": "CA", "America/Edmonton": "CA",
    "America/Winnipeg": "CA", "America/Halifax": "CA", "America/St_Johns": "CA",
    "America/Regina": "CA", "America/Montreal": "CA", "America/Moncton": "CA",
    "America/Mexico_City": "MX", "America/Tijuana": "MX", "America/Monterrey": "MX",
    "America/Cancun": "MX", "America/Merida": "MX", "America/Chihuahua": "MX",
    "America/Hermosillo": "MX", "America/Mazatlan": "MX",
    # Central America & Caribbean
    "America/Guatemala": "GT", "America/El_Salvador": "SV", "America/Tegucigalpa": "HN",
    "America/Managua": "NI", "America/Costa_Rica": "CR", "America/Panama": "PA",
    "America/Havana": "CU", "America/Santo_Domingo": "DO", "America/Puerto_Rico": "PR",
    "America/Jamaica": "JM", "America/Port-au-Prince": "HT", "America/Barbados": "BB",
    "America/Nassau": "BS", "America/Port_of_Spain": "TT",
    # South America
    "America/Sao_Paulo": "BR", "America/Fortaleza": "BR", "America/Recife": "BR",
    "America/Manaus": "BR", "America/Bahia": "BR", "America/Belem": "BR",
    "America/Campo_Grande": "BR", "America/Cuiaba": "BR", "America/Porto_Velho": "BR",
    "America/Rio_Branco": "BR", "America/Araguaina": "BR", "America/Maceio": "BR",
    "America/Santarem": "BR", "America/Boa_Vista": "BR", "America/Noronha": "BR",
    "America/Bogota": "CO", "America/Lima": "PE", "America/Santiago": "CL",
    "America/Punta_Arenas": "CL", "America/Caracas": "VE", "America/La_Paz": "BO",
    "America/Montevideo": "UY", "America/Asuncion": "PY", "America/Guayaquil": "EC",
    "America/Cayenne": "GF", "America/Paramaribo": "SR", "America/Guyana": "GY",
    # Europe
    "Europe/London": "GB", "Europe/Dublin": "IE", "Europe/Paris": "FR",
    "Europe/Berlin": "DE", "Europe/Madrid": "ES", "Europe/Rome": "IT",
    "Europe/Amsterdam": "NL", "Europe/Brussels": "BE", "Europe/Vienna": "AT",
    "Europe/Zurich": "CH", "Europe/Stockholm": "SE", "Europe/Oslo": "NO",
    "Europe/Copenhagen": "DK", "Europe/Helsinki": "FI", "Europe/Warsaw": "PL",
    "Europe/Prague": "CZ", "Europe/Budapest": "HU", "Europe/Bucharest": "RO",
    "Europe/Sofia": "BG", "Europe/Athens": "GR", "Europe/Lisbon": "PT",
    "Europe/Kyiv": "UA", "Europe/Kiev": "UA", "Europe/Moscow": "RU",
    "Europe/Istanbul": "TR", "Europe/Belgrade": "RS", "Europe/Zagreb": "HR",
    "Europe/Ljubljana": "SI", "Europe/Bratislava": "SK", "Europe/Vilnius": "LT",
    "Europe/Riga": "LV", "Europe/Tallinn": "EE", "Europe/Minsk": "BY",
    "Europe/Chisinau": "MD", "Europe/Luxembourg": "LU", "Europe/Monaco": "MC",
    "Europe/Malta": "MT", "Europe/Sarajevo": "BA", "Europe/Skopje": "MK",
    "Europe/Tirane": "AL", "Europe/Andorra": "AD", "Europe/Gibraltar": "GI",
    "Atlantic/Reykjavik": "IS", "Atlantic/Canary": "ES", "Atlantic/Madeira": "PT",
    "Atlantic/Azores": "PT", "Europe/Kaliningrad": "RU", "Europe/Samara": "RU",
    # Asia & Middle East
    "Asia/Tokyo": "JP", "Asia/Seoul": "KR", "Asia/Shanghai": "CN",
    "Asia/Urumqi": "CN", "Asia/Hong_Kong": "HK", "Asia/Macau": "MO",
    "Asia/Taipei": "TW", "Asia/Singapore": "SG", "Asia/Kuala_Lumpur": "MY",
    "Asia/Jakarta": "ID", "Asia/Makassar": "ID", "Asia/Jayapura": "ID",
    "Asia/Bangkok": "TH", "Asia/Ho_Chi_Minh": "VN", "Asia/Saigon": "VN",
    "Asia/Manila": "PH", "Asia/Kolkata": "IN", "Asia/Calcutta": "IN",
    "Asia/Karachi": "PK", "Asia/Dhaka": "BD", "Asia/Colombo": "LK",
    "Asia/Kathmandu": "NP", "Asia/Yangon": "MM", "Asia/Phnom_Penh": "KH",
    "Asia/Vientiane": "LA", "Asia/Dubai": "AE", "Asia/Riyadh": "SA",
    "Asia/Qatar": "QA", "Asia/Kuwait": "KW", "Asia/Bahrain": "BH",
    "Asia/Muscat": "OM", "Asia/Tehran": "IR", "Asia/Baghdad": "IQ",
    "Asia/Jerusalem": "IL", "Asia/Tel_Aviv": "IL", "Asia/Amman": "JO",
    "Asia/Beirut": "LB", "Asia/Damascus": "SY", "Asia/Baku": "AZ",
    "Asia/Yerevan": "AM", "Asia/Tbilisi": "GE", "Asia/Almaty": "KZ",
    "Asia/Tashkent": "UZ", "Asia/Bishkek": "KG", "Asia/Dushanbe": "TJ",
    "Asia/Ashgabat": "TM", "Asia/Kabul": "AF", "Asia/Ulaanbaatar": "MN",
    "Asia/Novosibirsk": "RU", "Asia/Yekaterinburg": "RU", "Asia/Vladivostok": "RU",
    "Asia/Krasnoyarsk": "RU", "Asia/Irkutsk": "RU", "Asia/Omsk": "RU",
    "Asia/Nicosia": "CY", "Asia/Brunei": "BN",
    # Africa
    "Africa/Cairo": "EG", "Africa/Lagos": "NG", "Africa/Johannesburg": "ZA",
    "Africa/Nairobi": "KE", "Africa/Casablanca": "MA", "Africa/Algiers": "DZ",
    "Africa/Tunis": "TN", "Africa/Tripoli": "LY", "Africa/Accra": "GH",
    "Africa/Abidjan": "CI", "Africa/Dakar": "SN", "Africa/Addis_Ababa": "ET",
    "Africa/Dar_es_Salaam": "TZ", "Africa/Kampala": "UG", "Africa/Khartoum": "SD",
    "Africa/Kinshasa": "CD", "Africa/Luanda": "AO", "Africa/Harare": "ZW",
    "Africa/Lusaka": "ZM", "Africa/Maputo": "MZ", "Africa/Gaborone": "BW",
    "Africa/Windhoek": "NA", "Africa/Kigali": "RW", "Africa/Bamako": "ML",
    # Oceania
    "Pacific/Auckland": "NZ", "Pacific/Fiji": "FJ", "Pacific/Guam": "GU",
    "Pacific/Port_Moresby": "PG", "Pacific/Tahiti": "PF", "Pacific/Noumea": "NC",
}

COUNTRY_NAMES = {
    "US": "United States", "CA": "Canada", "MX": "Mexico", "BR": "Brazil",
    "AR": "Argentina", "CO": "Colombia", "PE": "Peru", "CL": "Chile",
    "VE": "Venezuela", "BO": "Bolivia", "UY": "Uruguay", "PY": "Paraguay",
    "EC": "Ecuador", "GT": "Guatemala", "SV": "El Salvador", "HN": "Honduras",
    "NI": "Nicaragua", "CR": "Costa Rica", "PA": "Panama", "CU": "Cuba",
    "DO": "Dominican Republic", "PR": "Puerto Rico", "JM": "Jamaica",
    "HT": "Haiti", "BB": "Barbados", "BS": "Bahamas", "TT": "Trinidad & Tobago",
    "GF": "French Guiana", "SR": "Suriname", "GY": "Guyana",
    "GB": "United Kingdom", "IE": "Ireland", "FR": "France", "DE": "Germany",
    "ES": "Spain", "IT": "Italy", "NL": "Netherlands", "BE": "Belgium",
    "AT": "Austria", "CH": "Switzerland", "SE": "Sweden", "NO": "Norway",
    "DK": "Denmark", "FI": "Finland", "PL": "Poland", "CZ": "Czechia",
    "HU": "Hungary", "RO": "Romania", "BG": "Bulgaria", "GR": "Greece",
    "PT": "Portugal", "UA": "Ukraine", "RU": "Russia", "TR": "Türkiye",
    "RS": "Serbia", "HR": "Croatia", "SI": "Slovenia", "SK": "Slovakia",
    "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia", "BY": "Belarus",
    "MD": "Moldova", "LU": "Luxembourg", "MC": "Monaco", "MT": "Malta",
    "BA": "Bosnia & Herzegovina", "MK": "North Macedonia", "AL": "Albania",
    "AD": "Andorra", "GI": "Gibraltar", "IS": "Iceland", "CY": "Cyprus",
    "JP": "Japan", "KR": "South Korea", "CN": "China", "HK": "Hong Kong",
    "MO": "Macao", "TW": "Taiwan", "SG": "Singapore", "MY": "Malaysia",
    "ID": "Indonesia", "TH": "Thailand", "VN": "Vietnam", "PH": "Philippines",
    "IN": "India", "PK": "Pakistan", "BD": "Bangladesh", "LK": "Sri Lanka",
    "NP": "Nepal", "MM": "Myanmar", "KH": "Cambodia", "LA": "Laos",
    "AE": "United Arab Emirates", "SA": "Saudi Arabia", "QA": "Qatar",
    "KW": "Kuwait", "BH": "Bahrain", "OM": "Oman", "IR": "Iran", "IQ": "Iraq",
    "IL": "Israel", "JO": "Jordan", "LB": "Lebanon", "SY": "Syria",
    "AZ": "Azerbaijan", "AM": "Armenia", "GE": "Georgia", "KZ": "Kazakhstan",
    "UZ": "Uzbekistan", "KG": "Kyrgyzstan", "TJ": "Tajikistan",
    "TM": "Turkmenistan", "AF": "Afghanistan", "MN": "Mongolia", "BN": "Brunei",
    "EG": "Egypt", "NG": "Nigeria", "ZA": "South Africa", "KE": "Kenya",
    "MA": "Morocco", "DZ": "Algeria", "TN": "Tunisia", "LY": "Libya",
    "GH": "Ghana", "CI": "Côte d'Ivoire", "SN": "Senegal", "ET": "Ethiopia",
    "TZ": "Tanzania", "UG": "Uganda", "SD": "Sudan", "CD": "DR Congo",
    "AO": "Angola", "ZW": "Zimbabwe", "ZM": "Zambia", "MZ": "Mozambique",
    "BW": "Botswana", "NA": "Namibia", "RW": "Rwanda", "ML": "Mali",
    "AU": "Australia", "NZ": "New Zealand", "FJ": "Fiji", "GU": "Guam",
    "PG": "Papua New Guinea", "PF": "French Polynesia", "NC": "New Caledonia",
    "AQ": "Antarctica",
}

def country_from(tz, headers):
    cc = (headers.get("CF-IPCountry") or headers.get("X-Country") or "").strip().upper()
    if len(cc) == 2 and cc.isalpha() and cc != "XX":
        return cc
    tz = (tz or "").strip()
    if tz in TZ_COUNTRY:
        return TZ_COUNTRY[tz]
    for prefix, code in TZ_PREFIX.items():
        if tz.startswith(prefix):
            return code
    return ""

def country_label(cc):
    return COUNTRY_NAMES.get(cc, cc) if cc else "Unknown"

def country_flag(cc):
    if len(cc) == 2 and cc.isalpha() and cc.isupper():
        return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)
    return "\U0001F310"  # globe for unknown

# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

_local = threading.local()

def db():
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.conn = conn
    return conn

def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id       INTEGER PRIMARY KEY,
            site     TEXT NOT NULL,
            ts       INTEGER NOT NULL,          -- unix seconds
            date     TEXT NOT NULL,             -- YYYY-MM-DD, server-local
            hour     INTEGER NOT NULL,          -- 0-23, server-local
            visitor  TEXT NOT NULL,             -- daily-rotating hash, never an IP
            path     TEXT NOT NULL,
            referrer TEXT NOT NULL DEFAULT '',  -- external referrer hostname only
            screen   TEXT NOT NULL DEFAULT 'Unknown',
            country  TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_events_site_date ON events (site, date);

        CREATE TABLE IF NOT EXISTS salts (
            day  TEXT PRIMARY KEY,
            salt BLOB NOT NULL
        );
        """
    )
    conn.commit()

# --------------------------------------------------------------------------- #
# Daily-rotating visitor hash (never store raw IPs)
# --------------------------------------------------------------------------- #

_salt_lock = threading.Lock()
_salt_cache = {"day": None, "salt": None}

def daily_salt(today):
    with _salt_lock:
        if _salt_cache["day"] == today:
            return _salt_cache["salt"]
        conn = db()
        row = conn.execute("SELECT salt FROM salts WHERE day = ?", (today,)).fetchone()
        if row:
            salt = row["salt"]
        else:
            salt = secrets.token_bytes(32)
            conn.execute("INSERT OR IGNORE INTO salts (day, salt) VALUES (?, ?)", (today, salt))
            # forget old salts so past hashes can never be re-linked to anyone
            conn.execute("DELETE FROM salts WHERE day < ?", (today,))
            conn.commit()
            row = conn.execute("SELECT salt FROM salts WHERE day = ?", (today,)).fetchone()
            salt = row["salt"]
        _salt_cache["day"] = today
        _salt_cache["salt"] = salt
        return salt

def visitor_hash(today, site, ip, ua):
    digest = hashlib.sha256()
    digest.update(daily_salt(today))
    digest.update(site.encode())
    digest.update(b"|")
    digest.update(ip.encode())
    digest.update(b"|")
    digest.update(ua.encode("utf-8", "replace"))
    return digest.hexdigest()[:16]

def client_ip(handler):
    fwd = handler.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return handler.client_address[0]

# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #

SITE_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{0,100}$")

def ingest(handler, body):
    ua = handler.headers.get("User-Agent", "")
    if is_bot(ua):
        return
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return
    if not isinstance(data, dict):
        return
    site = str(data.get("s", "")).strip().lower()
    if not SITE_RE.match(site):
        return
    path = str(data.get("p", "/"))[:512]
    if not path.startswith("/"):
        path = "/" + path
    path = path.split("?", 1)[0].split("#", 1)[0] or "/"

    # keep only the hostname of *external* referrers
    referrer = ""
    raw_ref = str(data.get("r", ""))[:1024]
    if raw_ref:
        try:
            ref_host = (urlparse(raw_ref).hostname or "").lower().removeprefix("www.")
        except ValueError:
            ref_host = ""
        origin = str(handler.headers.get("Origin", ""))
        try:
            origin_host = (urlparse(origin).hostname or "").lower().removeprefix("www.")
        except ValueError:
            origin_host = ""
        if ref_host and ref_host not in (origin_host, site):
            referrer = ref_host

    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    visitor = visitor_hash(today, site, client_ip(handler), ua)
    conn = db()
    conn.execute(
        "INSERT INTO events (site, ts, date, hour, visitor, path, referrer, screen, country)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            site,
            int(now.timestamp()),
            today,
            now.hour,
            visitor,
            path,
            referrer,
            screen_class(data.get("w")),
            country_from(data.get("tz"), handler.headers),
        ),
    )
    conn.commit()

# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #

RANGES = {
    "today": ("Today", 1),
    "7d": ("Last 7 days", 7),
    "30d": ("Last 30 days", 30),
}

def range_dates(key):
    """Returns (start, end, prev_start, prev_end) as YYYY-MM-DD strings."""
    days = RANGES[key][1]
    end = date.today()
    start = end - timedelta(days=days - 1)
    prev_end = start - timedelta(days=1)
    prev_start = prev_end - timedelta(days=days - 1)
    iso = lambda d: d.strftime("%Y-%m-%d")
    return iso(start), iso(end), iso(prev_start), iso(prev_end)

def totals(site, start, end):
    row = db().execute(
        "SELECT COUNT(DISTINCT visitor) AS visitors, COUNT(*) AS pageviews"
        " FROM events WHERE site = ? AND date BETWEEN ? AND ?",
        (site, start, end),
    ).fetchone()
    return row["visitors"], row["pageviews"]

def visit_stats(site, start, end):
    """Sessionization: a visit ends after SESSION_GAP idle seconds.
    Returns (visits, bounce_rate_pct or None, avg_duration_secs or None)."""
    row = db().execute(
        """
        WITH flagged AS (
            SELECT visitor, ts,
                   CASE WHEN LAG(ts) OVER w IS NULL
                             OR ts - LAG(ts) OVER w > :gap
                        THEN 1 ELSE 0 END AS starts
            FROM events
            WHERE site = :site AND date BETWEEN :start AND :end
            WINDOW w AS (PARTITION BY visitor ORDER BY ts)
        ),
        numbered AS (
            SELECT visitor, ts,
                   SUM(starts) OVER (PARTITION BY visitor ORDER BY ts) AS visit_no
            FROM flagged
        ),
        visits AS (
            SELECT COUNT(*) AS views, MAX(ts) - MIN(ts) AS duration
            FROM numbered GROUP BY visitor, visit_no
        )
        SELECT COUNT(*) AS visits,
               SUM(views = 1) AS bounces,
               AVG(duration) AS avg_duration
        FROM visits
        """,
        {"gap": SESSION_GAP, "site": site, "start": start, "end": end},
    ).fetchone()
    visits = row["visits"] or 0
    if visits == 0:
        return 0, None, None
    return visits, 100.0 * row["bounces"] / visits, row["avg_duration"]

def visitors_by_day(site, start, end):
    rows = db().execute(
        "SELECT date, COUNT(DISTINCT visitor) AS visitors FROM events"
        " WHERE site = ? AND date BETWEEN ? AND ? GROUP BY date",
        (site, start, end),
    ).fetchall()
    by_date = {r["date"]: r["visitors"] for r in rows}
    out = []
    d = datetime.strptime(start, "%Y-%m-%d").date()
    last = datetime.strptime(end, "%Y-%m-%d").date()
    while d <= last:
        iso = d.strftime("%Y-%m-%d")
        out.append((iso, by_date.get(iso, 0)))
        d += timedelta(days=1)
    return out

def visitors_by_hour(site, day):
    rows = db().execute(
        "SELECT hour, COUNT(DISTINCT visitor) AS visitors FROM events"
        " WHERE site = ? AND date = ? GROUP BY hour",
        (site, day),
    ).fetchall()
    by_hour = {r["hour"]: r["visitors"] for r in rows}
    return [(h, by_hour.get(h, 0)) for h in range(24)]

def breakdown(site, column, start, end, limit=10):
    assert column in ("path", "referrer", "country", "screen")
    return db().execute(
        f"SELECT {column} AS key, COUNT(DISTINCT visitor) AS visitors,"
        f" COUNT(*) AS pageviews FROM events"
        f" WHERE site = ? AND date BETWEEN ? AND ?"
        f" GROUP BY {column} ORDER BY visitors DESC, pageviews DESC LIMIT ?",
        (site, start, end, limit),
    ).fetchall()

def known_sites():
    return [r["site"] for r in db().execute("SELECT DISTINCT site FROM events ORDER BY site")]

# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #

def fmt_int(n):
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}".rstrip("0").rstrip(".") + "M"
    if n >= 10_000:
        return f"{n / 1000:.1f}".rstrip("0").rstrip(".") + "K"
    return f"{n:,}"

def fmt_duration(secs):
    if secs is None:
        return "–"
    secs = int(round(secs))
    if secs < 60:
        return f"{secs}s"
    return f"{secs // 60}m {secs % 60:02d}s"

def pct_change(current, previous):
    if previous in (None, 0):
        return None
    return 100.0 * (current - previous) / previous

def esc(text):
    return html.escape(str(text), quote=True)

# --------------------------------------------------------------------------- #
# Inline SVG bar chart (single series — visitors per day/hour)
# --------------------------------------------------------------------------- #

def nice_ticks(max_value):
    if max_value <= 0:
        return [0, 1, 2, 3, 4], 4
    target = 4
    raw = max_value / target
    magnitude = 10 ** len(str(int(raw))) / 10 if raw >= 1 else 1
    step = 1
    for mult in (1, 2, 5, 10):
        step = mult * magnitude
        if step * target >= max_value:
            break
    top = step * target
    while top < max_value:
        top += step
    ticks = []
    v = 0
    while v <= top:
        ticks.append(int(v))
        v += step
    return ticks, ticks[-1]

def svg_bar_chart(buckets, x_labels, label_every, peak_note):
    """buckets: list of (tooltip_label, value). Returns inline SVG + hover JS hooks."""
    W, H = 860, 250
    pad_l, pad_r, pad_t, pad_b = 46, 14, 22, 28
    plot_w, plot_h = W - pad_l - pad_r, H - pad_t - pad_b
    base_y = pad_t + plot_h

    values = [v for _, v in buckets]
    max_v = max(values) if values else 0
    ticks, top = nice_ticks(max_v)

    n = len(buckets)
    slot = plot_w / n
    bar_w = min(24.0, slot - 2)  # ≤24px thick, ≥2px air between neighbours
    if bar_w < 3:
        bar_w = slot * 0.8

    parts = []
    # hairline gridlines + y tick labels (skip 0 gridline; the baseline covers it)
    for tick in ticks:
        y = base_y - (tick / top) * plot_h if top else base_y
        if tick:
            parts.append(
                f'<line x1="{pad_l}" y1="{y:.1f}" x2="{W - pad_r}" y2="{y:.1f}" class="grid"/>'
            )
        parts.append(
            f'<text x="{pad_l - 8}" y="{y + 4:.1f}" class="tick" text-anchor="end">{fmt_int(tick)}</text>'
        )
    parts.append(f'<line x1="{pad_l}" y1="{base_y}" x2="{W - pad_r}" y2="{base_y}" class="axis"/>')

    peak_idx = values.index(max_v) if max_v > 0 else -1
    bars, hits = [], []
    for i, (tip_label, value) in enumerate(buckets):
        cx = pad_l + slot * i + slot / 2
        x = cx - bar_w / 2
        h = (value / top) * plot_h if top else 0
        y = base_y - h
        r = min(4.0, bar_w / 2, h)
        if h > 0:
            # rounded data-end at the top, square at the baseline
            bars.append(
                f'<path id="bar{i}" class="bar" d="M{x:.1f},{base_y:.1f} '
                f'V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} '
                f'H{x + bar_w - r:.1f} Q{x + bar_w:.1f},{y:.1f} {x + bar_w:.1f},{y + r:.1f} '
                f'V{base_y:.1f} Z"/>'
            )
        if i == peak_idx:
            parts.append(
                f'<text x="{cx:.1f}" y="{y - 7:.1f}" class="peak" text-anchor="middle">{fmt_int(value)}</text>'
            )
        # full-height transparent hit target, keyboard-focusable
        hits.append(
            f'<rect class="hit" x="{pad_l + slot * i:.1f}" y="{pad_t}" width="{slot:.1f}" '
            f'height="{plot_h}" data-i="{i}" data-l="{esc(tip_label)}" data-v="{value}" '
            f'tabindex="0" role="img" aria-label="{esc(tip_label)}: {value} visitors"/>'
        )
        if i % label_every == 0 and x_labels[i]:
            parts.append(
                f'<text x="{cx:.1f}" y="{H - 8}" class="tick" text-anchor="middle">{esc(x_labels[i])}</text>'
            )

    return (
        f'<div class="chartwrap"><svg viewBox="0 0 {W} {H}" role="img" '
        f'aria-label="{esc(peak_note)}" preserveAspectRatio="xMidYMid meet">'
        + "".join(parts) + "".join(bars) + "".join(hits)
        + '</svg><div class="tooltip" id="tip" hidden><strong id="tipv"></strong><span id="tipl"></span></div></div>'
    )

# --------------------------------------------------------------------------- #
# Dashboard HTML
# --------------------------------------------------------------------------- #

CSS = """
:root {
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19;
  --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835;
  --border: rgba(255,255,255,0.10);
  --series: #3987e5; --series-hot: #5598e7;
  --wash: rgba(57,135,229,0.16);
  --good: #0ca30c; --bad: #e66767;
  --chip: rgba(255,255,255,0.06);
}
:root[data-theme="light"] {
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb;
  --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7;
  --border: rgba(11,11,11,0.10);
  --series: #2a78d6; --series-hot: #5598e7;
  --wash: rgba(42,120,214,0.14);
  --good: #006300; --bad: #d03b3b;
  --chip: rgba(11,11,11,0.05);
}
* { box-sizing: border-box; }
body {
  margin: 0; overflow-x: clip; background: var(--page); color: var(--ink);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
}
a { color: inherit; }
.wrap { max-width: 1060px; margin: 0 auto; padding: 24px 20px 56px; }
header { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; }
.logo { width: 12px; height: 12px; border-radius: 50%; background: var(--series); box-shadow: 0 0 0 4px var(--wash); }
h1 { font-size: 18px; font-weight: 650; margin: 0; letter-spacing: .01em; }
h1 small { color: var(--muted); font-weight: 450; margin-left: 6px; }
.spacer { flex: 1; }
.themebtn {
  background: var(--chip); color: var(--ink-2); border: 1px solid var(--border);
  border-radius: 8px; padding: 5px 11px; font: inherit; font-size: 13px; cursor: pointer;
}
.filters { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 20px; }
.seg { display: inline-flex; background: var(--chip); border: 1px solid var(--border); border-radius: 10px; padding: 3px; }
.seg a {
  padding: 5px 14px; border-radius: 7px; text-decoration: none;
  color: var(--ink-2); font-size: 13.5px; font-weight: 500;
}
.seg a.on { background: var(--surface); color: var(--ink); border: 1px solid var(--border); font-weight: 600; }
select.site {
  background: var(--chip); color: var(--ink); border: 1px solid var(--border);
  border-radius: 10px; padding: 7px 12px; font: inherit; font-size: 13.5px;
}
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; margin-bottom: 14px; }
.tile { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px 14px; }
.tile .label { color: var(--ink-2); font-size: 13px; font-weight: 550; }
.tile .value { font-size: 34px; font-weight: 650; line-height: 1.15; margin: 2px 0 1px; }
.tile .delta { font-size: 12.5px; font-weight: 600; }
.tile .delta.up { color: var(--good); }
.tile .delta.down { color: var(--bad); }
.tile .delta.flat { color: var(--muted); font-weight: 500; }
.tile .why { color: var(--muted); font-size: 12px; line-height: 1.45; margin-top: 7px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 18px 20px; margin-bottom: 14px; }
.card h2 { font-size: 14.5px; font-weight: 650; margin: 0; }
.card .sub { color: var(--muted); font-size: 12.5px; margin: 2px 0 14px; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
.grid2 > .card, .tiles > .tile { min-width: 0; }
.chartwrap { position: relative; overflow-x: auto; }
.chartwrap svg { width: 100%; min-width: 640px; height: auto; display: block; }
.bar { fill: var(--series); }
.bar.hot { fill: var(--series-hot); }
.hit { fill: transparent; cursor: pointer; outline: none; }
.hit:focus-visible { fill: var(--wash); }
.grid { stroke: var(--grid); stroke-width: 1; }
.axis { stroke: var(--axis); stroke-width: 1; }
.tick { fill: var(--muted); font-size: 11.5px; font-variant-numeric: tabular-nums; }
.peak { fill: var(--ink-2); font-size: 12px; font-weight: 600; }
.tooltip {
  position: absolute; pointer-events: none; background: var(--page);
  border: 1px solid var(--border); border-radius: 9px; padding: 7px 11px;
  font-size: 12.5px; white-space: nowrap; box-shadow: 0 6px 18px rgba(0,0,0,.25);
  transform: translate(-50%, calc(-100% - 10px)); z-index: 5;
}
.tooltip strong { display: block; font-size: 14px; }
.tooltip span { color: var(--ink-2); }
table.list { width: 100%; border-collapse: collapse; font-size: 13.5px; table-layout: fixed; }
table.list th.num, table.list td.num { width: 24%; }
table.list th {
  text-align: left; color: var(--muted); font-size: 11.5px; font-weight: 550;
  text-transform: uppercase; letter-spacing: .05em; padding: 0 0 8px;
}
table.list th.num, table.list td.num {
  text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; padding-left: 12px;
}
table.list td { padding: 5px 0; }
.rowbar { position: relative; padding: 4px 9px; border-radius: 6px; overflow: hidden; }
.rowbar i {
  position: absolute; inset: 0; background: var(--wash); border-radius: 6px;
  transform-origin: left; z-index: 0;
}
.rowbar span { position: relative; z-index: 1; overflow-wrap: anywhere; }
.share { color: var(--muted); }
details.twin { margin-top: 12px; }
details.twin summary, details.explain summary { cursor: pointer; color: var(--ink-2); font-size: 13px; }
details.twin table { margin-top: 10px; max-width: 460px; }
.explain dt { font-weight: 650; margin-top: 12px; }
.explain dd { margin: 2px 0 0; color: var(--ink-2); }
.empty { text-align: center; padding: 40px 20px; color: var(--ink-2); }
.empty h2 { color: var(--ink); }
pre.snippet {
  text-align: left; background: var(--chip); border: 1px solid var(--border);
  border-radius: 10px; padding: 14px 16px; font-size: 12.5px; overflow-x: auto;
}
.warn {
  background: var(--chip); border: 1px solid var(--border); border-left: 3px solid var(--bad);
  border-radius: 10px; padding: 10px 14px; font-size: 13px; color: var(--ink-2); margin-bottom: 16px;
}
footer { color: var(--muted); font-size: 12.5px; margin-top: 26px; }
@media (max-width: 620px) { .tile .value { font-size: 28px; } }
"""

JS = """
(function () {
  var qp = new URLSearchParams(location.search).get("theme");
  var saved = localStorage.getItem("ps-theme");
  if (qp === "light" || qp === "dark") document.documentElement.dataset.theme = qp;
  else if (saved) document.documentElement.dataset.theme = saved;
  else if (matchMedia("(prefers-color-scheme: light)").matches)
    document.documentElement.dataset.theme = "light";
  var btn = document.getElementById("themebtn");
  if (btn) btn.addEventListener("click", function () {
    var next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("ps-theme", next);
  });

  var siteSel = document.getElementById("sitesel");
  if (siteSel) siteSel.addEventListener("change", function () {
    var u = new URL(location.href);
    u.searchParams.set("site", siteSel.value);
    location.href = u;
  });

  var tip = document.getElementById("tip");
  if (!tip) return;
  var tipv = document.getElementById("tipv"), tipl = document.getElementById("tipl");
  var wrap = tip.parentElement;
  function show(hit) {
    var v = hit.dataset.v, one = v === "1";
    tipv.textContent = v + (one ? " visitor" : " visitors");
    tipl.textContent = hit.dataset.l;
    var bar = document.getElementById("bar" + hit.dataset.i);
    if (bar) bar.classList.add("hot");
    var w = wrap.getBoundingClientRect(), r = hit.getBoundingClientRect();
    tip.hidden = false;
    tip.style.left = (r.left - w.left + r.width / 2) + "px";
    tip.style.top = (r.top - w.top + 8) + "px";
  }
  function hide(hit) {
    tip.hidden = true;
    var bar = document.getElementById("bar" + hit.dataset.i);
    if (bar) bar.classList.remove("hot");
  }
  document.querySelectorAll(".hit").forEach(function (hit) {
    hit.addEventListener("mouseenter", function () { show(hit); });
    hit.addEventListener("mouseleave", function () { hide(hit); });
    hit.addEventListener("focus", function () { show(hit); });
    hit.addEventListener("blur", function () { hide(hit); });
  });
})();
"""

EXPLAINERS = [
    ("Unique visitors",
     "How many different people came by. Each person counts once per day, no matter "
     "how many pages they read. This is your reach — the number to watch over time."),
    ("Pageviews",
     "Every single page load. If pageviews are much higher than visitors, people are "
     "sticking around and reading more than one thing — a good sign."),
    ("Bounce rate",
     "The share of visits where someone read one page and left. A high bounce rate "
     "isn't automatically bad: on a blog, someone who reads the post they came for and "
     "leaves happy still counts as a bounce. Watch the trend, not the absolute number."),
    ("Avg. visit length",
     "How long a typical visit lasts, from the first page to the last. One-page visits "
     "count as zero (we can't know how long they read), so treat this as a floor."),
    ("Trend arrows",
     "Each number is compared with the equal period before it — today vs. yesterday, "
     "this week vs. last week. Green means moving the way you'd want; red means the "
     "opposite. One red day means nothing; a red month is worth a look."),
    ("Top referrers",
     "Which other websites sent people your way. “Direct / none” means someone typed "
     "your address, used a bookmark, or came from an app that hides its source."),
]

def delta_chip(change, lower_is_better=False, vs="previous period"):
    if change is None:
        return '<span class="delta flat">no previous data</span>'
    if abs(change) < 0.05:
        return f'<span class="delta flat">±0% vs {esc(vs)}</span>'
    arrow = "↑" if change > 0 else "↓"
    improving = (change < 0) if lower_is_better else (change > 0)
    cls = "up" if improving else "down"
    return f'<span class="delta {cls}">{arrow} {abs(change):.0f}% vs {esc(vs)}</span>'

def tile(label, value, chip, why):
    return (
        f'<div class="tile"><div class="label">{esc(label)}</div>'
        f'<div class="value">{value}</div>{chip}'
        f'<div class="why">{esc(why)}</div></div>'
    )

def breakdown_card(title, sub, rows, key_fn, total_visitors):
    if not rows:
        body = '<p class="sub">Nothing here yet for this period.</p>'
        return f'<div class="card"><h2>{esc(title)}</h2><div class="sub">{esc(sub)}</div>{body}</div>'
    max_v = rows[0]["visitors"] or 1
    lines = []
    for r in rows:
        share = 100.0 * r["visitors"] / total_visitors if total_visitors else 0
        width = max(2.0, 100.0 * r["visitors"] / max_v)
        lines.append(
            f'<tr><td><div class="rowbar"><i style="transform:scaleX({width / 100:.3f})"></i>'
            f"<span>{key_fn(r)}</span></div></td>"
            f'<td class="num">{fmt_int(r["visitors"])}</td>'
            f'<td class="num share">{share:.0f}%</td></tr>'
        )
    return (
        f'<div class="card"><h2>{esc(title)}</h2><div class="sub">{esc(sub)}</div>'
        f'<table class="list" aria-label="{esc(title)}">'
        f'<thead><tr><th></th><th class="num">Visitors</th><th class="num">Share</th></tr></thead>'
        f'<tbody>{"".join(lines)}</tbody></table></div>'
    )

def onboarding_html(host_hint):
    return f"""
    <div class="card empty">
      <h2>No data yet — let's fix that</h2>
      <p>Paste this one line into your site's HTML, just before <code>&lt;/head&gt;</code>.
      Use a short id for each site you want to track (e.g. <code>myblog</code>).</p>
      <pre class="snippet">&lt;script defer src="{esc(host_hint)}/a.js" data-site="myblog"&gt;&lt;/script&gt;</pre>
      <p>That's it. No cookies, no consent banner needed for this data, nothing else to configure.<br>
      Visits show up here within seconds — refresh this page after loading your site.</p>
    </div>"""

def render_dashboard(site, range_key, host_hint, auth_enabled):
    start, end, prev_start, prev_end = range_dates(range_key)
    sites = known_sites()
    if not site and sites:
        site = sites[0]

    has_data = bool(site) and site in sites
    body = []

    # ---- filter row -------------------------------------------------------
    seg = "".join(
        f'<a href="/dashboard?site={esc(site or "")}&range={key}" class="{"on" if key == range_key else ""}">{label}</a>'
        for key, (label, _) in RANGES.items()
    )
    site_opts = "".join(
        f'<option value="{esc(s)}" {"selected" if s == site else ""}>{esc(s)}</option>' for s in sites
    ) or '<option>no sites yet</option>'
    body.append(
        f'<div class="filters"><div class="seg">{seg}</div>'
        f'<select id="sitesel" class="site" aria-label="Site">{site_opts}</select></div>'
    )

    if not auth_enabled:
        body.append(
            '<div class="warn"><strong>Dashboard is not password-protected.</strong> '
            "Set DASH_USER and DASH_PASS in your .env file and restart to lock it down.</div>"
        )

    if not has_data:
        body.append(onboarding_html(host_hint))
        return page_shell(body, range_key)

    # ---- headline numbers -------------------------------------------------
    visitors, pageviews = totals(site, start, end)
    p_visitors, p_pageviews = totals(site, prev_start, prev_end)
    visits, bounce, avg_dur = visit_stats(site, start, end)
    _, p_bounce, p_avg_dur = visit_stats(site, prev_start, prev_end)

    vs = {"today": "yesterday", "7d": "previous 7 days", "30d": "previous 30 days"}[range_key]
    # bounce is compared in percentage points, not relative %
    bounce_change = (bounce - p_bounce) if (bounce is not None and p_bounce is not None) else None
    if bounce_change is None:
        bounce_chip = '<span class="delta flat">no previous data</span>'
    elif abs(bounce_change) < 0.5:
        bounce_chip = f'<span class="delta flat">±0 pts vs {esc(vs)}</span>'
    else:
        arrow = "↑" if bounce_change > 0 else "↓"
        cls = "down" if bounce_change > 0 else "up"
        bounce_chip = f'<span class="delta {cls}">{arrow} {abs(bounce_change):.0f} pts vs {esc(vs)}</span>'

    body.append('<div class="tiles">' + "".join([
        tile("Unique visitors", fmt_int(visitors), delta_chip(pct_change(visitors, p_visitors), vs=vs),
             "Different people who stopped by — each counted once."),
        tile("Pageviews", fmt_int(pageviews), delta_chip(pct_change(pageviews, p_pageviews), vs=vs),
             "Total pages loaded. More per visitor = people looking around."),
        tile("Bounce rate", f"{bounce:.0f}%" if bounce is not None else "–", bounce_chip,
             "Visits that read one page and left. Lower usually means stickier."),
        tile("Avg. visit length", fmt_duration(avg_dur),
             delta_chip(pct_change(avg_dur or 0, p_avg_dur) if p_avg_dur else None, vs=vs),
             "First page to last, per visit. One-page visits count as 0s."),
    ]) + "</div>")

    # ---- chart ------------------------------------------------------------
    if range_key == "today":
        raw = visitors_by_hour(site, end)
        def hlabel(h):
            return "12am" if h == 0 else ("12pm" if h == 12 else (f"{h}am" if h < 12 else f"{h - 12}pm"))
        buckets = [(hlabel(h), v) for h, v in raw]
        x_labels = [hlabel(h) for h, _ in raw]
        label_every, chart_title = 3, "Visitors per hour"
        chart_sub = "When people showed up today. Quiet hours are normal — look for your daily rhythm."
    else:
        raw = visitors_by_day(site, start, end)
        def dlabel(iso):
            d = datetime.strptime(iso, "%Y-%m-%d")
            return d.strftime("%b %-d") if os.name != "nt" else d.strftime("%b %d")
        buckets = [(dlabel(iso), v) for iso, v in raw]
        x_labels = [dlabel(iso) for iso, _ in raw]
        label_every = 1 if len(raw) <= 10 else 5
        chart_title = "Visitors per day"
        chart_sub = ("Your trend line. One tall or short bar means little — "
                     "what matters is whether the bars drift up over weeks.")

    chart = svg_bar_chart(buckets, x_labels, label_every, f"{chart_title}, {RANGES[range_key][0].lower()}")
    twin_rows = "".join(
        f'<tr><td>{esc(label)}</td><td class="num">{value}</td></tr>' for label, value in buckets
    )
    body.append(
        f'<div class="card"><h2>{chart_title}</h2><div class="sub">{esc(chart_sub)}</div>{chart}'
        f'<details class="twin"><summary>View as table</summary>'
        f'<table class="list"><thead><tr><th>Period</th><th class="num">Visitors</th></tr></thead>'
        f'<tbody>{twin_rows}</tbody></table></details></div>'
    )

    # ---- breakdowns -------------------------------------------------------
    pages = breakdown(site, "path", start, end)
    refs = breakdown(site, "referrer", start, end)
    countries = breakdown(site, "country", start, end)
    screens = breakdown(site, "screen", start, end, limit=5)

    body.append('<div class="grid2">')
    body.append(breakdown_card(
        "Top pages", "What people actually read.", pages,
        lambda r: esc(r["key"]), visitors))
    body.append(breakdown_card(
        "Top referrers", "Who sent people your way.", refs,
        lambda r: esc(r["key"]) if r["key"] else '<em>Direct / none</em>', visitors))
    body.append(breakdown_card(
        "Countries", "Where your readers are (from their timezone — no IP lookups).", countries,
        lambda r: f'{country_flag(r["key"])}&nbsp; {esc(country_label(r["key"]))}', visitors))
    body.append(breakdown_card(
        "Devices", "Screen size classes, a proxy for phone vs. computer.", screens,
        lambda r: esc(r["key"]), visitors))
    body.append("</div>")

    # ---- plain-English guide ---------------------------------------------
    dl = "".join(f"<dt>{esc(t)}</dt><dd>{esc(d)}</dd>" for t, d in EXPLAINERS)
    body.append(
        '<div class="card"><details class="explain"><summary><strong>What do these numbers mean?</strong>'
        " A plain-English guide</summary><dl>" + dl + "</dl></details></div>"
    )

    body.append(
        '<footer>Counted without cookies. Visitor identities rotate daily and raw IP addresses '
        "are never stored — yesterday's numbers can't be traced back to anyone.</footer>"
    )
    return page_shell(body, range_key)

def page_shell(body_parts, range_key):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Plainsight · {esc(RANGES.get(range_key, ("", 0))[0])}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header><div class="logo"></div><h1>Plainsight<small>privacy-first analytics</small></h1>
<div class="spacer"></div><button id="themebtn" class="themebtn" aria-label="Toggle theme">◐ Theme</button></header>
{"".join(body_parts)}
</div>
<script>{JS}</script>
</body>
</html>"""

# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #

with open(os.path.join(BASE_DIR, "tracker.js"), encoding="utf-8") as f:
    TRACKER_JS = f.read()

class Handler(BaseHTTPRequestHandler):
    server_version = "plainsight/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the console quiet; errors still raise
        pass

    def _send(self, status, body=b"", ctype="text/plain; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, val in (extra or {}).items():
            self.send_header(key, val)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authorized(self):
        if not (DASH_USER and DASH_PASS):
            return True  # auth not configured; dashboard shows a warning instead
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, _, pw = base64.b64decode(header[6:]).decode("utf-8", "replace").partition(":")
        except (ValueError, base64.binascii.Error):
            return False
        return hmac.compare_digest(user, DASH_USER) and hmac.compare_digest(pw, DASH_PASS)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/a.js":
            self._send(200, TRACKER_JS.encode(), "application/javascript; charset=utf-8",
                       {"Cache-Control": "public, max-age=86400", "Access-Control-Allow-Origin": "*"})
        elif url.path == "/health":
            self._send(200, b"ok")
        elif url.path in ("/", "/dashboard"):
            if not self._authorized():
                self._send(401, b"Authentication required.",
                           extra={"WWW-Authenticate": 'Basic realm="plainsight"'})
                return
            qs = parse_qs(url.query)
            site = (qs.get("site", [""])[0]).strip().lower()
            if site and not SITE_RE.match(site):
                site = ""
            range_key = qs.get("range", ["7d"])[0]
            if range_key not in RANGES:
                range_key = "7d"
            host = self.headers.get("Host", f"localhost:{PORT}")
            scheme = "https" if self.headers.get("X-Forwarded-Proto") == "https" else "http"
            page = render_dashboard(site, range_key, f"{scheme}://{host}", bool(DASH_USER and DASH_PASS))
            self._send(200, page.encode(), "text/html; charset=utf-8",
                       {"Cache-Control": "no-store"})
        else:
            self._send(404, b"not found")

    def do_POST(self):
        url = urlparse(self.path)
        if url.path != "/api/event":
            self._send(404, b"not found")
            return
        length = min(int(self.headers.get("Content-Length", 0) or 0), MAX_BODY)
        body = self.rfile.read(length) if length else b""
        try:
            ingest(self, body)
        except sqlite3.Error:
            pass  # never bounce a beacon back to the browser
        self._send(202, b"", extra={"Access-Control-Allow-Origin": "*"})

    def do_OPTIONS(self):
        self._send(204, b"", extra={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Max-Age": "86400",
        })

def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    auth = "basic-auth ON" if (DASH_USER and DASH_PASS) else "NO AUTH — set DASH_USER/DASH_PASS in .env"
    print(f"plainsight listening on http://{HOST}:{PORT}  (dashboard: /dashboard, {auth})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")

if __name__ == "__main__":
    main()
