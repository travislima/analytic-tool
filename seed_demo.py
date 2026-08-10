#!/usr/bin/env python3
"""Fill the database with ~45 days of realistic-looking demo traffic so you can
explore the dashboard before wiring up a real site.

  python3 seed_demo.py          # writes into analytics.db (or $DB_PATH)

Safe to re-run: it only ever inserts rows for the demo site ids and clears
those first.
"""

import random
import sqlite3
from datetime import date, datetime, timedelta

import app  # reuse config + schema

random.seed(7)

PAGES = [
    ("/", 30), ("/blog/how-i-built-my-desk", 18), ("/blog/a-year-of-running", 14),
    ("/about", 9), ("/blog/sourdough-notes", 8), ("/projects", 7),
    ("/blog/camera-bag-2026", 6), ("/uses", 4), ("/blog/quitting-twitter", 3), ("/contact", 1),
]
REFERRERS = [
    ("", 46), ("google.com", 24), ("news.ycombinator.com", 8), ("reddit.com", 6),
    ("duckduckgo.com", 5), ("bing.com", 4), ("mastodon.social", 3), ("t.co", 2), ("lobste.rs", 2),
]
COUNTRIES = [
    ("US", 34), ("GB", 12), ("DE", 9), ("CA", 8), ("FR", 6), ("NL", 5), ("AU", 5),
    ("IN", 5), ("BR", 4), ("SE", 3), ("JP", 3), ("ES", 2), ("PL", 2), ("", 2),
]
SCREENS = [("Mobile", 44), ("Desktop", 28), ("Laptop", 22), ("Tablet", 6)]

def pick(table):
    keys, weights = zip(*table)
    return random.choices(keys, weights=weights, k=1)[0]

def seed(conn, site, base_visitors, days=75):
    conn.execute("DELETE FROM events WHERE site = ?", (site,))
    today = date.today()
    rows = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        iso = day.strftime("%Y-%m-%d")
        growth = 1.0 + 0.35 * (days - offset) / days           # gentle upward trend
        weekday_pull = 0.72 if day.weekday() >= 5 else 1.0     # quieter weekends
        spike = 3.1 if offset == 11 else 1.0                   # one "made the rounds" day
        n = max(1, int(random.gauss(base_visitors * growth * weekday_pull * spike,
                                    base_visitors * 0.14)))
        for _ in range(n):
            visitor = "%016x" % random.getrandbits(64)
            hour = min(23, max(0, int(random.gauss(14, 4.5))))
            ts = int(datetime(day.year, day.month, day.day, hour,
                              random.randrange(60), random.randrange(60)).timestamp())
            country, screen, referrer = pick(COUNTRIES), pick(SCREENS), pick(REFERRERS)
            # ~58% bounce; the rest browse 2-6 pages a couple of minutes apart
            views = 1 if random.random() < 0.58 else random.randint(2, 6)
            for view in range(views):
                rows.append((site, ts, iso, datetime.fromtimestamp(ts).hour, visitor,
                             pick(PAGES), referrer if view == 0 else "", screen, country))
                ts += random.randint(35, 260)
    conn.executemany(
        "INSERT INTO events (site, ts, date, hour, visitor, path, referrer, screen, country)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    conn.commit()
    print(f"  {site}: {len(rows)} events")

def main():
    app.init_db()
    conn = sqlite3.connect(app.DB_PATH)
    print(f"Seeding demo data into {app.DB_PATH} …")
    seed(conn, "myblog", base_visitors=38)
    seed(conn, "sideproject", base_visitors=11)
    print("Done. Start the server (python3 app.py) and open /dashboard")

if __name__ == "__main__":
    main()
