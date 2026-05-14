import re
import io
import os
import time
import sqlite3
import requests
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ==========================
# CONFIG (Render ENV Support)
# ==========================
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "ISI_API_KEY_KAMU_DISINI")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "SOC_ADMIN_123")

DB_FILE = "ip_cache.db"
CACHE_TTL = 86400  # 24 jam cache
MAX_WORKERS = 10


# ==========================
# FASTAPI INIT
# ==========================
app = FastAPI(title="SOC IP Reputation Checker (Render)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # internal only, bisa dibatasi kalau perlu
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static file serving
app.mount("/static", StaticFiles(directory="static"), name="static")


# ==========================
# INPUT MODEL
# ==========================
class ReportInput(BaseModel):
    report_text: str


# ==========================
# SQLITE INIT
# ==========================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            abuseScore INTEGER,
            totalReports INTEGER,
            countryCode TEXT,
            isp TEXT,
            domain TEXT,
            last_checked INTEGER
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ==========================
# CACHE FUNCTIONS
# ==========================
def get_cached_ip(ip: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT abuseScore, totalReports, countryCode, isp, domain, last_checked
        FROM ip_cache
        WHERE ip = ?
    """, (ip,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    abuseScore, totalReports, countryCode, isp, domain, last_checked = row

    now = int(time.time())
    if (now - last_checked) > CACHE_TTL:
        return None

    return {
        "abuseScore": abuseScore,
        "totalReports": totalReports,
        "countryCode": countryCode,
        "isp": isp,
        "domain": domain
    }


def save_cache_ip(ip: str, data: dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO ip_cache
        (ip, abuseScore, totalReports, countryCode, isp, domain, last_checked)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        ip,
        data.get("abuseScore"),
        data.get("totalReports"),
        data.get("countryCode"),
        data.get("isp"),
        data.get("domain"),
        int(time.time())
    ))

    conn.commit()
    conn.close()


# ==========================
# PARSER REPORT
# ==========================
def parse_events(report_text: str):
    blocks = re.split(r"\n\s*\n", report_text.strip())
    events = []

    for block in blocks:
        if "Source IP" not in block:
            continue

        event_title_match = re.search(r"\[(.*?)\]\s*(.*)", block)
        event_name = None
        if event_title_match:
            event_name = event_title_match.group(2).strip()

        src_ip_match = re.search(r"Source IP\s*:\s*([\d\.]+)", block)
        action_match = re.search(r"Action\s*:\s*(.*)", block)
        count_match = re.search(r"Count\s*:\s*(\d+)", block)
        url_match = re.search(r"URL\s*:\s*(.*)", block)

        events.append({
            "eventName": event_name,
            "sourceIP": src_ip_match.group(1) if src_ip_match else None,
            "url": url_match.group(1).strip() if url_match else None,
            "action": action_match.group(1).strip() if action_match else None,
            "count": int(count_match.group(1)) if count_match else 0
        })

    return events


# ==========================
# ABUSEIPDB CHECKER (WITH SQLITE CACHE)
# ==========================
def check_abuseipdb(ip: str):
    cached = get_cached_ip(ip)
    if cached:
        return cached

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)

        if res.status_code != 200:
            result = {
                "abuseScore": None,
                "totalReports": None,
                "countryCode": None,
                "isp": None,
                "domain": None
            }
        else:
            data = res.json().get("data", {})
            result = {
                "abuseScore": data.get("abuseConfidenceScore"),
                "totalReports": data.get("totalReports"),
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain")
            }

    except:
        result = {
            "abuseScore": None,
            "totalReports": None,
            "countryCode": None,
            "isp": None,
            "domain": None
        }

    save_cache_ip(ip, result)
    return result


# ==========================
# ROUTES
# ==========================
@app.get("/", response_class=HTMLResponse)
def home():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/analyze")
def analyze_report(data: ReportInput):
    events = parse_events(data.report_text)
    unique_ips = list(set([e["sourceIP"] for e in events if e["sourceIP"]]))

    ip_reputation = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_abuseipdb, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            ip = futures[future]
            ip_reputation[ip] = future.result()

    final_results = []
    for e in events:
        rep = ip_reputation.get(e["sourceIP"], {})
        final_results.append({**e, **rep})

    return {
        "total_events": len(events),
        "total_unique_ips": len(unique_ips),
        "results": final_results
    }


@app.post("/download_csv")
def download_csv(data: ReportInput):
    events = parse_events(data.report_text)
    unique_ips = list(set([e["sourceIP"] for e in events if e["sourceIP"]]))

    ip_reputation = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_abuseipdb, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            ip = futures[future]
            ip_reputation[ip] = future.result()

    final_results = []
    for e in events:
        rep = ip_reputation.get(e["sourceIP"], {})

        final_results.append({
            "Event Name": e.get("eventName"),
            "Source IP": e.get("sourceIP"),
            "URL": e.get("url"),
            "Action": e.get("action"),
            "Count": e.get("count"),
            "Abuse Score": rep.get("abuseScore"),
            "Total Reports": rep.get("totalReports"),
            "ISP": rep.get("isp"),
            "Country": rep.get("countryCode"),
            "Domain": rep.get("domain"),
        })

    df = pd.DataFrame(final_results)

    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_ip_reputation_report.csv"}
    )


@app.post("/clear_cache")
def clear_cache(token: str = Query(...)):
    if token != ADMIN_TOKEN:
        return {"status": "FAILED", "message": "Unauthorized"}

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_cache")
    conn.commit()
    conn.close()

    return {"status": "SUCCESS", "message": "Cache cleared successfully"}