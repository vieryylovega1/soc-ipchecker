import io
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import pandas as pd
import requests
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


# ==========================
# CONFIG
# ==========================
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "c27f5ba7946189bcd515976491999a0cd348da259b34fd0c754c9a2b8c6d4a4b2b8db46eb91470e9")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "SOC_ADMIN_123")

DB_FILE = "ip_cache.db"
CACHE_TTL = 86400  # 24 jam
MAX_WORKERS = 10


# ==========================
# FASTAPI INIT
# ==========================
app = FastAPI(title="SOC IP Reputation Checker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


class ReportInput(BaseModel):
    report_text: str


# ==========================
# SQLITE
# ==========================
def get_db_connection():
    return sqlite3.connect(DB_FILE)


def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                isp TEXT,
                countryCode TEXT,
                city TEXT,
                totalReports INTEGER,
                abuseScore INTEGER,
                lastReportedAt TEXT,
                checkedAt TEXT,
                domain TEXT,
                usageType TEXT,
                asn TEXT,
                last_checked INTEGER
            )
        """)
        conn.commit()


init_db()


def get_cached_ip(ip: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                isp,
                countryCode,
                city,
                totalReports,
                abuseScore,
                lastReportedAt,
                checkedAt,
                domain,
                usageType,
                asn,
                last_checked
            FROM ip_cache
            WHERE ip = ?
        """, (ip,))

        row = cursor.fetchone()

    if not row:
        return None

    (
        isp,
        countryCode,
        city,
        totalReports,
        abuseScore,
        lastReportedAt,
        checkedAt,
        domain,
        usageType,
        asn,
        last_checked,
    ) = row

    if int(time.time()) - last_checked > CACHE_TTL:
        return None

    return {
        "isp": isp,
        "countryCode": countryCode,
        "city": city,
        "totalReports": totalReports,
        "abuseScore": abuseScore,
        "lastReportedAt": lastReportedAt,
        "checkedAt": checkedAt,
        "domain": domain,
        "usageType": usageType,
        "asn": asn,
    }


def save_cache_ip(ip: str, data: dict):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO ip_cache (
                ip,
                isp,
                countryCode,
                city,
                totalReports,
                abuseScore,
                lastReportedAt,
                checkedAt,
                domain,
                usageType,
                asn,
                last_checked
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            data.get("isp"),
            data.get("countryCode"),
            data.get("city"),
            data.get("totalReports"),
            data.get("abuseScore"),
            data.get("lastReportedAt"),
            data.get("checkedAt"),
            data.get("domain"),
            data.get("usageType"),
            data.get("asn"),
            int(time.time()),
        ))
        conn.commit()


# ==========================
# PARSER REPORT
# ==========================
def parse_events(report_text: str):
    report_text = report_text.strip()

    # ==========================
    # MODE 1 - SIMPLE IP LIST
    # ==========================
    ip_lines = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", report_text)

    # Jika isi hanya IP-IP
    if ip_lines and len(ip_lines) == len(report_text.splitlines()):

        ip_counter = {}

        for ip in ip_lines:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

        events = []

        for ip, count in ip_counter.items():
            events.append({
                "sourceIP": ip,
                "eventName": "Manual IP Check",
                "action": "-",
                "count": count,
            })

        return events

    # ==========================
    # MODE 2 - SOC REPORT FORMAT
    # ==========================
    blocks = re.split(r"\n\s*\n", report_text)
    events = []

    for block in blocks:
        if "Source IP" not in block:
            continue

        event_match = re.search(r"\[(.*?)\]\s*(.*)", block)
        source_match = re.search(r"Source IP\s*:\s*([\d\.]+)", block)
        action_match = re.search(r"Action\s*:\s*(.*)", block)
        count_match = re.search(r"Count\s*:\s*(\d+)", block)

        events.append({
            "sourceIP": source_match.group(1) if source_match else None,
            "eventName": event_match.group(2).strip() if event_match else None,
            "action": action_match.group(1).strip() if action_match else None,
            "count": int(count_match.group(1)) if count_match else 0,
        })

    return events


# ==========================
# ABUSEIPDB
# ==========================
def empty_reputation():
    return {
        "isp": None,
        "countryCode": None,
        "city": None,
        "totalReports": None,
        "abuseScore": None,
        "lastReportedAt": None,
        "checkedAt": datetime.now().strftime("%d/%m/%Y"),
        "domain": None,
        "usageType": None,
        "asn": None,
    }


def check_abuseipdb(ip: str):
    cached = get_cached_ip(ip)
    if cached:
        return cached

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)

        if response.status_code != 200:
            result = empty_reputation()
        else:
            data = response.json().get("data", {})
            result = {
                "isp": data.get("isp"),
                "countryCode": data.get("countryCode"),
                "city": data.get("city"),
                "totalReports": data.get("totalReports"),
                "abuseScore": data.get("abuseConfidenceScore"),
                "lastReportedAt": data.get("lastReportedAt"),
                "checkedAt": datetime.now().strftime("%d/%m/%Y"),
                "domain": data.get("domain"),
                "usageType": data.get("usageType"),
                "asn": data.get("asn"),
            }

    except requests.RequestException:
        result = empty_reputation()

    save_cache_ip(ip, result)
    return result


# ==========================
# PROCESSING
# ==========================
def enrich_events(events: list[dict]):
    unique_ips = list({event["sourceIP"] for event in events if event.get("sourceIP")})
    ip_reputation = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(check_abuseipdb, ip): ip
            for ip in unique_ips
        }

        for future in as_completed(futures):
            ip = futures[future]
            ip_reputation[ip] = future.result()

    results = []
    for event in events:
        reputation = ip_reputation.get(event.get("sourceIP"), {})
        results.append({
            **event,
            **reputation,
        })

    return results, len(unique_ips)


def build_csv_rows(results: list[dict]):
    rows = []

    for row in results:
        rows.append({
            "IP": row.get("sourceIP"),
            "ISP": row.get("isp"),
            "Country": row.get("countryCode"),
            "City": row.get("city"),
            "TotalReports": row.get("totalReports"),
            "AbuseConfidenceScore": row.get("abuseScore"),
            "LastReportedAt": row.get("lastReportedAt"),
            "CheckedAt": row.get("checkedAt"),
            "Domain": row.get("domain"),
            "Jenis Aktivitas": row.get("eventName"),
            "Count": row.get("count"),
            "Action": row.get("action"),
            "Usage Type": row.get("usageType"),
            "ASN": row.get("asn"),
        })

    return rows


# ==========================
# ROUTES
# ==========================
@app.get("/", response_class=HTMLResponse)
def home():
    with open("templates/index.html", "r", encoding="utf-8") as file:
        return file.read()


@app.post("/analyze")
def analyze_report(data: ReportInput):
    events = parse_events(data.report_text)
    results, total_unique_ips = enrich_events(events)

    return {
        "total_events": len(events),
        "total_unique_ips": total_unique_ips,
        "results": results,
    }


@app.post("/download_csv")
def download_csv(data: ReportInput):
    events = parse_events(data.report_text)
    results, _ = enrich_events(events)

    df = pd.DataFrame(build_csv_rows(results))

    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=soc_ip_reputation_report.csv"
        },
    )


@app.post("/clear_cache")
def clear_cache(token: str = Query(...)):
    if token != ADMIN_TOKEN:
        return {
            "status": "FAILED",
            "message": "Unauthorized",
        }

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ip_cache")
        conn.commit()

    return {
        "status": "SUCCESS",
        "message": "Cache cleared successfully",
    }