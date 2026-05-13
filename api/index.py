import re
import io
import requests
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ABUSEIPDB_API_KEY = "ISI_API_KEY_KAMU_DISINI"
MAX_WORKERS = 10
ADMIN_TOKEN = "SOC_ADMIN_123"

app = FastAPI(title="SOC IP Reputation Checker (Vercel)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")


class ReportInput(BaseModel):
    report_text: str


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
        dst_ip_match = re.search(r"Destination IP\s*:\s*([\d\.]+)", block)
        action_match = re.search(r"Action\s*:\s*(.*)", block)
        count_match = re.search(r"Count\s*:\s*(\d+)", block)
        url_match = re.search(r"URL\s*:\s*(.*)", block)

        events.append({
            "eventName": event_name,
            "sourceIP": src_ip_match.group(1) if src_ip_match else None,
            "destinationIP": dst_ip_match.group(1) if dst_ip_match else None,
            "url": url_match.group(1).strip() if url_match else None,
            "action": action_match.group(1).strip() if action_match else None,
            "count": int(count_match.group(1)) if count_match else 0
        })

    return events


def check_abuseipdb(ip: str):
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
            return {
                "abuseScore": None,
                "totalReports": None,
                "countryCode": None,
                "isp": None,
                "domain": None
            }

        data = res.json().get("data", {})

        return {
            "abuseScore": data.get("abuseConfidenceScore"),
            "totalReports": data.get("totalReports"),
            "countryCode": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain")
        }

    except:
        return {
            "abuseScore": None,
            "totalReports": None,
            "countryCode": None,
            "isp": None,
            "domain": None
        }


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
            "Destination IP": e.get("destinationIP"),
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

    # Di Vercel tidak ada sqlite persistent, jadi clear_cache hanya simbolik
    return {"status": "SUCCESS", "message": "No persistent cache on Vercel (serverless)."}