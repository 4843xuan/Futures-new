import os
import json
import hashlib
import datetime as dt
from dateutil import parser as dtparser

import pandas as pd
import requests
from bs4 import BeautifulSoup
import feedparser

from google.oauth2 import service_account
from googleapiclient.discovery import build


# ==========================
# Google Sheets I/O helpers
# ==========================
def _load_service_account_info() -> dict:
    raw = os.environ["GOOGLE_SERVICE_ACCOUNT_JSON"]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # If Secret was stored as base64, decode here
        import base64
        return json.loads(base64.b64decode(raw).decode("utf-8"))


def get_sheets_service():
    info = _load_service_account_info()
    creds = service_account.Credentials.from_service_account_info(
        info,
        scopes=["https://www.googleapis.com/auth/spreadsheets"],
    )
    return build("sheets", "v4", credentials=creds)


def append_rows(spreadsheet_id: str, sheet_name: str, rows: list[list]):
    svc = get_sheets_service()
    body = {"values": rows}
    svc.spreadsheets().values().append(
        spreadsheetId=spreadsheet_id,
        range=f"{sheet_name}!A1",
        valueInputOption="USER_ENTERED",
        insertDataOption="INSERT_ROWS",
        body=body,
    ).execute()


def read_existing_dedup_ids(spreadsheet_id: str, sheet_name: str, dedup_col_letter="Q", max_rows=20000) -> set[str]:
    """
    Read the existing dedup_id column (e.g., Q) to avoid duplicates.
    Adjust dedup_col_letter to match your actual sheet layout.
    """
    svc = get_sheets_service()
    rng = f"{sheet_name}!{dedup_col_letter}2:{dedup_col_letter}{max_rows+1}"
    resp = svc.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range=rng).execute()
    vals = resp.get("values", [])
    return set(v[0] for v in vals if v)


# ==========================
# Utilities
# ==========================
def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def now_utc_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def safe_parse_date(s: str | None):
    if not s:
        return None
    try:
        return dtparser.parse(s).date().isoformat()
    except Exception:
        return None


# ==========================
# Fetchers
# ==========================
def fetch_rss(feed_url: str) -> list[dict]:
    d = feedparser.parse(feed_url)
    items = []
    for e in d.entries[:80]:
        url = getattr(e, "link", None)
        title = getattr(e, "title", None)
        published = getattr(e, "published", None) or getattr(e, "updated", None)
        snippet = getattr(e, "summary", None) or ""

        if not url or not title:
            continue

        items.append({
            "published_at": safe_parse_date(published),
            "title": str(title).strip(),
            "url": str(url).strip(),
            "content_snippet": BeautifulSoup(str(snippet), "lxml").get_text(" ", strip=True)[:800],
        })
    return items


def fetch_sitemap(sitemap_url: str, include_patterns: list[str] | None = None) -> list[str]:
    r = requests.get(sitemap_url, timeout=30)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "xml")
    urls = [loc.get_text(strip=True) for loc in soup.find_all("loc")]
    if include_patterns:
        return [u for u in urls if any(p in u for p in include_patterns)]
    return urls


def fetch_html_list(list_url: str) -> list[dict]:
    r = requests.get(list_url, timeout=30)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "lxml")

    items = []
    for a in soup.select("a"):
        href = a.get("href")
        text = a.get_text(" ", strip=True)
        if not href or not text:
            continue

        if href.startswith("/"):
            href = requests.compat.urljoin(list_url, href)
        if not href.startswith("http"):
            continue
        if len(text) < 10:
            continue

        items.append({
            "published_at": None,
            "title": text[:200],
            "url": href,
            "content_snippet": "",
        })
    return items[:80]


def fetch_email_imap(host: str, user: str, password: str) -> list[dict]:
    import imaplib
    import email
    import re

    M = imaplib.IMAP4_SSL(host)
    M.login(user, password)
    M.select("INBOX")
    typ, data = M.search(None, "UNSEEN")
    ids = data[0].split() if data and data[0] else []

    items = []
    for mid in ids[:80]:
        typ, msg_data = M.fetch(mid, "(RFC822)")
        msg = email.message_from_bytes(msg_data[0][1])

        # subject
        dh = email.header.decode_header(msg.get("Subject"))
        subj = dh[0][0]
        if isinstance(subj, bytes):
            subj = subj.decode(errors="ignore")

        date = msg.get("Date")

        # body
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True) or b""
                    body_text = payload.decode(errors="ignore")
                    break
        else:
            payload = msg.get_payload(decode=True) or b""
            body_text = payload.decode(errors="ignore")

        # first link
        m = re.search(r"https?://\S+", body_text)
        url = m.group(0).rstrip(")>\"'") if m else ""

        items.append({
            "published_at": safe_parse_date(date),
            "title": str(subj).strip()[:200],
            "url": url,
            "content_snippet": BeautifulSoup(body_text, "lxml").get_text(" ", strip=True)[:800],
        })

        # mark as seen
        M.store(mid, "+FLAGS", "\\Seen")

    M.logout()
    return items


# ==========================
# AI enrichment (placeholder)
# Replace ai_enrich() with your real LLM call.
# ==========================
def ai_enrich(item: dict) -> dict:
    # TODO: Use os.environ["LLM_API_KEY"] to call your LLM and return strict JSON.
    return {
        "ai_summary_cn": f"【占位】{item['title']}",
        "ai_summary_en": f"[placeholder] {item['title']}",
        "ai_category_lv1": "Uncategorized",
        "ai_category_lv2": "",
        "ai_entities": "",
        "ai_relevance_score": 0.5,
        "ai_action_tags": "",
    }


# ==========================
# Pipeline
# ==========================
def main():
    spreadsheet_id = os.environ["GSHEET_ID"]
    fetched_at = now_utc_iso()
    run_id = sha1(fetched_at)

    sources = pd.read_csv("sources_config.csv")

    # Read existing dedup ids from news_ai sheet (Q column by default).
    existing = read_existing_dedup_ids(spreadsheet_id, "news_ai", dedup_col_letter="Q", max_rows=20000)

    raw_rows = []
    ai_rows = []

    for _, s in sources.iterrows():
        meta = s.to_dict()
        channel = str(meta.get("channel_type", "")).strip()
        url = str(meta.get("url", "")).strip()

        try:
            if channel == "rss":
                items = fetch_rss(url)

            elif channel == "rss_index":
                # discover rss links from the index page, then pull each feed
                r = requests.get(url, timeout=30); r.raise_for_status()
                soup = BeautifulSoup(r.text, "lxml")

                rss_links = []
                for a in soup.select("a"):
                    href = a.get("href") or ""
                    txt = (a.get_text(" ", strip=True) or "").lower()
                    if "rss" in txt or "rss" in href.lower() or "feed" in href.lower() or href.lower().endswith(".xml"):
                        if href.startswith("/"):
                            href = requests.compat.urljoin(url, href)
                        if href.startswith("http"):
                            rss_links.append(href)

                rss_links = list(dict.fromkeys(rss_links))[:12]
                items = []
                for f in rss_links:
                    items.extend(fetch_rss(f))

            elif channel == "sitemap":
                # include_patterns can be specified in parse_hint like: include_patterns=/news/press-releases/|/notices/
                include = None
                hint = str(meta.get("parse_hint", ""))
                if "include_patterns=" in hint:
                    include = hint.split("include_patterns=")[-1].split("|")
                urls = fetch_sitemap(url, include_patterns=include)
                items = [{"published_at": None, "title": u.split("/")[-1][:200], "url": u, "content_snippet": ""} for u in urls[:80]]

            elif channel == "html_list":
                items = fetch_html_list(url)

            elif channel == "email_imap":
                host = os.environ["IMAP_HOST"]
                user = os.environ["IMAP_USER"]
                pwd = os.environ["IMAP_PASS"]
                items = fetch_email_imap(host, user, pwd)

            else:
                continue

            for it in items:
                if not it.get("url"):
                    continue

                dedup_id = sha1(it["url"])
                if dedup_id in existing:
                    continue
                existing.add(dedup_id)

                raw_rows.append([
                    run_id, fetched_at,
                    meta.get("source_id"), meta.get("org"), meta.get("org_type"), meta.get("region"),
                    it.get("published_at"), it.get("title"), it.get("url"), it.get("content_snippet"),
                ])

                ai = ai_enrich(it)
                ai_rows.append([
                    run_id, fetched_at,
                    meta.get("source_id"), meta.get("org"), meta.get("org_type"), meta.get("region"),
                    it.get("published_at"), it.get("title"), it.get("url"), it.get("content_snippet"),
                    ai.get("ai_summary_cn"), ai.get("ai_summary_en"),
                    ai.get("ai_category_lv1"), ai.get("ai_category_lv2"), ai.get("ai_entities"),
                    ai.get("ai_relevance_score"), ai.get("ai_action_tags"), dedup_id
                ])

        except Exception as e:
            print(f"[ERROR] source_id={meta.get('source_id')} url={url} err={e}")

    if raw_rows:
        append_rows(spreadsheet_id, "news_raw", raw_rows)
    if ai_rows:
        append_rows(spreadsheet_id, "news_ai", ai_rows)

    # meta logging (optional)
    append_rows(spreadsheet_id, "meta", [[fetched_at, len(raw_rows), len(ai_rows)]])

    print(f"Done. raw={len(raw_rows)} ai={len(ai_rows)}")


if __name__ == "__main__":
    main()
