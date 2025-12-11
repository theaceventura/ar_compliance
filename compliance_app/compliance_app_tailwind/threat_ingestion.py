"""
Threat ingestion utilities for external advisories/feeds.

This module downloads threat/advisory feeds (CISA KEV, ACSC, CERT-NZ, MSRC, NVD)
and normalises them into ThreatObject instances before persisting to the
threat_objects table.
"""

import json
import re
from datetime import datetime, timedelta

import feedparser
import requests

from . import db

# Simple container so callers can build threat rows consistently
class ThreatObject:
    def __init__(
        self,
        source,
        item_type,
        title,
        summary,
        link,
        published_at,
        severity,
        kev_flag=False,
        cve_id=None,
        products_text="",
        raw_payload="",
    ):
        self.source = source
        self.item_type = item_type
        self.title = title
        self.summary = summary
        self.link = link
        self.published_at = published_at
        self.severity = severity
        self.kev_flag = kev_flag
        self.cve_id = cve_id
        self.products_text = products_text
        self.raw_payload = raw_payload


# CISA KEV
def fetch_cisa_kev():
    resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=20)
    resp.raise_for_status()
    return resp.json()


def normalise_cisa(raw):
    vulns = raw.get("vulnerabilities", []) if isinstance(raw, dict) else []
    out = []
    for item in vulns:
        cve_id = item.get("cveID")
        title = item.get("vulnerabilityName") or cve_id
        try:
            published_at = datetime.strptime(item.get("dateAdded"), "%Y-%m-%d")
        except Exception:
            published_at = None
        tobj = ThreatObject(
            source="CISA-KEV",
            item_type="CVE",
            cve_id=cve_id,
            title=title,
            summary=item.get("shortDescription") or "",
            link=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
            published_at=published_at,
            severity="Critical",
            kev_flag=True,
            products_text=item.get("product") or "",
            raw_payload=json.dumps(item),
        )
        out.append(tobj)
    return out


# ACSC alerts (RSS)
def fetch_acsc_alerts():
    feed = feedparser.parse("https://www.cyber.gov.au/acsc/view-all-content/alerts/rss.xml")
    return feed.entries or []


def _strip_html(text):
    if not text:
        return ""
    return re.sub(r"<[^>]+>", "", text)


def _to_datetime_from_struct(struct_time):
    if not struct_time:
        return None
    try:
        return datetime(*struct_time[:6])
    except Exception:
        return None


def normalise_acsc(raw):
    out = []
    for entry in raw:
        tobj = ThreatObject(
            source="ACSC",
            item_type="ALERT",
            cve_id=None,
            title=entry.get("title"),
            summary=_strip_html(entry.get("summary")),
            link=entry.get("link"),
            published_at=_to_datetime_from_struct(entry.get("published_parsed")),
            severity="Medium",
            kev_flag=False,
            products_text="",
            raw_payload=json.dumps(entry),
        )
        out.append(tobj)
    return out


# CERT NZ alerts (RSS)
def fetch_cert_nz():
    feed = feedparser.parse("https://www.cert.govt.nz/assets/feeds/advisories.rss")
    return feed.entries or []


def normalise_cert(raw):
    out = []
    for entry in raw:
        tobj = ThreatObject(
            source="CERT-NZ",
            item_type="ALERT",
            cve_id=None,
            title=entry.get("title"),
            summary=_strip_html(entry.get("summary") or entry.get("description")),
            link=entry.get("link"),
            published_at=_to_datetime_from_struct(entry.get("published_parsed")),
            severity="Medium",
            kev_flag=False,
            products_text="",
            raw_payload=json.dumps(entry),
        )
        out.append(tobj)
    return out


# MSRC security updates (JSON API)
def fetch_msrc():
    """Fetch MSRC updates from the CVRF JSON API."""
    url = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    return resp.json()


def normalise_msrc(raw):
    out = []
    items = raw.get("value", []) if isinstance(raw, dict) else []
    for entry in items:
        title = entry.get("DocumentTitle") or entry.get("ID") or entry.get("Alias")
        cvrf_url = entry.get("CvrfUrl") or ""
        # Severity is not always present; default to High
        severity = entry.get("Severity") or "High"
        # Dates
        published_raw = entry.get("CurrentReleaseDate") or entry.get("InitialReleaseDate")
        try:
            published_at = datetime.fromisoformat(published_raw.replace("Z", "+00:00")) if published_raw else None
        except Exception:
            published_at = None
        # Try to surface a CVE id if present in the update metadata
        cve_id = None
        cves = entry.get("CVE") or []
        if isinstance(cves, list) and cves:
            cve_id = cves[0]
        tobj = ThreatObject(
            source="MSRC",
            item_type="ADVISORY",
            cve_id=cve_id,
            title=title,
            summary=_strip_html(entry.get("DocumentTitle") or ""),
            link=cvrf_url,
            published_at=published_at,
            severity=severity,
            kev_flag=False,
            products_text="",
            raw_payload=json.dumps(entry),
        )
        out.append(tobj)
    return out


# NVD API
def fetch_nvd_for_keywords(keywords):
    """Fetch CVEs from NVD for each keyword over the last 7 days."""
    results = []
    for kw in keywords:
        params = {
            "keywordSearch": kw,
        }
        try:
            resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=30)
            resp.raise_for_status()
            results.append((kw, resp.json()))
        except requests.RequestException:
            # skip this keyword on network/HTTP errors to avoid breaking ingestion
            continue
    return results


def normalise_nvd(raw, keyword):
    out = []
    cves = raw.get("vulnerabilities", []) if isinstance(raw, dict) else []
    for item in cves:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions") or []
        desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        published = cve.get("published")
        try:
            published_at = datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
        except Exception:
            published_at = None
        metrics = cve.get("metrics", {})
        severity = "High"
        cvssv3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
        if cvssv3 and isinstance(cvssv3, list) and cvssv3:
            sev_val = cvssv3[0].get("cvssData", {}).get("baseSeverity")
            if sev_val:
                severity = sev_val
        tobj = ThreatObject(
            source="NVD",
            item_type="CVE",
            cve_id=cve_id,
            title=cve_id,
            summary=desc_en,
            link=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
            published_at=published_at,
            severity=severity,
            kev_flag=False,
            products_text=keyword,
            raw_payload=json.dumps(cve),
        )
        out.append(tobj)
    return out

# Track last error per source (in-memory)
_last_status = {}


def _set_status(source, error=None, message=None, progress=None):
    """Record the last status for a source in-memory."""
    if not source:
        return
    source_key = source.lower()
    entry = _last_status.get(source_key, {})
    entry["error"] = error
    entry["message"] = message
    entry["progress"] = progress
    entry["checked_at"] = datetime.utcnow().isoformat()
    _last_status[source_key] = entry


def _set_last_error(source, message):
    _set_status(source, message)


def get_last_status():
    """Return a mapping source -> {error, checked_at}."""
    return dict(_last_status)


# Persistence helpers
def save_threat_objects(threat_objects):
    """Insert threat objects if they don't already exist."""
    if not threat_objects:
        return 0
    conn = db.get_connection()
    cur = conn.cursor()
    inserted = 0
    for obj in threat_objects:
        cur.execute(
            """
            SELECT 1 FROM threat_objects
            WHERE source=? AND IFNULL(cve_id,'')=IFNULL(?, '') AND title=? AND link=?
            """,
            (obj.source, obj.cve_id, obj.title, obj.link),
        )
        if cur.fetchone():
            continue
        cur.execute(
            """
            INSERT INTO threat_objects (source, item_type, cve_id, title, summary, link, published_at, severity, kev_flag, products_text, raw_payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                obj.source,
                obj.item_type,
                obj.cve_id,
                obj.title,
                obj.summary,
                obj.link,
                obj.published_at.isoformat() if isinstance(obj.published_at, datetime) else (obj.published_at or None),
                obj.severity,
                1 if obj.kev_flag else 0,
                obj.products_text,
                obj.raw_payload,
                datetime.utcnow().isoformat(),
            ),
        )
        inserted += 1
    conn.commit()
    conn.close()
    return inserted


def ingest_source(source_name):
    """Fetch, normalise, and persist a given source."""
    source_name = (source_name or "").lower()
    all_objs = []
    _set_last_error(source_name, None)
    _set_status(source_name, message="Starting", progress=0)
    if source_name == "cisa":
        try:
            raw = fetch_cisa_kev()
            all_objs = normalise_cisa(raw)
            _set_status(source_name, message="Fetched CISA KEV", progress=50)
        except Exception as exc:
            _set_last_error(source_name, str(exc))
            return 0
    elif source_name == "acsc":
        try:
            raw = fetch_acsc_alerts()
            all_objs = normalise_acsc(raw)
            _set_status(source_name, message="Fetched ACSC", progress=50)
        except Exception as exc:
            _set_last_error(source_name, str(exc))
            return 0
    elif source_name == "certnz":
        try:
            raw = fetch_cert_nz()
            all_objs = normalise_cert(raw)
            _set_status(source_name, message="Fetched CERT-NZ", progress=50)
        except Exception as exc:
            _set_last_error(source_name, str(exc))
            return 0
    elif source_name == "msrc":
        try:
            from . import import_msrc

            inserted = import_msrc.import_msrc_threats()
            if inserted == 0:
                status_entry = _last_status.get(source_name, {})
                if not status_entry.get("error"):
                    _set_last_error(source_name, "No data ingested (empty feed or duplicates).")
            return inserted
        except Exception as exc:
            _set_last_error(source_name, str(exc))
            return 0
    elif source_name == "nvd":
        keywords = ["Windows", "Cisco", "VMware", "Fortinet", "Linux"]
        try:
            for kw, resp in fetch_nvd_for_keywords(keywords):
                all_objs.extend(normalise_nvd(resp, kw))
            _set_status(source_name, message="Fetched NVD", progress=50)
        except Exception as exc:
            _set_last_error(source_name, str(exc))
            return 0
    else:
        return 0

    inserted = save_threat_objects(all_objs)
    status_entry = _last_status.get(source_name, {})
    if inserted == 0 and not status_entry.get("error"):
        _set_last_error(source_name, "No data ingested (empty feed or duplicates).")
    else:
        _set_status(source_name, message="Completed", progress=100)
    return inserted


def check_source_connectivity(source_name):
    """Lightweight reachability check without saving data."""
    source_name = (source_name or "").lower()
    url_map = {
        "cisa": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "acsc": "https://www.cyber.gov.au/acsc/view-all-content/alerts/rss.xml",
        "certnz": "https://www.cert.govt.nz/assets/feeds/advisories.rss",
        "msrc": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
    }
    url = url_map.get(source_name)
    if not url:
        _set_last_error(source_name, "Unknown source.")
        return False
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        _set_last_error(source_name, None)
        return True
    except Exception as exc:
        _set_last_error(source_name, str(exc))
        return False


# Placeholder functions for completeness (not yet implemented)
def fetch_cert_nz_feed():
    return fetch_cert_nz()
