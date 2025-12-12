"""
Threat ingestion utilities for external advisories/feeds.

This module downloads threat/advisory feeds (CISA KEV, ACSC, CERT-NZ, MSRC, NVD)
and normalises them into ThreatObject instances before persisting to the
threat_objects table.
"""

import json
import re
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

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
        cvss_vector=None,
        cvss_base_score=None,
        cvss_version=None,
        last_modified_at=None,
        exploit_status=None,
        vendor_refs=None,
        cwe_id=None,
        cvss_av=None,
        cvss_ac=None,
        cvss_pr=None,
        cvss_ui=None,
        cvss_s=None,
        cvss_c=None,
        cvss_i=None,
        cvss_a=None,
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
        self.cvss_vector = cvss_vector
        self.cvss_base_score = cvss_base_score
        self.cvss_version = cvss_version
        self.last_modified_at = last_modified_at
        self.exploit_status = exploit_status
        self.vendor_refs = vendor_refs
        self.cwe_id = cwe_id
        self.cvss_av = cvss_av
        self.cvss_ac = cvss_ac
        self.cvss_pr = cvss_pr
        self.cvss_ui = cvss_ui
        self.cvss_s = cvss_s
        self.cvss_c = cvss_c
        self.cvss_i = cvss_i
        self.cvss_a = cvss_a


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


def _extract_products_from_nvd_configs(cve_obj):
    """Return a comma-separated string of vendor:product pairs from NVD configurations."""
    configs = cve_obj.get("configurations") or []
    products = []

    def _add_from_cpe(cpe_uri):
        if not cpe_uri:
            return
        parts = cpe_uri.split(":")
        if len(parts) >= 5:
            vendor = parts[3]
            product = parts[4]
            if vendor and product:
                products.append(f"{vendor}:{product}")

    def _walk_nodes(nodes):
        if not nodes:
            return
        if isinstance(nodes, list):
            for n in nodes:
                _walk_nodes(n)
            return
        if isinstance(nodes, dict):
            for match in nodes.get("cpeMatch", []):
                _add_from_cpe(match.get("criteria"))
            _walk_nodes(nodes.get("children"))

    _walk_nodes(configs)
    seen = set()
    unique = []
    for p in products:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return ", ".join(unique)


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


# Apple Security Updates (RSS)
def fetch_apple_updates():
    feed = feedparser.parse("https://support.apple.com/en-us/rss/securityupdates.rss")
    return feed.entries or []


def normalise_apple(raw):
    out = []
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    for entry in raw:
        title = entry.get("title")
        summary_html = entry.get("summary") or entry.get("description") or ""
        summary = _strip_html(summary_html)
        link = entry.get("link") or ""
        published = _to_datetime_from_struct(entry.get("published_parsed"))
        cves = cve_re.findall(summary) if summary else []
        cve_id = cves[0] if cves else None
        products = entry.get("tags") or []
        product_labels = []
        for p in products:
            label = p.get("term") if isinstance(p, dict) else None
            if label:
                product_labels.append(label)
        products_text = ", ".join(product_labels) if product_labels else "Apple"
        tobj = ThreatObject(
            source="APPLE",
            item_type="ADVISORY",
            cve_id=cve_id,
            title=title or (cve_id or "Apple Security Update"),
            summary=summary,
            link=link,
            published_at=published,
            severity="Medium",
            kev_flag=False,
            products_text=products_text,
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
def fetch_nvd_recent(days=10):
    """Fetch CVEs from NVD published in the last `days`."""
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000 UTC-00:00"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000 UTC-00:00"),
        "resultsPerPage": 2000,
    }
    try:
        resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return {}


def fetch_nvd_for_keywords(keywords):
    """Fetch CVEs from NVD for each keyword (fallback when date range is empty)."""
    results = []
    for kw in keywords:
        params = {
            "keywordSearch": kw,
            "resultsPerPage": 2000,
        }
        try:
            resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=30)
            resp.raise_for_status()
            results.append((kw, resp.json()))
        except requests.RequestException:
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
        last_mod = cve.get("lastModified")
        try:
            last_mod_at = datetime.fromisoformat(last_mod.replace("Z", "+00:00")) if last_mod else None
        except Exception:
            last_mod_at = None
        cwe_id = None
        weaknesses = cve.get("weaknesses") or []
        if weaknesses and isinstance(weaknesses, list):
            for w in weaknesses:
                for d in w.get("description", []):
                    if d.get("value"):
                        cwe_id = d.get("value")
                        break
                if cwe_id:
                    break
        metrics = cve.get("metrics", {})
        severity = "High"
        cvssv3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
        vector = None
        score_val = None
        cvss_version = None
        cvss_components = {}
        if cvssv3 and isinstance(cvssv3, list) and cvssv3:
            sev_val = cvssv3[0].get("cvssData", {}).get("baseSeverity")
            score_val = cvssv3[0].get("cvssData", {}).get("baseScore")
            vector = cvssv3[0].get("cvssData", {}).get("vectorString")
            cvss_version = cvssv3[0].get("cvssData", {}).get("version")
            if sev_val:
                severity = sev_val
            if vector and isinstance(vector, str):
                parts = vector.split("/")
                comp_map = {}
                for p in parts:
                    if ":" in p:
                        k, v = p.split(":", 1)
                        comp_map[k] = v
                cvss_components = {
                    "av": comp_map.get("AV"),
                    "ac": comp_map.get("AC"),
                    "pr": comp_map.get("PR"),
                    "ui": comp_map.get("UI"),
                    "s": comp_map.get("S"),
                    "c": comp_map.get("C"),
                    "i": comp_map.get("I"),
                    "a": comp_map.get("A"),
                }
        vendor_refs = ""
        refs = cve.get("references", [])
        if refs and isinstance(refs, list):
            urls = [r.get("url") for r in refs if r.get("url")]
            if urls:
                vendor_refs = urls[0]
        exploit_status = "known_exploited" if False else None  # placeholder: rely on kev_flag for KEV
        products = _extract_products_from_nvd_configs(cve)
        tobj = ThreatObject(
            source="NVD",
            item_type="CVE",
            cve_id=cve_id,
            title=cve_id,
            summary=desc_en,
            link=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
            published_at=published_at,
            last_modified_at=last_mod_at,
            severity=severity,
            kev_flag=False,
            products_text=products,
            raw_payload=json.dumps(cve),
            cvss_vector=vector,
            cvss_base_score=score_val,
            cvss_version=cvss_version,
            cvss_av=cvss_components.get("av"),
            cvss_ac=cvss_components.get("ac"),
            cvss_pr=cvss_components.get("pr"),
            cvss_ui=cvss_components.get("ui"),
            cvss_s=cvss_components.get("s"),
            cvss_c=cvss_components.get("c"),
            cvss_i=cvss_components.get("i"),
            cvss_a=cvss_components.get("a"),
            exploit_status=exploit_status,
            vendor_refs=vendor_refs,
            cwe_id=cwe_id,
        )
        tobj.nvd_product_family = products or (keyword or "")
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


# Abort handling
_abort_flags = {}


def abort_ingest(source):
    """Request that an in-flight ingest for the given source stops."""
    if not source:
        return
    _abort_flags[source.lower()] = True
    _set_status(source, message="Abort requested", progress=0)


def _clear_abort(source):
    if not source:
        return
    _abort_flags.pop(source.lower(), None)


def _abort_requested(source):
    if not source:
        return False
    return _abort_flags.get(source.lower(), False)


# Persistence helpers
def save_threat_objects(threat_objects, source_name=None, ingest_id=None):
    """Insert/update threat objects; secondary feeds update-only for existing CVEs."""
    if not threat_objects:
        return 0, 0, 0
    conn = db.get_connection()
    cur = conn.cursor()
    inserted = 0
    updated = 0
    skipped_missing_base = 0
    total = len(threat_objects)
    processed = 0
    # Preload existing CVEs (and rows) for faster secondary lookups
    existing_cves = set()
    existing_rows_map = None
    if source_name and source_name.lower() != "nvd":
        cur.execute("SELECT * FROM threat_objects WHERE cve_id IS NOT NULL")
        rows = cur.fetchall()
        existing_rows_map = {r["cve_id"].upper(): dict(r) for r in rows if r["cve_id"]}
        existing_cves = set(existing_rows_map.keys())

    def _exec(cur_obj, sql, params, retries=5):
        for attempt in range(retries):
            try:
                cur_obj.execute(sql, params)
                return
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < retries - 1:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise
    def _commit(conn_obj, retries=5):
        for attempt in range(retries):
            try:
                conn_obj.commit()
                return
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < retries - 1:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise

    def _exec_many(cur_obj, sql, rows, retries=5):
        for attempt in range(retries):
            try:
                cur_obj.executemany(sql, rows)
                return
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < retries - 1:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise

    def _progress():
        if source_name:
            if not total:
                pct = 100
            else:
                pct = 75 + int((processed / total) * 25)
                if processed > 0:
                    pct = max(pct, 76)
                if processed >= total:
                    pct = 100
            _set_status(source_name, message=f"Merging {total} item(s)...", progress=pct)

    chunk_size = 100  # commit/flush interval (smaller for snappier progress)

    if _abort_requested(source_name):
        _set_status(source_name, message="Aborted before save", progress=0)
        conn.close()
        return inserted, updated, skipped_missing_base
    # If table is empty, do fast path bulk insert
    cur.execute("SELECT COUNT(*) as c FROM threat_objects")
    total_existing = cur.fetchone()["c"]
    insert_rows = []
    insert_sql = """
        INSERT INTO threat_objects (
            source, item_type, cve_id, title, summary, link,
            published_at, last_modified_at, severity, kev_flag, products_text, nvd_product_family, raw_payload,
            cvss_vector, cvss_base_score, cvss_version, cvss_av, cvss_ac, cvss_pr, cvss_ui, cvss_s, cvss_c, cvss_i, cvss_a,
            exploit_status, vendor_refs, cwe_id, contrib_sources, ingest_id,
            created_at, updated_at, is_enriched, enriched_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    if total_existing == 0:
        now_iso = datetime.utcnow().isoformat()
        for obj in threat_objects:
            if _abort_requested(source_name):
                _set_status(source_name, message="Aborted during save", progress=0)
                conn.commit()
                conn.close()
                return inserted, updated, skipped_missing_base
            insert_rows.append(
                (
                    obj.source,
                    obj.item_type,
                    obj.cve_id,
                    obj.title,
                    obj.summary,
                    obj.link,
                    obj.published_at.isoformat() if isinstance(obj.published_at, datetime) else (obj.published_at or None),
                    obj.last_modified_at.isoformat() if isinstance(obj.last_modified_at, datetime) else (obj.last_modified_at or None),
                    obj.severity,
                    1 if obj.kev_flag else 0,
                    obj.products_text,
                    getattr(obj, "nvd_product_family", None),
                    obj.raw_payload,
                    obj.cvss_vector,
                    obj.cvss_base_score,
                    obj.cvss_version,
                    obj.cvss_av,
                    obj.cvss_ac,
                    obj.cvss_pr,
                    obj.cvss_ui,
                    obj.cvss_s,
                    obj.cvss_c,
                    obj.cvss_i,
                    obj.cvss_a,
                    obj.exploit_status,
                    obj.vendor_refs,
                    obj.cwe_id,
                    obj.source if obj.source else None,
                    ingest_id,
                    now_iso,
                    now_iso,
                    0,
                    None,
                )
            )
            processed += 1
            if processed % 200 == 0:
                _progress()
        if insert_rows:
            for i in range(0, len(insert_rows), chunk_size):
                _exec_many(cur, insert_sql, insert_rows[i : i + chunk_size])
                _commit(conn)
        conn.close()
        inserted = len(insert_rows)
        _progress()
        return inserted, updated, skipped_missing_base
    source_rank = ["NVD", "MSRC", "CISA-KEV", "ACSC", "CERT-NZ", "APPLE"]
    def _rank(src):
        if not src:
            return len(source_rank) + 1
        up = str(src).upper()
        return source_rank.index(up) if up in source_rank else len(source_rank)

    for obj in threat_objects:
        if _abort_requested(source_name):
            _set_status(source_name, message="Aborted during save", progress=0)
            conn.commit()
            conn.close()
            return inserted, updated, skipped_missing_base
        now_iso = datetime.utcnow().isoformat()
        existing = None
        existing_rows = []
        if obj.cve_id:
            cid = (obj.cve_id or "").upper()
            if existing_rows_map is not None:
                existing = existing_rows_map.get(cid)
            else:
                _exec(cur, "SELECT * FROM threat_objects WHERE cve_id=?", (obj.cve_id,))
                existing_rows = cur.fetchall()
                if existing_rows:
                    existing = min(existing_rows, key=lambda r: _rank(r["source"]))
            if not existing and cid and existing_cves and cid not in existing_cves and (obj.source or "").upper() != "NVD":
                skipped_missing_base += 1
                processed += 1
                if processed % 200 == 0:
                    _progress()
                continue
            if not existing and (obj.source or "").upper() != "NVD":
                skipped_missing_base += 1
                processed += 1
                if processed % 200 == 0:
                    _progress()
                continue
        if not existing:
            # fall back to matching by source+title+link for non-CVE items
            if not obj.cve_id:
                _exec(
                    cur,
                    """
                    SELECT * FROM threat_objects
                    WHERE source=? AND title=? AND link=?
                    """,
                    (obj.source, obj.title, obj.link),
                )
                existing = cur.fetchone()
        if existing:
            if isinstance(existing, sqlite3.Row):
                existing = dict(existing)
            existing_sources = set()
            if existing.get("source"):
                existing_sources.add(existing["source"])
            if existing.get("contrib_sources"):
                existing_sources.update([s.strip() for s in existing["contrib_sources"].split(",") if s.strip()])
            if obj.source:
                existing_sources.add(obj.source)
            contrib_sources_val = ", ".join(sorted(existing_sources))

            current_rank = _rank(existing.get("source"))
            incoming_rank = _rank(obj.source)
            primary_update = incoming_rank < current_rank

            # Determine values to persist
            item_type = obj.item_type if primary_update else existing.get("item_type")
            summary = obj.summary if primary_update else existing.get("summary")
            published_at = obj.published_at if primary_update else existing.get("published_at")
            last_modified_at = obj.last_modified_at if primary_update else existing.get("last_modified_at")
            severity = obj.severity if primary_update else existing.get("severity")
            kev_flag = 1 if obj.kev_flag or existing.get("kev_flag") else 0
            products_text = obj.products_text if primary_update else existing.get("products_text")
            nvd_product_family = getattr(obj, "nvd_product_family", None) if primary_update else existing.get("nvd_product_family")
            raw_payload = obj.raw_payload if primary_update else existing.get("raw_payload")
            cvss_vector = obj.cvss_vector if primary_update else existing.get("cvss_vector")
            cvss_base_score = obj.cvss_base_score if primary_update else existing.get("cvss_base_score")
            cvss_version = obj.cvss_version if primary_update else existing.get("cvss_version")
            cvss_av = obj.cvss_av if primary_update else existing.get("cvss_av")
            cvss_ac = obj.cvss_ac if primary_update else existing.get("cvss_ac")
            cvss_pr = obj.cvss_pr if primary_update else existing.get("cvss_pr")
            cvss_ui = obj.cvss_ui if primary_update else existing.get("cvss_ui")
            cvss_s = obj.cvss_s if primary_update else existing.get("cvss_s")
            cvss_c = obj.cvss_c if primary_update else existing.get("cvss_c")
            cvss_i = obj.cvss_i if primary_update else existing.get("cvss_i")
            cvss_a = obj.cvss_a if primary_update else existing.get("cvss_a")
            exploit_status = obj.exploit_status if primary_update else existing.get("exploit_status")
            vendor_refs = obj.vendor_refs if primary_update else existing.get("vendor_refs")
            cwe_id = obj.cwe_id if primary_update else existing.get("cwe_id")
            changed_fields = []
            def _track(field, new, old):
                if (new or None) != (old or None):
                    changed_fields.append(field)
            _track("item_type", item_type, existing.get("item_type"))
            _track("summary", summary, existing.get("summary"))
            _track("published_at", published_at, existing.get("published_at"))
            _track("last_modified_at", last_modified_at, existing.get("last_modified_at"))
            _track("severity", severity, existing.get("severity"))
            _track("products_text", products_text, existing.get("products_text"))
            _track("nvd_product_family", nvd_product_family, existing.get("nvd_product_family"))
            _track("raw_payload", raw_payload, existing.get("raw_payload"))
            _track("cvss_vector", cvss_vector, existing.get("cvss_vector"))
            _track("cvss_base_score", cvss_base_score, existing.get("cvss_base_score"))
            _track("cvss_version", cvss_version, existing.get("cvss_version"))
            _track("cvss_av", cvss_av, existing.get("cvss_av"))
            _track("cvss_ac", cvss_ac, existing.get("cvss_ac"))
            _track("cvss_pr", cvss_pr, existing.get("cvss_pr"))
            _track("cvss_ui", cvss_ui, existing.get("cvss_ui"))
            _track("cvss_s", cvss_s, existing.get("cvss_s"))
            _track("cvss_c", cvss_c, existing.get("cvss_c"))
            _track("cvss_i", cvss_i, existing.get("cvss_i"))
            _track("cvss_a", cvss_a, existing.get("cvss_a"))
            _track("exploit_status", exploit_status, existing.get("exploit_status"))
            _track("vendor_refs", vendor_refs, existing.get("vendor_refs"))
            _track("cwe_id", cwe_id, existing.get("cwe_id"))
            _track("kev_flag", kev_flag, existing.get("kev_flag"))
            is_enriched_val = existing.get("is_enriched") or 0
            enriched_at_val = existing.get("enriched_at")
            # Mark enrichment when a secondary feed updates the record
            if (obj.source or "").upper() != "NVD":
                is_enriched_val = 1
                enriched_at_val = now_iso
                _track("is_enriched", is_enriched_val, existing.get("is_enriched"))
                _track("enriched_at", enriched_at_val, existing.get("enriched_at"))
            # Update existing row
            _exec(
                cur,
                """
                UPDATE threat_objects
                SET source=?, item_type=?, summary=?, published_at=?, last_modified_at=?, severity=?, kev_flag=?, products_text=?, nvd_product_family=?, raw_payload=?, cvss_vector=?, cvss_base_score=?, cvss_version=?, cvss_av=?, cvss_ac=?, cvss_pr=?, cvss_ui=?, cvss_s=?, cvss_c=?, cvss_i=?, cvss_a=?, exploit_status=?, vendor_refs=?, cwe_id=?, contrib_sources=?, ingest_id=?, is_enriched=?, enriched_at=?, updated_at=?
                WHERE id=?
                """,
                (
                    existing.get("source") if current_rank <= incoming_rank else obj.source,
                    item_type,
                    summary,
                    published_at.isoformat() if isinstance(published_at, datetime) else (published_at or None),
                    last_modified_at.isoformat() if isinstance(last_modified_at, datetime) else (last_modified_at or None),
                    severity,
                    kev_flag,
                    products_text,
                    nvd_product_family,
                    raw_payload,
                    cvss_vector,
                    cvss_base_score,
                    cvss_version,
                    cvss_av,
                    cvss_ac,
                    cvss_pr,
                    cvss_ui,
                    cvss_s,
                    cvss_c,
                    cvss_i,
                    cvss_a,
                    exploit_status,
                    vendor_refs,
                    cwe_id,
                    contrib_sources_val,
                    ingest_id if ingest_id is not None else existing.get("ingest_id"),
                    is_enriched_val,
                    enriched_at_val,
                    now_iso,
                    existing["id"],
                ),
            )
            if changed_fields:
                try:
                    db.insert_cve_history(
                        obj.cve_id,
                        obj.source,
                        "update" if primary_update else "enrich",
                        changed_fields=",".join(changed_fields),
                        raw_payload=obj.raw_payload,
                    )
                except Exception:
                    pass
            updated += 1
            continue
        insert_rows.append(
            (
                obj.source,
                obj.item_type,
                obj.cve_id,
                obj.title,
                obj.summary,
                obj.link,
                obj.published_at.isoformat() if isinstance(obj.published_at, datetime) else (obj.published_at or None),
                obj.last_modified_at.isoformat() if isinstance(obj.last_modified_at, datetime) else (obj.last_modified_at or None),
                obj.severity,
                1 if obj.kev_flag else 0,
                obj.products_text,
                getattr(obj, "nvd_product_family", None),
                obj.raw_payload,
                obj.cvss_vector,
                obj.cvss_base_score,
                obj.cvss_version,
                obj.cvss_av,
                obj.cvss_ac,
                obj.cvss_pr,
                obj.cvss_ui,
                obj.cvss_s,
                obj.cvss_c,
                obj.cvss_i,
                obj.cvss_a,
                obj.exploit_status,
                obj.vendor_refs,
                obj.cwe_id,
                obj.source if obj.source else None,
                ingest_id,
                now_iso,
                now_iso,
                0,
                None,
            )
        )
        inserted += 1
        processed += 1
        if processed % chunk_size == 0:
            _commit(conn)
            _progress()
        if processed % 200 == 0:
            _progress()

    if insert_rows:
        for i in range(0, len(insert_rows), chunk_size):
            _exec_many(cur, insert_sql, insert_rows[i : i + chunk_size])
            _commit(conn)
    _commit(conn)
    conn.close()
    _progress()
    return inserted, updated, skipped_missing_base


def ingest_source(source_name):
    """Fetch, normalise, and persist a given source."""
    inserted = 0
    updated = 0
    skipped = 0
    source_name = (source_name or "").lower()
    _clear_abort(source_name)
    all_objs = []
    _set_last_error(source_name, None)
    _set_status(source_name, message="Starting", progress=0)
    run_id = None
    try:
        try:
            run_id = db.start_ingest_run(source_name, status="running", message="Starting ingest")
        except Exception:
            run_id = None
        if source_name == "cisa":
            try:
                raw = fetch_cisa_kev()
                all_objs = normalise_cisa(raw)
                _set_status(source_name, message=f"Fetched CISA KEV ({len(all_objs)} items)", progress=50)
            except Exception as exc:
                _set_last_error(source_name, str(exc))
                if run_id:
                    db.finish_ingest_run(run_id, status="failed", message=str(exc))
                return 0, 0, 0
        elif source_name == "acsc":
            try:
                raw = fetch_acsc_alerts()
                all_objs = normalise_acsc(raw)
                _set_status(source_name, message=f"Fetched ACSC ({len(all_objs)} items)", progress=50)
            except Exception as exc:
                _set_last_error(source_name, str(exc))
                if run_id:
                    db.finish_ingest_run(run_id, status="failed", message=str(exc))
                return 0, 0, 0
        elif source_name == "certnz":
            try:
                raw = fetch_cert_nz()
                all_objs = normalise_cert(raw)
                _set_status(source_name, message=f"Fetched CERT-NZ ({len(all_objs)} items)", progress=50)
            except Exception as exc:
                _set_last_error(source_name, str(exc))
                if run_id:
                    db.finish_ingest_run(run_id, status="failed", message=str(exc))
                return 0, 0, 0
        elif source_name == "apple":
            try:
                raw = fetch_apple_updates()
                all_objs = normalise_apple(raw)
                _set_status(source_name, message=f"Fetched Apple RSS ({len(all_objs)} items)", progress=50)
            except Exception as exc:
                _set_last_error(source_name, str(exc))
                if run_id:
                    db.finish_ingest_run(run_id, status="failed", message=str(exc))
                return 0, 0, 0
        elif source_name == "msrc":
            try:
                from . import import_msrc

                inserted, updated = import_msrc.import_msrc_threats(ingest_id=run_id)
                if inserted == 0 and updated == 0:
                    status_entry = _last_status.get(source_name, {})
                    if not status_entry.get("error"):
                        _set_last_error(source_name, "No data ingested (empty feed or duplicates).")
                if run_id:
                    db.finish_ingest_run(run_id, status="completed", inserted=inserted, updated=updated, message=_last_status.get(source_name, {}).get("message"))
                return inserted, updated, 0
            except Exception as exc:
                _set_last_error(source_name, str(exc))
                if run_id:
                    db.finish_ingest_run(run_id, status="failed", message=str(exc))
                return 0, 0, 0
        elif source_name == "nvd":
            try:
                cfg = get_nvd_filter_config()
                days = cfg.get("days") or 10
                keywords = cfg.get("keywords") or []
                if run_id:
                    try:
                        db.finish_ingest_run(run_id, status="running", inserted=0, updated=0, message=f"Config snapshot: days={days}, keywords={keywords}")
                    except Exception:
                        pass
                raw = fetch_nvd_recent(days)
                vulns = raw.get("vulnerabilities", []) if isinstance(raw, dict) else []
                if vulns:
                    all_objs.extend(normalise_nvd(raw, keyword=None))
                # Also fetch by keywords to supplement the date window
                keyword_total = 0
                if keywords:
                    for kw, resp in fetch_nvd_for_keywords(keywords):
                        all_objs.extend(normalise_nvd(resp, keyword=kw))
                        items = resp.get("vulnerabilities", []) if isinstance(resp, dict) else []
                        keyword_total += len(items)
                msg = f"Fetched NVD: {len(vulns)} by date (last {days} days)"
                if keywords:
                    msg += f"; {keyword_total} by keywords ({', '.join(keywords)})"
                _set_status(source_name, message=msg, progress=50)
            except Exception as exc:
                _set_last_error(source_name, str(exc))
                if run_id:
                    db.finish_ingest_run(run_id, status="failed", message=str(exc))
                return 0, 0, 0

        if _abort_requested(source_name):
            _set_status(source_name, message="Aborted before merge", progress=0)
            if run_id:
                db.finish_ingest_run(run_id, status="aborted", inserted=0, updated=0, message="Aborted before merge")
            return inserted, updated, skipped

        # Deduplicate by CVE (keep first) to avoid unique constraint errors within a batch
        if all_objs:
            deduped = []
            seen_cves = set()
            for obj in all_objs:
                key = (obj.cve_id or "").upper()
                if key and key in seen_cves:
                    continue
                if key:
                    seen_cves.add(key)
                deduped.append(obj)
            if len(deduped) != len(all_objs):
                _set_status(source_name, message=f"Deduped {len(all_objs)-len(deduped)} duplicates by CVE; merging {len(deduped)} item(s)...", progress=70)
            all_objs = deduped

        # If we have a batch, note we're saving/merging
        if all_objs:
            _set_status(source_name, message=f"Merging {len(all_objs)} item(s)...", progress=75)

        try:
            inserted, updated, skipped = save_threat_objects(all_objs, source_name=source_name, ingest_id=run_id)
        except Exception as exc:
            _set_status(source_name, error=f"Save failed: {exc}", progress=0)
            if run_id:
                db.finish_ingest_run(run_id, status="failed", inserted=inserted, updated=updated, message=str(exc))
            return 0, 0, 0

        status_entry = _last_status.get(source_name, {})
        if inserted == 0 and updated == 0 and not status_entry.get("error"):
            _set_status(source_name, error="No data ingested or updated (empty feed or duplicates).", progress=0)
        else:
            extra = f", skipped (no base CVE): {skipped}" if skipped else ""
            _set_status(source_name, message=f"Completed (new: {inserted}, updated: {updated}, total: {len(all_objs)}{extra})", progress=100)
        if run_id:
            db.finish_ingest_run(run_id, status="completed", inserted=inserted, updated=updated, message=status_entry.get("message"))
        return inserted, updated, skipped
    finally:
        idx_info = None
        try:
            idx_info = db.ensure_indexes()
        except Exception as exc:
            idx_info = {"status": f"error: {exc}", "checked_at": datetime.utcnow().isoformat()}
        if idx_info:
            print(f"[DB] Index refresh for threat_objects: {idx_info.get('status')} at {idx_info.get('checked_at')}")
            # append index status to last status message
            existing = _last_status.get(source_name, {})
            msg = existing.get("message")
            joined = f"Index status: {idx_info.get('status')} @ {idx_info.get('checked_at')}"
            new_msg = f"{msg} | {joined}" if msg else joined
            _set_status(
                source_name,
                error=existing.get("error"),
                message=new_msg,
                progress=existing.get("progress"),
            )


def check_source_connectivity(source_name):
    """Lightweight reachability check without saving data."""
    source_name = (source_name or "").lower()
    url_map = {
        "cisa": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "acsc": "https://www.cyber.gov.au/acsc/view-all-content/alerts/rss.xml",
        "certnz": "https://www.cert.govt.nz/assets/feeds/advisories.rss",
        "msrc": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
        "apple": "https://support.apple.com/en-us/rss/securityupdates.rss",
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


# Enrichment routines
def enrich_nvd_with_cisa_kev():
    kev_rows = db.get_threats_by_source("CISA-KEV")
    updated = 0
    for row in kev_rows:
        cve = row.get("cve_id")
        if not cve:
            continue
        nvd_row = db.get_nvd_threat_by_cve(cve)
        if not nvd_row:
            continue
        db.update_nvd_threat_for_enrichment(
            nvd_row["id"],
            kev_flag=True,
        )
        updated += 1
    print(f"enrich_nvd_with_cisa_kev: updated {updated} NVD rows")


def enrich_nvd_with_msrc():
    msrc_rows = db.get_threats_by_source("MSRC")
    updated = 0
    for row in msrc_rows:
        cve = row.get("cve_id")
        if not cve:
            continue
        nvd_row = db.get_nvd_threat_by_cve(cve)
        if not nvd_row:
            continue
        # Parse existing payloads
        def _safe_json(val):
            if not val:
                return None
            try:
                return json.loads(val)
            except Exception:
                return None
        nvd_payload = _safe_json(nvd_row.get("raw_payload"))
        msrc_payload = _safe_json(row.get("raw_payload"))
        merged_payload = json.dumps({"nvd": nvd_payload, "msrc": msrc_payload})

        base_products = nvd_row.get("products_text") or ""
        msrc_products = row.get("products_text") or ""
        combined_products = None
        if msrc_products:
            if not base_products:
                combined_products = msrc_products
            elif msrc_products not in base_products:
                combined_products = base_products + " | " + msrc_products

        db.update_nvd_threat_for_enrichment(
            nvd_row["id"],
            merged_raw_payload=merged_payload,
            products_text=combined_products,
        )
        updated += 1
    print(f"enrich_nvd_with_msrc: updated {updated} NVD rows")


def enrich_all_cve_sources():
    """
    Enrich NVD CVE threats with secondary sources (MSRC and CISA-KEV).
    This should be safe to run multiple times.
    """
    try:
        enrich_nvd_with_msrc()
    except Exception as exc:
        print("Error in enrich_nvd_with_msrc:", exc)
    try:
        enrich_nvd_with_cisa_kev()
    except Exception as exc:
        print("Error in enrich_nvd_with_cisa_kev:", exc)


# Placeholder functions for completeness (not yet implemented)
def fetch_cert_nz_feed():
    return fetch_cert_nz()


# NVD filter configuration
_NVD_CONFIG_PATH = Path(__file__).parent / "nvd_config.json"
_NVD_DEFAULT_CONFIG = {"days": 10, "keywords": ["Windows", "Cisco", "VMware", "Fortinet", "Linux"]}


def get_nvd_filter_config():
    if _NVD_CONFIG_PATH.exists():
        try:
            with open(_NVD_CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                days = int(data.get("days", _NVD_DEFAULT_CONFIG["days"]))
                keywords = data.get("keywords") or _NVD_DEFAULT_CONFIG["keywords"]
                if isinstance(keywords, str):
                    keywords = [k.strip() for k in keywords.split(",") if k.strip()]
                return {"days": days, "keywords": keywords}
        except Exception:
            pass
    return dict(_NVD_DEFAULT_CONFIG)


def save_nvd_filter_config(days, keywords):
    data = {"days": int(days), "keywords": keywords}
    try:
        with open(_NVD_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass
