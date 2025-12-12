"""
MSRC importer that fetches release headers and CVRF vulnerability details,
and upserts them into the threat_objects table using the existing ThreatObject
shape used by other ingesters.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, List, Optional

import requests

from . import db

MSRC_SOURCE = "MSRC"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
ACCEPT = "application/json"


def _map_severity(val: Optional[str], score: Optional[float] = None) -> str:
    if val:
        v = val.lower()
        if "critical" in v:
            return "Critical"
        if "important" in v or "high" in v:
            return "High"
        if "moderate" in v or "medium" in v:
            return "Medium"
        if "low" in v:
            return "Low"
    if score is not None:
        try:
            s = float(score)
            if s >= 9:
                return "Critical"
            if s >= 7:
                return "High"
            if s >= 4:
                return "Medium"
            return "Low"
        except Exception:
            pass
    return "High"


def _safe_get_date(val: Optional[str]) -> Optional[str]:
    """Return ISO datetime string or None; ignore sentinel ancient dates."""
    if not val:
        return None
    if isinstance(val, str) and val.startswith("0001-01-01"):
        return None
    try:
        # Normalise to ISO string for storage consistency
        return datetime.fromisoformat(val.replace("Z", "+00:00")).isoformat()
    except Exception:
        return None


def _extract_description(v: Dict) -> str:
    notes = v.get("Notes") or []
    if isinstance(notes, list):
        for n in notes:
            if not n:
                continue
            n_type = n.get("Type")
            n_title = str(n.get("Title") or "").lower()
            val = n.get("Text") or n.get("Value") or n.get("Description") or ""
            if n_type == 2 or n_title == "description":
                if val:
                    return val
        for n in notes:
            if not n:
                continue
            val = n.get("Text") or n.get("Value") or n.get("Description") or ""
            if val:
                return val
    threats = v.get("Threats") or []
    if isinstance(threats, list):
        for t in threats:
            if not t:
                continue
            desc = t.get("Description") or {}
            if isinstance(desc, dict):
                txt = desc.get("Value") or desc.get("Text") or ""
                if txt:
                    return txt
    if v.get("Title"):
        return v["Title"]
    return ""


def _extract_products(v: Dict, product_map: Dict[str, str]) -> str:
    product_ids: List[str] = []
    statuses = v.get("ProductStatuses") or []
    if isinstance(statuses, list):
        for st in statuses:
            if not st:
                continue
            pids = st.get("ProductID") or []
            if isinstance(pids, list):
                product_ids.extend(pids)
    remeds = v.get("Remediations") or []
    if isinstance(remeds, list):
        for r in remeds:
            if not r:
                continue
            pids = r.get("ProductID") or []
            if isinstance(pids, list):
                product_ids.extend(pids)
    product_ids = list(dict.fromkeys(pid for pid in product_ids if pid))
    names = [product_map.get(pid, pid) for pid in product_ids]
    return ", ".join(names)


def _build_product_map(product_tree: Dict) -> Dict[str, str]:
    product_name_map: Dict[str, str] = {}

    def _walk(node):
        if not node:
            return
        if isinstance(node, dict):
            pid = node.get("ProductID")
            val = node.get("Value")
            if pid and val:
                product_name_map[pid] = val
            for key in ("Branch", "FullProductName", "Product"):
                child = node.get(key)
                if isinstance(child, list):
                    for c in child:
                        _walk(c)
                elif isinstance(child, dict):
                    _walk(child)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(product_tree)
    return product_name_map


def _upsert_threat(obj) -> bool:
    """Insert or update a threat_object row. Returns True if inserted/updated."""
    conn = db.get_connection()
    cur = conn.cursor()
    now_iso = datetime.utcnow().isoformat()
    cur.execute(
        "SELECT id FROM threat_objects WHERE source=? AND IFNULL(cve_id,'')=IFNULL(?, '')",
        (obj.source, obj.cve_id),
    )
    row = cur.fetchone()
    now_iso = datetime.utcnow().isoformat()
    payload = (
        obj.item_type,
        obj.title,
        obj.summary,
        obj.link,
        obj.published_at.isoformat() if isinstance(obj.published_at, datetime) else (obj.published_at or None),
        obj.severity,
        1 if obj.kev_flag else 0,
        obj.products_text,
        obj.raw_payload,
    )
    if row:
        cur.execute(
            """
            UPDATE threat_objects
            SET item_type=?, title=?, summary=?, link=?, published_at=?, severity=?, kev_flag=?, products_text=?, raw_payload=?, cvss_vector=?, cvss_base_score=?, cvss_version=?, cvss_av=?, cvss_ac=?, cvss_pr=?, cvss_ui=?, cvss_s=?, cvss_c=?, cvss_i=?, cvss_a=?, updated_at=?
            WHERE id=?
            """,
            (*payload,
             vector, score, cvss_version,
             cvss_components.get("av"), cvss_components.get("ac"), cvss_components.get("pr"),
             cvss_components.get("ui"), cvss_components.get("s"), cvss_components.get("c"),
             cvss_components.get("i"), cvss_components.get("a"),
             now_iso, row["id"]),
        )
    else:
        cur.execute(
            """
            INSERT INTO threat_objects (source, item_type, cve_id, title, summary, link, published_at, severity, kev_flag, products_text, raw_payload, cvss_vector, cvss_base_score, created_at, updated_at, is_enriched, enriched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                getattr(obj, "cvss_vector", vector),
                getattr(obj, "cvss_base_score", score),
                now_iso,
                now_iso,
                0,
                None,
            ),
        )
    conn.commit()
    conn.close()
    return True


def _parse_vulnerabilities(cvrf_data: Dict, release_meta: Dict, threat_cls, stats: Optional[Dict] = None) -> List:
    vulns = cvrf_data.get("Vulnerability") or []
    if not isinstance(vulns, list):
        return []
    product_map = _build_product_map(cvrf_data.get("ProductTree") or {})
    if stats is None:
        stats = {}
    stats.setdefault("parsed_cves", 0)
    stats.setdefault("skipped_no_cve", 0)
    stats.setdefault("skipped_bad_entry", 0)
    threats: List[ThreatObject] = []
    for v in vulns:
        try:
            if not v or not isinstance(v, dict):
                stats["skipped_bad_entry"] = stats.get("skipped_bad_entry", 0) + 1
                continue
            cve = v.get("CVE") or v.get("ID")
            if isinstance(cve, list) and cve:
                cve = cve[0]
            if cve and not isinstance(cve, str):
                cve = str(cve)
            if not cve:
                stats["skipped_no_cve"] = stats.get("skipped_no_cve", 0) + 1
                continue
            title = v.get("Title") or cve
            if isinstance(title, dict):
                title = title.get("Value") or title.get("Text") or title.get("Title") or cve
            elif isinstance(title, list) and title:
                first_title = title[0] or {}
                if isinstance(first_title, dict):
                    title = first_title.get("Value") or first_title.get("Text") or first_title.get("Title") or cve
                else:
                    title = first_title
            if title and not isinstance(title, str):
                title = str(title)
            desc = _extract_description(v)
            if desc and not isinstance(desc, str):
                desc = str(desc)
            cvss = v.get("CVSSScoreSets") or []
            score = None
            vector = None
            cvss_version = None
            cvss_components = {}
            if isinstance(cvss, list) and cvss:
                first = cvss[0] or {}
                score = first.get("BaseScore") or first.get("Score")
                vector = first.get("Vector") or first.get("VectorString")
                cvss_version = first.get("Version") or None
                comp_map = {}
                if vector and isinstance(vector, str):
                    for p in vector.split("/"):
                        if ":" in p:
                            k, vcomp = p.split(":", 1)
                            comp_map[k] = vcomp
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
            severity = _map_severity(v.get("Severity") or v.get("BaseSeverity"), score)
            products = _extract_products(v, product_map)
            published = _safe_get_date(v.get("ReleaseDate")) or _safe_get_date(release_meta.get("initial_release")) or _safe_get_date(release_meta.get("current_release"))
            revs = v.get("RevisionHistory") or []
            updated = None
            if isinstance(revs, list) and revs:
                updated = _safe_get_date(revs[-1].get("Date"))
            if not updated:
                updated = _safe_get_date(release_meta.get("current_release")) or published
            link = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
            raw_payload = json.dumps(
                {
                    "release": release_meta,
                    "vulnerability": v,
                }
            )
            cwe_raw = v.get("CWE") or None
            cwe_val = None
            if isinstance(cwe_raw, list):
                first_cwe = cwe_raw[0] if cwe_raw else None
                if isinstance(first_cwe, dict):
                    cwe_val = first_cwe.get("ID") or first_cwe.get("Value") or first_cwe.get("Text") or first_cwe.get("Title")
                else:
                    cwe_val = first_cwe
            elif isinstance(cwe_raw, dict):
                cwe_val = cwe_raw.get("ID") or cwe_raw.get("Value") or cwe_raw.get("Text") or cwe_raw.get("Title")
            else:
                cwe_val = cwe_raw
            if cwe_val and not isinstance(cwe_val, str):
                cwe_val = str(cwe_val)
            threats.append(
                threat_cls(
                    source=MSRC_SOURCE,
                    item_type="VULNERABILITY",
                    cve_id=cve,
                    title=title,
                    summary=desc,
                    link=link,
                    published_at=published,
                    last_modified_at=updated,
                    severity=severity,
                    kev_flag=False,
                    products_text=products,
                    raw_payload=raw_payload,
                    cvss_vector=vector,
                    cvss_base_score=score,
                    cvss_version=cvss_version,
                    cvss_av=cvss_components.get("av"),
                    cvss_ac=cvss_components.get("ac"),
                    cvss_pr=cvss_components.get("pr"),
                    cvss_ui=cvss_components.get("ui"),
                    cvss_s=cvss_components.get("s"),
                    cvss_c=cvss_components.get("c"),
                    cvss_i=cvss_components.get("i"),
                    cvss_a=cvss_components.get("a"),
                    cwe_id=cwe_val,
                )
            )
            stats["parsed_cves"] = stats.get("parsed_cves", 0) + 1
        except Exception:
            stats["skipped_bad_entry"] = stats.get("skipped_bad_entry", 0) + 1
            continue
    return threats


def _fetch_json(session: requests.Session, url: str) -> Dict:
    try:
        resp = session.get(url, timeout=20)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.SSLError:
        resp = session.get(url, timeout=20, verify=False)
        resp.raise_for_status()
        return resp.json()


def _fetch_cvrf(session: requests.Session, url: str) -> Optional[Dict]:
    try:
        resp = session.get(url, timeout=30)
    except requests.exceptions.SSLError:
        resp = session.get(url, timeout=30, verify=False)
    resp.raise_for_status()
    content_type = resp.headers.get("Content-Type", "").lower()
    if "json" in content_type:
        return resp.json()
    # Fallback XML parse if needed
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(resp.text)
        # Minimal XML -> dict conversion for Vulnerability nodes
        vulns = []
        for vuln in root.findall(".//{*}Vulnerability"):
            vid = vuln.get("ID") or ""
            title_el = vuln.find(".//{*}Title")
            title = title_el.text if title_el is not None else vid
            desc_el = vuln.find(".//{*}Note[@Type='Description']")
            desc = desc_el.text if desc_el is not None else ""
            sev = ""
            score_el = vuln.find(".//{*}CVSSScoreSets/{*}ScoreSet/{*}BaseScore")
            if score_el is not None and score_el.text:
                sev = score_el.text
            vulns.append(
                {
                    "CVE": vid,
                    "Title": title,
                    "Severity": sev,
                    "Notes": [{"Type": 2, "Text": desc}],
                }
            )
        return {"Vulnerability": vulns}
    except Exception:
        return None


def import_msrc_threats(ingest_id=None) -> tuple[int, int]:
    """Main entry point for scheduled/CLI ingestion."""
    # Lazy import to avoid circular import at module load
    from . import threat_ingestion

    ThreatObject = threat_ingestion.ThreatObject
    session = requests.Session()
    session.headers.update({"User-Agent": UA, "Accept": ACCEPT})
    base_url = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
    try:
        threat_ingestion._set_status("msrc", message="Fetching MSRC releases", progress=5)
        updates = _fetch_json(session, base_url)
    except Exception as exc:
        threat_ingestion._set_status("msrc", error=f"Failed to fetch MSRC updates: {exc}", progress=0)
        return 0

    items = updates.get("value") or []
    all_threats: List[ThreatObject] = []
    if not items:
        threat_ingestion._set_status("msrc", error="MSRC updates response contained no releases.", progress=0)
        return 0

    total = len(items)
    stats = {
        "releases_total": total,
        "releases_with_cvrf": 0,
        "parsed_cves": 0,
        "skipped_no_cve": 0,
    }
    ingest_log = []
    for idx, header in enumerate(items):
        cvrf_url = header.get("CvrfUrl")
        release_id = header.get("ID")
        if not cvrf_url:
            ingest_log.append({"release_id": release_id, "status": "skip", "reason": "no cvrf url"})
            continue
        release_meta = {
            "release_id": release_id,
            "release_title": header.get("DocumentTitle"),
            "initial_release": header.get("InitialReleaseDate"),
            "current_release": header.get("CurrentReleaseDate"),
            "cvrf_url": cvrf_url,
        }
        try:
            threat_ingestion._set_status("msrc", message=f"Fetching CVRF {release_id}", progress=int((idx / total) * 90))
            cvrf = _fetch_cvrf(session, cvrf_url)
        except Exception as exc:
            threat_ingestion._set_status("msrc", error=f"Failed CVRF fetch for {release_id}: {exc}", progress=int((idx / total) * 90))
            ingest_log.append({"release_id": release_id, "status": "error_fetch", "reason": str(exc)})
            continue
        if not cvrf:
            ingest_log.append({"release_id": release_id, "status": "error_fetch", "reason": "empty cvrf"})
            continue
        stats["releases_with_cvrf"] += 1
        if not isinstance(cvrf, dict):
            ingest_log.append({"release_id": release_id, "status": "error_parse", "reason": f"unexpected cvrf type {type(cvrf)}"})
            continue
        try:
            threats = _parse_vulnerabilities(cvrf, release_meta, ThreatObject, stats)
        except Exception as exc:
            threat_ingestion._set_status("msrc", error=f"Failed to parse CVRF for {release_id}: {exc}", progress=int((idx / total) * 90))
            ingest_log.append({"release_id": release_id, "status": "error_parse", "reason": str(exc)})
            continue
        ingest_log.append({"release_id": release_id, "status": "ok", "vulns": len(threats)})
        all_threats.extend(threats)
    inserted, updated, _ = threat_ingestion.save_threat_objects(all_threats, source_name="msrc", ingest_id=ingest_id)
    ok = sum(1 for e in ingest_log if e.get("status") == "ok")
    errs = [e for e in ingest_log if e.get("status") != "ok"]
    err_ids = [e.get("release_id") for e in errs if e.get("release_id")]
    err_preview = ", ".join(err_ids[:5]) if err_ids else ""
    summary_msg = (
        f"Completed. Releases: {stats.get('releases_total', 0)} (cvrf: {stats.get('releases_with_cvrf', 0)}); "
        f"CVEs parsed: {stats.get('parsed_cves', 0)}; skipped (no CVE): {stats.get('skipped_no_cve', 0)}; "
        f"skipped (bad entry): {stats.get('skipped_bad_entry', 0)}; "
        f"release OK: {ok}, errors: {len(errs)}"
    )
    print(f"[MSRC] {summary_msg}")
    if err_preview:
        print(f"[MSRC] Error releases (first 5): {err_preview}")
    # Log a concise per-release summary for debugging
    print(f"[MSRC] Release ingest: ok {ok}, errors {len(errs)}")
    for e in errs[:10]:
        print(f"[MSRC] Issue for {e.get('release_id')}: {e.get('status')} ({e.get('reason')})")
    if len(errs) > 10:
        print(f"[MSRC] ... and {len(errs)-10} more errors (truncated)")
    threat_ingestion._set_status("msrc", message=summary_msg, progress=100, error=None)
    return inserted, updated
