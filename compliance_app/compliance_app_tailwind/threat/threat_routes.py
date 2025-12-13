"""Threat ingestion and admin views blueprint."""

from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET
from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
import requests

from compliance_app.compliance_app_tailwind.auth_helpers import admin_required
from compliance_app.compliance_app_tailwind import db
from compliance_app.compliance_app_tailwind.threat import threat_ingestion


NOT_FOUND = "Not found"

threats_bp = Blueprint("threats", __name__, url_prefix="/admin/threats")


@threats_bp.route("/", methods=["GET"], endpoint="admin_threats")
@admin_required
def admin_threats():
    """List threat objects with optional filtering."""
    def _fmt_dt(val):
        if not val:
            return "—"
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt.strftime("%d/%m/%Y")
        except Exception:
            return val
    def _fmt_dt_time(val):
        if not val:
            return "—"
        try:
            dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            return dt.strftime("%d/%m/%Y %I:%M %p")
        except Exception:
            return val

    source = request.args.get("source") or ""
    source_map = {
        "msrc": "MSRC",
        "microsoft": "MSRC",
        "nvd": "NVD",
        "acsc": "ACSC",
        "cisa": "CISA-KEV",
        "apple": "APPLE",
    }
    source_filter = source_map.get(source.lower(), source)
    q = request.args.get("q") or ""
    severity = request.args.get("severity") or ""
    date_range = request.args.get("date_range") or ""
    kev_filter = request.args.get("kev_flag") or ""
    raw_threats = db.admin_list_threats(
        source=source_filter if source and source != "all" and source != "none" else None,
        q=q or None,
        severity=severity if severity and severity.lower() != "all" else None,
        kev_filter=kev_filter if kev_filter in ["yes", "no"] else None,
    )
    def _parse_dt(val):
        if not val:
            return None
        try:
            if isinstance(val, datetime):
                dt = val
            else:
                dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
    if date_range:
        now = datetime.now(timezone.utc)
        start_dt = None
        if date_range == "today":
            start_dt = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        elif date_range == "week":
            start_dt = now - timedelta(days=7)
        elif date_range == "month":
            start_dt = now - timedelta(days=30)
        if start_dt:
            filtered = []
            for t in raw_threats:
                pub_dt = _parse_dt(t.get("published_at")) or _parse_dt(t.get("created_at")) or _parse_dt(t.get("updated_at"))
                if not pub_dt:
                    continue
                if pub_dt >= start_dt:
                    filtered.append(t)
            raw_threats = filtered
    threats = []
    badge_threshold_days = 7
    for t in raw_threats:
        row = dict(t)
        row["published_fmt"] = _fmt_dt(row.get("published_at"))
        created_raw = row.get("created_at")
        updated_raw = row.get("updated_at")
        is_enriched = bool(row.get("is_enriched"))
        row["badge_enriched"] = is_enriched
        try:
            created_dt = datetime.fromisoformat(created_raw) if created_raw else None
        except Exception:
            created_dt = None
        try:
            updated_dt = datetime.fromisoformat(updated_raw) if updated_raw else None
        except Exception:
            updated_dt = None
        if created_dt:
            row["badge_new"] = (datetime.utcnow() - created_dt).days <= badge_threshold_days and not is_enriched
        else:
            row["badge_new"] = False
        row["badge_updated"] = False
        if created_dt and updated_dt and updated_dt > created_dt:
            row["badge_updated"] = True
        threats.append(row)

    # Simple pagination (default 5 per page)
    per_page = 5
    page = request.args.get("page", default=1, type=int)
    total = len(threats)
    total_pages = max((total + per_page - 1) // per_page, 1)
    if page < 1:
        page = 1
    if page > total_pages:
        page = total_pages
    start = (page - 1) * per_page
    end = start + per_page
    threats_page = threats[start:end]
    sources = ["CISA-KEV", "ACSC", "MSRC", "NVD", "APPLE"]
    stats = db.admin_threat_summary(sources)
    feed_entry_counts = db.admin_feed_entry_counts(sources)
    nvd_cisa_overlap = db.count_nvd_with_feed("CISA-KEV")
    nvd_msrc_overlap = db.count_nvd_with_feed("MSRC")
    recent_counts = db.admin_threat_recent_counts(sources, days=7)
    ingest_history = []
    last_ingest_run = None
    if source:
        try:
            ingest_history = db.get_ingest_runs(source.upper(), limit=5)
            last_ingest_run = ingest_history[0] if ingest_history else None
            for run in ingest_history:
                try:
                    dt_start = datetime.fromisoformat(str(run.get("started_at")).replace("Z", "+00:00"))
                    run["started_date"] = dt_start.strftime("%d/%m/%Y")
                    run["started_time"] = dt_start.strftime("%I:%M %p")
                except Exception:
                    run["started_date"] = run.get("started_at")
                    run["started_time"] = ""
                try:
                    dt_finish = datetime.fromisoformat(str(run.get("finished_at")).replace("Z", "+00:00"))
                    run["finished_date"] = dt_finish.strftime("%d/%m/%Y")
                    run["finished_time"] = dt_finish.strftime("%I:%M %p")
                except Exception:
                    run["finished_date"] = run.get("finished_at")
                    run["finished_time"] = ""
        except Exception:
            ingest_history = []
            last_ingest_run = None
    for _, stat in stats.items():
        stat["last_created_fmt"] = _fmt_dt(stat.get("last_created"))
        stat["last_activity_fmt"] = _fmt_dt(stat.get("last_activity"))

    raw_status = threat_ingestion.get_last_status()
    nvd_config = threat_ingestion.get_nvd_filter_config()
    last_status = {}
    for k, v in raw_status.items():
        last_status[k] = {
            "error": v.get("error"),
            "checked_at": _fmt_dt(v.get("checked_at")),
            "message": v.get("message"),
            "progress": v.get("progress"),
        }

    feed_labels = {
        "cisa": "CISA-KEV",
        "acsc": "ACSC",
        "msrc": "MSRC",
        "nvd": "NVD",
        "apple": "Apple Security Updates",
    }
    feed_key_lookup = {v: k for k, v in feed_labels.items()}
    feed_key_lookup.update({
        "CISA-KEV": "cisa",
        "ACSC": "acsc",
        "MSRC": "msrc",
        "NVD": "nvd",
        "National Vulnerability Database": "nvd",
        "National Vulnerability Database (NVD), published by NIST": "nvd",
        "APPLE": "apple",
        "Apple": "apple",
        "Apple Security Updates": "apple",
        "CISA Known Exploited Vulnerabilities (CISA)": "cisa",
    })
    feed_roles = {
        "nvd": "Primary",
        "acsc": "Primary",
        "cisa": "Secondary",
        "msrc": "Secondary",
        "apple": "Secondary",
    }
    return render_template(
        "admin_threats.html",
        threats=threats_page,
        source=source,
        q=q,
        severity=severity,
        kev_filter=kev_filter,
        date_range=date_range,
        sources=sources,
        stats=stats,
        last_errors=last_status,
        feed_labels=feed_labels,
        feed_key_lookup=feed_key_lookup,
        feed_roles=feed_roles,
        recent_counts=recent_counts,
        ingest_history=ingest_history,
        last_ingest_run=last_ingest_run,
        feed_entry_counts=feed_entry_counts,
        nvd_cisa_overlap=nvd_cisa_overlap,
        nvd_msrc_overlap=nvd_msrc_overlap,
        nvd_config=nvd_config,
        pagination={
            "page": page,
            "total_pages": total_pages,
            "per_page": per_page,
            "total": total,
        },
        page_name="templates/admin_threats.html",
    )


@threats_bp.route("/fetch/", methods=["POST"], endpoint="admin_threats_fetch")
@admin_required
def admin_threats_fetch():
    """Trigger ingestion for a given source and redirect back."""
    source = (request.form.get("source") or "").lower()
    # If NVD and filters are provided, persist them before ingest
    if source == "nvd":
        try:
            days_raw = request.form.get("nvd_days")
            days = int(days_raw) if days_raw else 10
            if days <= 0:
                days = 10
        except Exception:
            days = 10
        keywords_raw = request.form.get("nvd_keywords") or ""
        keywords = [k.strip() for k in keywords_raw.split(",") if k.strip()]
        threat_ingestion.save_nvd_filter_config(days, keywords)

    result = threat_ingestion.ingest_source(source)
    inserted = updated = skipped = 0
    if isinstance(result, tuple):
        if len(result) == 3:
            inserted, updated, skipped = result
        elif len(result) == 2:
            inserted, updated = result
        elif len(result) == 1:
            inserted = result[0]
    else:
        inserted = result
    if inserted or updated:
        extra = f" / Skipped (no base CVE): {skipped}" if skipped else ""
        flash(f"Ingested {inserted} new / Updated {updated}{extra} from {source.upper()}.")
    else:
        status_entry = threat_ingestion.get_last_status().get(source, {}) or {}
        err_msg = status_entry.get("error")
        if err_msg:
            flash(f"No records ingested/updated from {source.upper()}: {err_msg}")
        else:
            flash(f"No records ingested/updated from {source.upper()}.")
    return redirect(url_for("threats.admin_threats", source=source))


@threats_bp.route("/enrich_cve", methods=["POST"], endpoint="admin_threats_enrich_cve")
@admin_required
def admin_threats_enrich_cve():
    """
    Run CVE enrichment: MSRC and CISA-KEV applied to NVD rows.
    """
    threat_ingestion.enrich_all_cve_sources()
    flash("CVE enrichment (MSRC + CISA-KEV) has been run.")
    return redirect(url_for("threats.admin_threats"))


@threats_bp.route("/<int:threat_id>/apply_feeds", methods=["POST"], endpoint="admin_threat_apply_feeds")
@admin_required
def admin_threat_apply_feeds(threat_id):
    """Apply stored feed entries to a specific CVE/master record."""
    master = db.admin_get_threat(threat_id)
    if not master or not master.get("cve_id"):
        flash("Threat not found or missing CVE.")
        return redirect(url_for("threats.admin_threats"))
    applied = threat_ingestion.apply_feed_entries_for_cve(master["cve_id"])
    flash(f"Applied {applied} feed entr{'y' if applied==1 else 'ies'} to CVE {master['cve_id']}.")
    return redirect(url_for("threats.admin_threat_detail", threat_id=threat_id))


@threats_bp.route("/nvd_filters", methods=["POST"], endpoint="admin_threats_nvd_filters")
@admin_required
def admin_threats_nvd_filters():
    """Update NVD filter settings (days and keywords)."""
    try:
        days = int(request.form.get("nvd_days") or 10)
        if days <= 0:
            days = 10
    except Exception:
        days = 10
    keywords_raw = request.form.get("nvd_keywords") or ""
    keywords = [k.strip() for k in keywords_raw.split(",") if k.strip()]

    threat_ingestion.save_nvd_filter_config(days, keywords)
    flash(f"NVD filters updated: {days} day window; keywords: {', '.join(keywords) if keywords else 'none'}")
    return redirect(url_for("threats.admin_threats", source="nvd"))


@threats_bp.route("/check/", methods=["POST"], endpoint="admin_threats_check")
@admin_required
def admin_threats_check():
    """Check connectivity for a given feed without ingesting."""
    source = (request.form.get("source") or "").lower()
    ok = threat_ingestion.check_source_connectivity(source)
    err = threat_ingestion.get_last_status().get(source, {}).get("error")
    if ok and not err:
        flash(f"Connectivity OK for {source.upper()}.")
    else:
        flash(f"Connectivity issue for {source.upper()}: {err or 'Unknown error'}")
    return redirect(url_for("threats.admin_threats", source=source))


@threats_bp.route("/stop/", methods=["POST"], endpoint="admin_threats_stop")
@admin_required
def admin_threats_stop():
    """Request an in-progress feed ingest to stop."""
    source = (request.form.get("source") or "").lower()
    if not source:
        flash("No source selected to stop.")
        return redirect(url_for("threats.admin_threats"))
    threat_ingestion.abort_ingest(source)
    flash(f"Stop requested for {source.upper()}.")
    return redirect(url_for("threats.admin_threats", source=source))


@threats_bp.route("/status", methods=["GET"], endpoint="admin_threats_status")
@admin_required
def admin_threats_status():
    """Return last ingest status (including progress) for polling."""
    return jsonify(threat_ingestion.get_last_status())


@threats_bp.route("/rollback/", methods=["POST"], endpoint="admin_threats_rollback")
@admin_required
def admin_threats_rollback():
    """Rollback last ingest for a source (deletes inserted rows only)."""
    source = (request.form.get("source") or "").upper()
    if not source:
        flash("No source provided for rollback.")
        return redirect(url_for("threats.admin_threats"))
    deleted, run = db.rollback_last_ingest(source)
    if run:
        flash(f"Rolled back ingest {run.get('id')} for {source}, deleted {deleted} inserted rows.")
    else:
        flash(f"No ingest runs found for {source}.")
    return redirect(url_for("threats.admin_threats", source=source.lower()))


@threats_bp.route("/delete/", methods=["POST"], endpoint="admin_threats_delete")
@admin_required
def admin_threats_delete():
    """Delete all threats for a given source (testing only)."""
    source = (request.form.get("source") or "").upper()
    # Normalize UI key to canonical source stored in DB
    alias_map = {
        "CISA": "CISA-KEV",
        "CISA-KEV": "CISA-KEV",
        "MSRC": "MSRC",
        "NVD": "NVD",
        "ACSC": "ACSC",
        "APPLE": "APPLE",
    }
    canonical = alias_map.get(source, source)
    if not source:
        flash("No source provided.")
        return redirect(url_for("threats.admin_threats"))
    deleted = db.admin_delete_threats_by_source(canonical)
    feed_deleted = db.admin_delete_feed_entries_by_source(canonical)
    kev_deleted = 0
    # Also remove source from contrib_sources on merged records
    def _clean_source(src):
        cleaned_local = 0
        conn_local = db.get_connection()
        cur_local = conn_local.cursor()
        cur_local.execute(
            "SELECT id, contrib_sources, kev_flag FROM threat_objects WHERE contrib_sources LIKE ?",
            (f"%{src}%",),
        )
        rows_local = cur_local.fetchall()
        for row in rows_local:
            cs = row["contrib_sources"] or ""
            parts = [p.strip() for p in cs.split(",") if p.strip()]
            parts = [p for p in parts if p.upper() != src]
            new_cs = ", ".join(parts)
            kev_flag = row["kev_flag"]
            if src == "CISA-KEV":
                kev_flag = 0
            cur_local.execute(
                "UPDATE threat_objects SET contrib_sources=?, kev_flag=? WHERE id=?",
                (new_cs if new_cs else None, kev_flag, row["id"]),
            )
            cleaned_local += 1
        conn_local.commit()
        conn_local.close()
        return cleaned_local

    cleaned = _clean_source(canonical)
    if canonical == "NVD":
        # Also purge CISA-KEV rows and remove their contributions when NVD is wiped
        deleted += db.admin_delete_threats_by_source("CISA-KEV")
        feed_deleted += db.admin_delete_feed_entries_by_source("CISA-KEV")
        kev_deleted += db.admin_delete_kev_enrichment()
        cleaned += _clean_source("CISA-KEV")
    if canonical == "CISA-KEV":
        kev_deleted += db.admin_delete_kev_enrichment()
    flash(f"Deleted {deleted} threat(s) from {canonical}. Cleaned {cleaned} merged record(s).")
    if feed_deleted:
        flash(f"Deleted {feed_deleted} stored feed entry(ies) for {canonical}.")
    if kev_deleted:
        flash(f"Deleted {kev_deleted} KEV enrichment record(s).")
    return redirect(url_for("threats.admin_threats", source=source.lower()))


@threats_bp.route("/<int:threat_id>", methods=["GET"], endpoint="admin_threat_detail")
@admin_required
def admin_threat_detail(threat_id):
    """Show a single threat object."""
    threat = db.admin_get_threat(threat_id)
    if not threat:
        return NOT_FOUND, 404
    history = []
    feed_entries = []
    kev_enrichment = None
    msrc_enrichment = None
    if threat.get("cve_id"):
        try:
            history = db.get_cve_history(threat["cve_id"])
        except Exception:
            history = []
        try:
            feed_entries = db.get_feed_entries_by_cve(threat["cve_id"])
        except Exception:
            feed_entries = []
        try:
            kev_enrichment = db.get_kev_enrichment(threat["cve_id"])
        except Exception:
            kev_enrichment = None
        try:
            msrc_enrichment = db.get_msrc_enrichment(threat["cve_id"])
        except Exception:
            msrc_enrichment = None
    def _fmt_dt_time(val):
        if not val:
            return "—"
        try:
            dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            return dt.strftime("%d/%m/%Y %I:%M %p")
        except Exception:
            return val
    badge_threshold_days = 7
    try:
        created_dt = datetime.fromisoformat(threat.get("created_at")) if threat.get("created_at") else None
    except Exception:
        created_dt = None
    try:
        updated_dt = datetime.fromisoformat(threat.get("updated_at")) if threat.get("updated_at") else None
    except Exception:
        updated_dt = None
    threat["badge_enriched"] = bool(threat.get("is_enriched"))
    if created_dt:
        threat["badge_new"] = (datetime.utcnow() - created_dt).days <= badge_threshold_days and not threat["badge_enriched"]
    else:
        threat["badge_new"] = False
    threat["badge_updated"] = False
    if created_dt and updated_dt and updated_dt > created_dt:
        threat["badge_updated"] = True
    threat["published_at_display"] = _fmt_dt_time(threat.get("published_at"))
    if kev_enrichment:
        kev_enrichment["date_added_display"] = _fmt_dt_time(kev_enrichment.get("kev_date_added"))
        kev_enrichment["due_date_display"] = _fmt_dt_time(kev_enrichment.get("kev_due_date"))
        kev_enrichment["kev_action_required_text"] = kev_enrichment.get("kev_required_action") or "—"
    if msrc_enrichment:
        msrc_enrichment["initial_display"] = _fmt_dt_time(msrc_enrichment.get("msrc_initial_release_utc"))
        msrc_enrichment["current_display"] = _fmt_dt_time(msrc_enrichment.get("msrc_current_release_utc"))
        msrc_enrichment["last_seen_display"] = _fmt_dt_time(msrc_enrichment.get("last_seen_utc"))
        # decode lists
        import json as _json
        try:
            products_json = msrc_enrichment.get("msrc_affected_products")
            msrc_enrichment["products_list"] = _json.loads(products_json) if products_json else []
        except Exception:
            msrc_enrichment["products_list"] = []
        try:
            rem_urls_json = msrc_enrichment.get("msrc_remediation_urls")
            msrc_enrichment["remediation_urls_list"] = _json.loads(rem_urls_json) if rem_urls_json else []
        except Exception:
            msrc_enrichment["remediation_urls_list"] = []
        # parse exploitability string into parts
        try:
            expl_raw = msrc_enrichment.get("msrc_exploitability_assessment") or ""
            parts = {}
            for seg in expl_raw.split(";"):
                if ":" in seg:
                    k, v = seg.split(":", 1)
                    parts[k.strip()] = v.strip()
            msrc_enrichment["exploitability_parts"] = parts
            msrc_enrichment["msrc_latest_release"] = parts.get("Latest Software Release") or parts.get("Latest Software")
        except Exception:
            msrc_enrichment["exploitability_parts"] = {}
    if history:
        for h in history:
            try:
                h["created_at_display"] = _fmt_dt_time(h.get("created_at"))
            except Exception:
                h["created_at_display"] = h.get("created_at")
    back_params = {
        "source": request.args.get("source") or "",
        "q": request.args.get("q") or "",
        "severity": request.args.get("severity") or "",
        "page": request.args.get("page") or "",
    }
    return render_template(
        "admin_threat_detail.html",
        threat=threat,
        history=history,
        feed_entries=feed_entries,
        kev_enrichment=kev_enrichment,
        msrc_enrichment=msrc_enrichment,
        back_params=back_params,
        page_name="templates/admin_threat_detail.html",
    )


# Placeholder loader for threat by CVE
def load_threat_by_cve(cve_id: str):
    """
    Placeholder function that loads a threat object by CVE ID.
    Replace the body with the real query you already use in admin_threat_detail.
    """
    # Try by numeric id first
    if cve_id and cve_id.isdigit():
        found = db.admin_get_threat(int(cve_id))
        if found:
            return found
    # If a dedicated lookup exists, use it; otherwise fall back to a simple query
    if hasattr(db, "admin_get_threat_by_cve"):
        return db.admin_get_threat_by_cve(cve_id)
    # Minimal fallback: query by cve_id directly
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threat_objects WHERE cve_id=?", (cve_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


@threats_bp.route("/<cve_id>/msrc_details", methods=["GET"], endpoint="admin_threat_msrc_details")
@admin_required
def admin_threat_msrc_details(cve_id):
    """Return raw MSRC CVRF details for a given CVE."""
    try:
        threat = load_threat_by_cve(cve_id)
    except NotImplementedError:
        return jsonify({"ok": False, "error": "Threat lookup not implemented"}), 500
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Threat lookup failed: {exc}"}), 500

    if not threat:
        return jsonify({"ok": False, "error": "Threat not found"}), 404

    # Adapt field access if threat is a dict
    def _get(obj, key):
        return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)

    src = _get(threat, "source") or ""
    is_msrc = src and ("msrc" in src.lower() or src == "Microsoft")
    cvrf_url = _get(threat, "msrc_cvrf_url") or _get(threat, "link")
    if not is_msrc or not cvrf_url:
        return jsonify({"ok": False, "error": "Threat is not a Microsoft threat or has no CVRF URL"}), 400

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "Accept": "application/json",
    }
    resp = None
    insecure = False
    try:
        resp = requests.get(cvrf_url, timeout=15, headers=headers)
    except requests.exceptions.SSLError:
        # Fallback to an insecure request for environments with SSL interception
        try:
            resp = requests.get(cvrf_url, timeout=15, headers=headers, verify=False)
            insecure = True
        except requests.exceptions.RequestException as exc:
            return jsonify({"ok": False, "error": f"Failed to fetch Microsoft details (SSL verify off): {exc}"}), 502
    except requests.exceptions.RequestException:
        # Final fallback using urllib with a permissive SSL context (covers non-requests environments)
        try:
            import urllib.request, ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(cvrf_url, headers=headers)
            with urllib.request.urlopen(req, timeout=20, context=ctx) as h:
                body = h.read()
                status = h.status
                content_type = h.headers.get("Content-Type", "")
            # Wrap in a simple object to mimic requests.Response where needed
            class _RespShim:
                def __init__(self, body, status, headers):
                    self._body = body
                    self.status_code = status
                    self.headers = {"Content-Type": headers}
                @property
                def text(self):
                    return self._body.decode("utf-8", errors="ignore")
                def json(self):
                    import json
                    return json.loads(self.text)
            resp = _RespShim(body, status, content_type)
            insecure = True
        except Exception as exc:
            return jsonify({"ok": False, "error": f"Failed to fetch Microsoft details: {exc}"}), 502

    if resp.status_code != 200:
        return jsonify({"ok": False, "error": f"Microsoft API returned status {resp.status_code}"}), resp.status_code

    content_type = resp.headers.get("Content-Type", "").lower()
    content = None
    summary_vulns = []
    try:
        if "json" in content_type:
            try:
                data = resp.json()
                content = data
                # Also pass through raw HTML/text if the service returns embedded HTML in known fields
                if isinstance(data, dict) and "Document" in data and isinstance(data["Document"], str):
                    content = data
            except Exception:
                content = resp.text
        else:
            raw_text = resp.text
            # Try to parse XML CVRF into a simple JSON structure with vulnerabilities
            try:
                root = ET.fromstring(raw_text)
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
                    vuln_entry = {
                        "CVE": vid,
                        "Title": title,
                        "Description": desc,
                        "Severity": sev,
                    }
                    vulns.append(vuln_entry)
                content = {"Vulnerability": vulns, "Document": raw_text}
            except Exception:
                content = raw_text
            # Build a simplified vulnerability summary for the UI
            product_name_map = {}
            if isinstance(content, dict):
                # Build a map of ProductID -> Name from the ProductTree, if present
                def _walk_products(node):
                    if not node:
                        return
                    if isinstance(node, dict):
                        pid = node.get("ProductID")
                        val = node.get("Value")
                        if pid and val:
                            product_name_map[pid] = val
                        # Some payloads use FullProductName arrays
                        for key in ("Branch", "FullProductName", "Product"):
                            child = node.get(key)
                            if isinstance(child, list):
                                for c in child:
                                    _walk_products(c)
                            elif isinstance(child, dict):
                                _walk_products(child)
                    elif isinstance(node, list):
                        for item in node:
                            _walk_products(item)
                _walk_products(content.get("ProductTree"))

                vulns = content.get("Vulnerability") or []
                if isinstance(vulns, list):
                    def _pick_note_desc(v):
                        """Return the first useful note text, preferring description notes but falling back to any value."""
                        notes = v.get("Notes") or []
                        if not isinstance(notes, list):
                            return ""
                        first_with_value = ""
                        for n in notes:
                            if not n:
                                continue
                            val = n.get("Text") or n.get("Value") or n.get("Description") or ""
                            if val and not first_with_value:
                                first_with_value = val
                            n_type = n.get("Type")
                            n_title = str(n.get("Title") or "").lower()
                            if n_type == 2 or n_title == "description":
                                if val:
                                    return val
                        return first_with_value

                    def _pick_threat_desc(v):
                        threats = v.get("Threats") or []
                        if not isinstance(threats, list):
                            return ""
                        for t in threats:
                            if not t:
                                continue
                            desc = t.get("Description") or {}
                            if isinstance(desc, dict):
                                return desc.get("Value") or desc.get("Text") or ""
                        return ""

                    def _pick_severity_and_score(v):
                        severity = v.get("Severity") or v.get("BaseSeverity") or ""
                        score = ""
                        vector = ""
                        cvss_list = v.get("CVSSScoreSets") or []
                        if isinstance(cvss_list, list) and cvss_list:
                            s = cvss_list[0] or {}
                            score = s.get("BaseScore") or s.get("Score") or ""
                            vector = s.get("Vector") or s.get("VectorString") or ""
                            if not severity:
                                severity = s.get("BaseSeverity") or s.get("BaseSev") or ""
                        threats = v.get("Threats") or []
                        if not severity and isinstance(threats, list) and threats:
                            t0 = threats[0] or {}
                            severity = t0.get("Severity") or severity or ""
                        return severity, score, vector

                    def _pick_products(v):
                        product_ids = []
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
                        return ", ".join(sorted(set(product_ids)))

                    def _pick_remediations(v):
                        remeds = v.get("Remediations") or []
                        if not isinstance(remeds, list):
                            return ""
                        out = []
                        for r in remeds:
                            if not r:
                                continue
                            url = r.get("URL") or ""
                            desc = r.get("Description") or ""
                            if isinstance(desc, dict):
                                desc = desc.get("Value") or desc.get("Text") or ""
                            typ = r.get("Type")
                            label = r.get("Name") or r.get("Title") or ""
                            parts = [p for p in [label, desc, url] if p]
                            if parts:
                                out.append(" | ".join(parts))
                            elif typ:
                                out.append(str(typ))
                        return "; ".join(out)

                    def _pick_remediation_urls(v):
                        remeds = v.get("Remediations") or []
                        if not isinstance(remeds, list):
                            return ""
                        urls = []
                        for r in remeds:
                            if not r:
                                continue
                            url = r.get("URL")
                            if url:
                                urls.append(url)
                        return "; ".join(urls)

                    def _pick_remediation_types(v):
                        remeds = v.get("Remediations") or []
                        if not isinstance(remeds, list):
                            return ""
                        types = []
                        for r in remeds:
                            if not r:
                                continue
                            typ = r.get("Type")
                            if typ is not None:
                                types.append(str(typ))
                        return "; ".join(types)

                    def _pick_acknowledgments(v):
                        acks = v.get("Acknowledgments") or []
                        if not isinstance(acks, list):
                            return ""
                        out = []
                        for a in acks:
                            if not a:
                                continue
                            names = a.get("Names") or []
                            orgs = a.get("Organization") or []
                            text = []
                            if isinstance(names, list):
                                text.extend([n for n in names if n])
                            if isinstance(orgs, list):
                                text.extend([o for o in orgs if o])
                            if text:
                                out.append(", ".join(text))
                        return "; ".join(out)

                    def _pick_revision_history(v):
                        revs = v.get("RevisionHistory") or []
                        if not isinstance(revs, list):
                            return ""
                        parts = []
                        for r in revs:
                            if not r:
                                continue
                            num = r.get("Number") or ""
                            date = r.get("Date") or ""
                            desc = r.get("Description") or ""
                            if isinstance(desc, dict):
                                desc = desc.get("Value") or desc.get("Text") or ""
                            piece = " | ".join([p for p in [num, date, desc] if p])
                            if piece:
                                parts.append(piece)
                        return "; ".join(parts)

                    for v in vulns:
                        if not v:
                            continue
                        cve = v.get("CVE") or v.get("ID")
                        sev, score, vector = _pick_severity_and_score(v)
                        threat_text = _pick_threat_desc(v)
                        desc = _pick_note_desc(v) or threat_text or v.get("Title") or v.get("ID") or ""
                        if (desc or "").strip().lower() == "description":
                            desc = ""
                        if not desc and vector:
                            desc = vector
                        products = _pick_products(v)
                        product_names = ", ".join([product_name_map.get(pid, pid) for pid in products.split(", ") if pid]) if products else ""
                        remediations = _pick_remediations(v)
                        remediation_urls = _pick_remediation_urls(v)
                        remediation_types = _pick_remediation_types(v)
                        acknowledgments = _pick_acknowledgments(v)
                        revision_history = _pick_revision_history(v)
                        summary_vulns.append({
                            "cve": cve,
                            "severity": sev,
                            "score": score,
                            "vector": vector,
                            "threat": threat_text,
                            "description": desc,
                            "discovery_date": v.get("DiscoveryDate") or "",
                            "release_date": v.get("ReleaseDate") or "",
                            "cwe": v.get("CWE") or "",
                            "products": products,
                            "product_names": product_names,
                            "remediations": remediations,
                            "remediation_urls": remediation_urls,
                            "remediation_types": remediation_types,
                            "acknowledgments": acknowledgments,
                            "revision_history": revision_history,
                        })
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Failed to parse Microsoft response: {exc}"}), 500

    return jsonify({"ok": True, "content": content, "summary_vulns": summary_vulns, "raw_text": resp.text, "insecure": insecure})
