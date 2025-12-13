"""Flask entrypoint for the compliance tracker.

This file wires together:
- Auth/session helpers (current_user, decorators).
- Admin dashboards for tasks/companies/users.
- Company-admin and user dashboards.
- CRUD routes for tasks, users, companies, app settings.
- Utility endpoints (task answers, reports, config toggles).

The actual data access lives in db.py; this file focuses on request handling
and shaping data for templates.
"""

import os

from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta, timezone
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
# Attempt to import the package-level DB module; if import fails (e.g. when running
# the app directly), add the project root to sys.path and retry the import.
try:
    import compliance_app.compliance_app_tailwind.db as db
    import compliance_app.compliance_app_tailwind.risk_utils as risk_utils
    from compliance_app.compliance_app_tailwind.admin_routes import admin_bp
    import compliance_app.compliance_app_tailwind.core_utils as core_utils
    from compliance_app.compliance_app_tailwind.auth_helpers import (
        current_user,
        login_required,
        company_admin_required,
        admin_required,
    )
except ImportError:
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))
    import compliance_app.compliance_app_tailwind.db as db
    import compliance_app.compliance_app_tailwind.risk_utils as risk_utils
    from compliance_app.compliance_app_tailwind.admin_routes import admin_bp
    import compliance_app.compliance_app_tailwind.core_utils as core_utils
    from compliance_app.compliance_app_tailwind.auth_helpers import (
        current_user,
        login_required,
        company_admin_required,
        admin_required,
    )

app = Flask(__name__)
app.secret_key = "change_this_secret_key"
ADMIN_USERS_TEMPLATE = "admin_users.html"
ADMIN_PROFILE_TEMPLATE = "admin_profile.html"
# Full template path constant to avoid duplicating the literal
ADMIN_PROFILE_PAGE_NAME = "templates/admin_profile.html"
COMPANY_ADMIN_USERS_TEMPLATE = "templates/company_admin_users.html"
INVALID_OPTION_TYPE = "Invalid option type"

# Common display formats
DATE_FMT = "%d/%m/%Y"
DATETIME_FMT = f"{DATE_FMT} %H:%M"
USER_NOT_FOUND = "User not found"
NOT_FOUND = "Not found"
ACCESS_DENIED = "Access denied"

# Optional modules (extensions)
ENABLE_THREAT_MODULE = os.getenv("APP_ENABLE_THREAT_MODULE", "1") == "1"
ENABLE_RISK_MODULE = os.getenv("APP_ENABLE_RISK_MODULE", "0") == "1"

# Register blueprints
try:
    from compliance_app.compliance_app_tailwind.core_routes import core_bp
    from compliance_app.compliance_app_tailwind.threat.threat_routes import threats_bp
except ImportError:
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))
    from compliance_app.compliance_app_tailwind.core_routes import core_bp
    from compliance_app.compliance_app_tailwind.threat.threat_routes import threats_bp
app.register_blueprint(core_bp)
app.register_blueprint(admin_bp)
if ENABLE_THREAT_MODULE:
    app.register_blueprint(threats_bp)

try:
    from compliance_app.compliance_app_tailwind.risk_routes import risk_bp
except ImportError:
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))
    from compliance_app.compliance_app_tailwind.risk_routes import risk_bp
if ENABLE_RISK_MODULE:
    app.register_blueprint(risk_bp)

# Initialize database tables on startup (Flask 3 removed before_first_request)
db.create_tables_if_needed()

# Inject settings into all templates
@app.context_processor
def inject_app_settings():
    """Make app settings available to every template render and build a small banner payload."""
    settings = db.admin_get_app_settings()
    if settings is None:
        settings = {}
    if isinstance(settings, dict) and not settings.get("app_name"):
        settings["app_name"] = "Compliance Tracker"
    # Build a lightweight banner object for templates if a user is logged in
    banner = None
    if "user_id" in session:
        user_row = db.admin_get_user(session["user_id"])
        if user_row:
            display_name = f"{user_row['first_name'] or ''} {user_row['last_name'] or ''}".strip() or user_row["username"]
            banner = {
                "display_name": display_name,
                "role": user_row["role"],
                "role_label": None,  # filled below via role_label
            }
    def role_label(role):
        mapping = {
            "admin": "Admin",
            "company_admin": "Company Admin",
            "user": "User",
        }
        return mapping.get(role, role)
    if banner:
        banner["role_label"] = role_label(banner["role"])
    return {
        "app_settings": settings,
        "role_label": role_label,
        "current_user_banner": banner,
        "extensions": {
            "threats": ENABLE_THREAT_MODULE,
            "risk": ENABLE_RISK_MODULE,
        },
    }

def _is_hashed(pw):
    """Check whether a stored password value is hashed."""
    return isinstance(pw, str) and (pw.startswith("pbkdf2:") or pw.startswith("scrypt:"))


def _company_rollup_for_admin(company_id, company_name, unassigned_seen, unassigned_details):
    """Summarize task completion for a single company and capture unassigned tasks."""
    company_tasks = db.admin_get_all_tasks(company_id)
    roll = db.admin_task_completion_rollup(company_id)
    rows = []

    def _record_unassigned_once(t, assign_total, assign_completed, overdue_flag):
        key = (t["id"], company_id)
        if assign_total != 0 or key in unassigned_seen:
            return
        unassigned_seen.add(key)
        company_label = t["company_name"] if "company_name" in t.keys() and t["company_name"] else company_name
        unassigned_details.append({
            "id": t["id"],
            "title": t["title"] if "title" in t.keys() else None,
            "assign_total": assign_total,
            "assign_completed": assign_completed,
            "completion_pct": 0,
            "fully_completed": False,
            "overdue": overdue_flag,
            "company_label": company_label,
        })

    for t in company_tasks:
        comp = roll.get(t["id"], {"completed": 0, "total": 0})
        assign_total = comp.get("total", 0)
        assign_completed = comp.get("completed", 0)
        fully_completed = assign_total > 0 and assign_completed == assign_total
        overdue_raw = t["overdue"] if "overdue" in t.keys() else False
        overdue_flag = bool(overdue_raw and not fully_completed)

        rows.append({
            "assign_total": assign_total,
            "assign_completed": assign_completed,
            "fully_completed": fully_completed,
            "overdue": overdue_flag,
        })

        # If the task has no assignments and we haven't seen it yet, record it once.
        _record_unassigned_once(t, assign_total, assign_completed, overdue_flag)

    counted = [r for r in rows if r["assign_total"] > 0]
    tasks_total = len(counted)
    tasks_completed = sum(1 for r in counted if r["fully_completed"])
    tasks_overdue = sum(1 for r in counted if r["overdue"])
    tasks_pending = max(tasks_total - tasks_completed, 0)
    unassigned = sum(1 for r in rows if r["assign_total"] == 0)
    return {
        "name": company_name,
        "company_id": company_id,
        "unassigned": unassigned,
        "assignments_total": sum(r["assign_total"] for r in rows),
        "tasks_total": tasks_total,
        "tasks_completed": tasks_completed,
        "tasks_pending": tasks_pending,
        "tasks_overdue": tasks_overdue,
        "tasks_compliance": round((tasks_completed / tasks_total) * 100, 1) if tasks_total else 0,
    }

def _compute_totals(rows):
    if not rows:
        return None
    total_tasks_all = sum(r["tasks_total"] for r in rows)
    total_completed_all = sum(r["tasks_completed"] for r in rows)
    total_pending_all = sum(r["tasks_pending"] for r in rows)
    total_overdue_all = sum(r["tasks_overdue"] for r in rows)
    total_unassigned_all = sum(r["unassigned"] for r in rows)
    total_users_all = sum(r.get("user_count", 0) for r in rows)
    return {
        "assignments_total": sum(r.get("assignments_total", 0) for r in rows),
        "tasks_total": total_tasks_all,
        "tasks_completed": total_completed_all,
        "tasks_pending": total_pending_all,
        "tasks_overdue": total_overdue_all,
        "unassigned": total_unassigned_all,
        "tasks_compliance": round((total_completed_all / total_tasks_all) * 100, 1) if total_tasks_all else 0,
        "user_count": total_users_all,
    }

def _admin_get_metric_mode(req):
    """Return 'task' or 'user' based on query param metric_mode (defaults to task)."""
    mode = req.args.get("metric_mode")
    return mode if mode in ("task", "user") else "task"

def _admin_get_selected_company_id(req):
    """Parse company_id from query params; None for all/blank/invalid, else int."""
    arg = req.args.get("company_id")
    if arg is None:
        return None
    arg = arg.strip()
    if arg == "" or arg == "all":
        return None
    try:
        return int(arg)
    except ValueError:
        return None


def _admin_build_palettes_from_settings(settings_row, severity_counts, impact_counts):
    settings = dict(settings_row) if settings_row else {}
    sev_map = core_utils.parse_color_map(settings.get("severity_palette"))
    imp_map = core_utils.parse_color_map(settings.get("impact_palette"))
    comp_map = core_utils.parse_color_map(settings.get("completion_palette"))
    default_palette = ['#2563eb', '#16a34a', '#f59e0b', '#ef4444', '#8b5cf6', '#0ea5e9']
    severity_palette = core_utils.palette_for_labels([c["label"] for c in severity_counts], default_palette, sev_map)
    impact_palette = core_utils.palette_for_labels([c["label"] for c in impact_counts], default_palette, imp_map)
    completion_labels = ["Completed", "Pending", "Overdue"]
    completion_defaults = ['#16a34a', '#f59e0b', '#ef4444']
    completion_palette = core_utils.palette_for_labels(completion_labels, completion_defaults, comp_map)
    return severity_palette, impact_palette, completion_palette

def _admin_build_tasks_json(tasks, rollup, selected_company_id):
    tasks_out = []
    unassigned = []
    for t in tasks:
        comp = rollup.get(t["id"], {"completed": 0, "total": 0})
        base = core_utils.normalize_task_for_dashboard(t, comp, date.today())
        tasks_out.append(base)
        if selected_company_id is not None and base["assign_total"] == 0:
            company_label = t["company_name"] if "company_name" in t.keys() else "Global"
            unassigned.append({**base, "company_label": company_label})
    return tasks_out, unassigned

def _admin_build_company_rows(companies_list, unassigned_seen, unassigned_details):
    """Build per-company summaries and user rows for the admin/company tables."""
    summaries = []
    user_rows = {}
    for c in companies_list:
        company_users = [dict(u) for u in db.admin_user_compliance(c["id"])]
        filtered = [u for u in company_users if str(u.get("role", "")).lower() not in ("admin", "global admin")]
        filtered.sort(key=lambda u: ((u.get("first_name") or "") + (u.get("last_name") or "") + (u.get("username") or "")).lower())
        user_rows[c["id"]] = filtered
        user_rows[str(c["id"])] = filtered
        rollup_row = _company_rollup_for_admin(c["id"], c["name"], unassigned_seen, unassigned_details)
        rollup_row["user_count"] = len(filtered)
        summaries.append(rollup_row)
    return summaries, user_rows

def _admin_view_prepare(selected_company_id):
    """Prepare and return all derived data needed by the admin task dashboard.

    Steps (in order):
    1) Ensure assignments exist for the selected company (or all) so counts are consistent.
    2) Build task/user compliance metrics and palettes for charts.
    3) Compute aggregates (tasks, assignments, rollups) and company drill-down rows.
    4) Package everything the template expects (including unassigned details and risk matrix).
    """
    db.admin_ensure_assignments_for_company(selected_company_id)

    summary = db.admin_get_summary_counts(selected_company_id)
    severity_counts = db.admin_task_counts_by("severity", selected_company_id)
    impact_counts = db.admin_task_counts_by("impact", selected_company_id)

    # Compliance rows and basic user metrics
    compliance = [dict(r) for r in db.admin_user_compliance(selected_company_id)]
    compliance.sort(key=lambda u: ((u.get("first_name") or "") + (u.get("last_name") or "") + (u.get("username") or "")).lower())

    pending_non_overdue = max(summary.get("total_pending", 0) - summary.get("total_overdue", 0), 0)
    user_metrics = {
        "total_users": len(compliance),
        "completed_users": sum(1 for r in compliance if (r.get("pending_tasks") or 0) == 0),
        "pending_users": sum(1 for r in compliance if (r.get("pending_tasks") or 0) > 0),
        "overdue_users": sum(1 for r in compliance if (r.get("overdue_tasks") or 0) > 0),
        "compliance_pct": round((sum(1 for r in compliance if (r.get("pending_tasks") or 0) == 0) / len(compliance)) * 100, 1) if len(compliance) else 0.0,
    }

    # Palettes
    settings_row = db.admin_get_app_settings()
    severity_palette, impact_palette, completion_palette = _admin_build_palettes_from_settings(settings_row, severity_counts, impact_counts)

    # Tasks + rollup
    tasks = db.admin_get_all_tasks(selected_company_id)
    rollup = db.admin_task_completion_rollup(selected_company_id)
    tasks_json, unassigned_details = _admin_build_tasks_json(tasks, rollup, selected_company_id)

    # Compute task and assignment aggregates using the shared company helper to reduce nesting
    agg = _company_compute_task_aggregates(tasks_json)

    task_counts = {
        "total": agg["task_total"],
        "completed": agg["task_completed"],
        "pending": agg["task_pending"],
        "overdue": agg["task_overdue"],
    }

    # Company rollups and mappings via helper to keep flow linear
    companies_all = db.admin_get_companies(show_inactive=True)
    unassigned_seen = set()
    company_summaries, company_user_rows = _admin_build_company_rows(companies_all, unassigned_seen, unassigned_details)

    company_summaries = company_summaries or []
    company_user_rows = company_user_rows or {}
    company_summaries.sort(key=lambda r: (r.get("name") or "").lower())

    company_table_rows = company_summaries
    company_totals = _compute_totals(company_table_rows)
    unassigned_tasks = company_totals["unassigned"] if company_totals else 0

    # Map tasks to their company for drill-down panels (include global tasks for all companies)
    company_task_rows = {}
    for c in company_summaries:
        cid = c["company_id"]
        company_task_rows[cid] = [t for t in tasks_json if (t.get("company_id") == cid or t.get("company_id") is None)]

    risk_matrix = risk_utils.build_risk_matrix(tasks_json) if ENABLE_RISK_MODULE else {}

    return {
        "summary": summary,
        "severity_counts": severity_counts,
        "impact_counts": impact_counts,
        "compliance": compliance,
        "pending_non_overdue": pending_non_overdue,
        "severity_palette": severity_palette,
        "impact_palette": impact_palette,
        "completion_palette": completion_palette,
        "tasks_json": tasks_json,
        "task_compliance_percent": agg["task_compliance_percent"],
        "assignment_counts": agg["assignment_counts"],
        "user_metrics": user_metrics,
        "user_counts": {
            "total": user_metrics["total_users"],
            "completed": user_metrics["completed_users"],
            "pending": user_metrics["pending_users"],
            "overdue": user_metrics["overdue_users"],
            "compliance": user_metrics["compliance_pct"],
        },
        "companies_all": companies_all,
        "company_summaries": company_summaries,
        "company_user_rows": company_user_rows,
        "company_table_rows": company_table_rows,
        "company_totals": company_totals,
        "unassigned_details": unassigned_details,
        "unassigned_tasks": unassigned_tasks,
        "company_task_rows": company_task_rows,
        "risk_matrix": risk_matrix,
        "task_counts": task_counts,
    }


def _admin_view(user):
    """Render the admin task dashboard (tasks/users/companies/risk) using prepared data."""
    # Thin orchestrator that delegates heavy lifting to helpers to reduce complexity.
    metric_mode = _admin_get_metric_mode(request)
    selected_company_id = _admin_get_selected_company_id(request)
    session.pop("selected_company_id", None)

    data = _admin_view_prepare(selected_company_id)

    # If a specific company is selected, re-order and filter company data so the table matches the dropdown
    filtered_company_rows = data["company_table_rows"]
    filtered_company_user_rows = data["company_user_rows"]
    filtered_company_task_rows = data.get("company_task_rows", {})
    filtered_company_totals = data["company_totals"]
    filtered_unassigned_tasks = data["unassigned_tasks"]

    if selected_company_id is not None:
        data["company_summaries"].sort(
            key=lambda r: (0 if r.get("company_id") == selected_company_id else 1, (r.get("name") or "").lower())
        )
        filtered_company_rows = [r for r in data["company_table_rows"] if r.get("company_id") == selected_company_id]
        filtered_company_user_rows = {
            k: v for k, v in data["company_user_rows"].items() if str(k) == str(selected_company_id)
        }
        filtered_company_task_rows = {
            k: v for k, v in data.get("company_task_rows", {}).items() if str(k) == str(selected_company_id)
        }
        filtered_company_totals = _compute_totals(filtered_company_rows)
        filtered_unassigned_tasks = filtered_company_totals["unassigned"] if filtered_company_totals else 0

    # Expose a compact set of variables to the template exactly as before
    return render_template(
        "admin_task_dashboard.html",
        summary=data["summary"],
        severity_counts=data["severity_counts"],
        impact_counts=data["impact_counts"],
        compliance_percent=data["task_compliance_percent"],
        compliance=data["compliance"],
        pending_non_overdue=data["pending_non_overdue"],
        severity_palette=data["severity_palette"],
        impact_palette=data["impact_palette"],
        completion_palette=data["completion_palette"],
        companies=data["companies_all"],
        selected_company_id=selected_company_id,
        is_company_admin=False,
        user_metrics=data["user_metrics"],
        user=user,
        tasks=data["tasks_json"],
        task_counts=data["task_counts"],
        assignment_counts=data["assignment_counts"],
        user_counts=data["user_counts"],
        metric_mode=metric_mode,
        unassigned_tasks=filtered_unassigned_tasks,
        company_summaries=data["company_summaries"],
        company_totals=filtered_company_totals,
        company_user_rows=filtered_company_user_rows,
        company_task_rows=filtered_company_task_rows,
        company_table_rows=filtered_company_rows,
        risk_matrix=data["risk_matrix"],
        unassigned_details=data["unassigned_details"],
        page_name="templates/admin_task_dashboard.html",
    )

def _company_user_metrics_from_compliance(rows):
    total = len(rows)
    completed_users = sum(1 for r in rows if (r.get("pending_tasks") or 0) == 0)
    pending_users = sum(1 for r in rows if (r.get("pending_tasks") or 0) > 0)
    overdue_users = sum(1 for r in rows if (r.get("overdue_tasks") or 0) > 0)
    pct = round((completed_users / total) * 100, 1) if total else 0
    return {
        "total_users": total,
        "completed_users": completed_users,
        "pending_users": pending_users,
        "overdue_users": overdue_users,
        "compliance_pct": pct,
    }

def _company_build_palettes_from_settings_row(settings_row, sev_counts, imp_counts):
    settings_local = dict(settings_row) if settings_row else {}
    sev_map = core_utils.parse_color_map(settings_local.get("severity_palette"))
    imp_map = core_utils.parse_color_map(settings_local.get("impact_palette"))
    comp_map = core_utils.parse_color_map(settings_local.get("completion_palette"))
    default_palette = ['#2563eb', '#16a34a', '#f59e0b', '#ef4444', '#8b5cf6', '#0ea5e9']
    severity_palette = core_utils.palette_for_labels([c["label"] for c in sev_counts], default_palette, sev_map)
    impact_palette = core_utils.palette_for_labels([c["label"] for c in imp_counts], default_palette, imp_map)
    completion_labels = ["Completed", "Pending", "Overdue"]
    completion_defaults = ['#16a34a', '#f59e0b', '#ef4444']
    completion_palette = core_utils.palette_for_labels(completion_labels, completion_defaults, comp_map)
    return severity_palette, impact_palette, completion_palette

def _company_tasks_and_unassigned(tasks, rollup):
    tasks_out = []
    unassigned = []
    for t in tasks:
        comp = rollup.get(t["id"], {"completed": 0, "total": 0})
        base = _task_to_base(t, comp)
        tasks_out.append(base)
        if base["assign_total"] == 0:
            company_label = t.get("company_name") if "company_name" in t.keys() else "Global"
            unassigned.append({**base, "company_label": company_label})
    return tasks_out, unassigned

def _company_compute_task_aggregates(tasks_list):
    total = len(tasks_list)
    overdue = sum(1 for t in tasks_list if t.get("overdue"))
    completed = sum(1 for t in tasks_list if t.get("fully_completed"))
    pending = max(total - completed, 0)
    compliance_pct = round((completed / total) * 100, 1) if total else 0
    unassigned = sum(1 for t in tasks_list if t.get("assign_total", 0) == 0)
    assignments_total = sum(t.get("assign_total") or 0 for t in tasks_list)
    assignment_completed = sum(t.get("assign_completed") or 0 for t in tasks_list)
    assignment_overdue = sum((t.get("assign_total") or 0) for t in tasks_list if t.get("overdue"))
    assignment_pending = max(assignments_total - assignment_completed, 0)
    assignment_counts = {
        "total": assignments_total,
        "completed": assignment_completed,
        "pending": assignment_pending,
        "overdue": assignment_overdue,
    }
    return {
        "task_total": total,
        "task_overdue": overdue,
        "task_completed": completed,
        "task_pending": pending,
        "task_compliance_percent": compliance_pct,
        "unassigned_tasks": unassigned,
        "assignment_counts": assignment_counts,
    }

def _company_admin_view(user):
    metric_mode = request.args.get("metric_mode")
    if metric_mode not in ("task", "user"):
        metric_mode = "task"
    selected_company_id = user.get("company_id")

    db.admin_ensure_assignments_for_company(selected_company_id)

    # Core rows used throughout
    summary = db.admin_get_summary_counts(selected_company_id)
    severity_counts = db.admin_task_counts_by("severity", selected_company_id)
    impact_counts = db.admin_task_counts_by("impact", selected_company_id)
    compliance = [dict(r) for r in db.admin_user_compliance(selected_company_id)]

    # Build palettes
    settings_row = db.admin_get_app_settings()
    severity_palette, impact_palette, completion_palette = _company_build_palettes_from_settings_row(settings_row, severity_counts, impact_counts)

    # Build tasks and rollups
    tasks = db.admin_get_all_tasks(selected_company_id)
    rollup = db.admin_task_completion_rollup(selected_company_id)
    tasks_json, unassigned_details = _company_tasks_and_unassigned(tasks, rollup)

    # Compute aggregates
    agg = _company_compute_task_aggregates(tasks_json)
    task_counts = {
        "total": agg["task_total"],
        "completed": agg["task_completed"],
        "pending": agg["task_pending"],
        "overdue": agg["task_overdue"],
    }

    # Company info and summaries
    company_row = db.admin_get_company(selected_company_id) if selected_company_id else None
    if company_row:
        company_name = company_row["name"] if "name" in company_row.keys() else f"Company #{selected_company_id}"
    elif selected_company_id:
        company_name = f"Company #{selected_company_id}"
    else:
        company_name = "Company"

    company_summaries = [{
        "name": company_name,
        "company_id": selected_company_id,
        "unassigned": agg["unassigned_tasks"],
        "assignments_total": agg["assignment_counts"]["total"],
        "tasks_total": agg["task_total"],
        "tasks_completed": agg["task_completed"],
        "tasks_pending": agg["task_pending"],
        "tasks_overdue": agg["task_overdue"],
        "tasks_compliance": agg["task_compliance_percent"],
        "user_count": len(compliance),
    }]
    company_table_rows = company_summaries
    company_totals = {
        "assignments_total": agg["assignment_counts"]["total"],
        "tasks_total": agg["task_total"],
        "tasks_completed": agg["task_completed"],
        "tasks_pending": agg["task_pending"],
        "tasks_overdue": agg["task_overdue"],
        "unassigned": agg["unassigned_tasks"],
        "tasks_compliance": agg["task_compliance_percent"],
        "user_count": len(compliance),
    }
    company_user_rows = {selected_company_id: compliance} if selected_company_id else {}
    company_task_rows = {selected_company_id: tasks_json} if selected_company_id else {}

    # User metrics and counts
    um = _company_user_metrics_from_compliance(compliance)
    user_metrics = {
        "total_users": um["total_users"],
        "completed_users": um["completed_users"],
        "pending_users": um["pending_users"],
        "overdue_users": um["overdue_users"],
        "compliance_pct": um["compliance_pct"],
    }
    user_counts = {
        "total": user_metrics["total_users"],
        "completed": user_metrics["completed_users"],
        "pending": user_metrics["pending_users"],
        "overdue": user_metrics["overdue_users"],
        "compliance": user_metrics["compliance_pct"],
    }
    pending_non_overdue = max(summary.get("total_pending", 0) - summary.get("total_overdue", 0), 0)

    # Risk matrix (same parameters as original)
    risk_matrix = risk_utils.build_risk_matrix(
        tasks_json,
        severity_order=None,
        impact_order={"Low": 0, "Medium": 1, "High": 2},
        severity_sort=False,
    ) if ENABLE_RISK_MODULE else {}

    return render_template(
        "admin_task_dashboard.html",
        summary=summary,
        severity_counts=severity_counts,
        impact_counts=impact_counts,
        compliance_percent=agg["task_compliance_percent"],
        compliance=compliance,
        pending_non_overdue=pending_non_overdue,
        severity_palette=severity_palette,
        impact_palette=impact_palette,
        completion_palette=completion_palette,
        companies=[db.admin_get_company(selected_company_id)] if selected_company_id else db.admin_get_companies(),
        selected_company_id=selected_company_id,
        is_company_admin=True,
        user_metrics=user_metrics,
        user=user,
        tasks=tasks_json,
        task_counts=task_counts,
        assignment_counts=agg["assignment_counts"],
        user_counts=user_counts,
        metric_mode=metric_mode,
        unassigned_tasks=agg["unassigned_tasks"],
        company_summaries=company_summaries,
        company_table_rows=company_table_rows,
        company_totals=company_totals,
        company_user_rows=company_user_rows,
        company_task_rows=company_task_rows,
        risk_matrix=risk_matrix,
        unassigned_details=unassigned_details,
        page_name="templates/admin_task_dashboard.html",
    )

def _personal_view(user):
    """Render the regular user dashboard with their pending/completed tasks and charts."""
    profile_row = db.admin_get_user(user["id"], user.get("company_id"))
    db.ensure_user_assignments(user["id"], user.get("company_id"))

    user_full = {**user}
    if profile_row:
        user_full["first_name"] = profile_row["first_name"] if "first_name" in profile_row.keys() else None
        user_full["last_name"] = profile_row["last_name"] if "last_name" in profile_row.keys() else None

    tasks = db.get_tasks_for_user(user["id"])
    today = date.today()

    pending = [t for t in tasks if ((t["status"] if "status" in t.keys() else "") != "completed")]
    completed = [t for t in tasks if ((t["status"] if "status" in t.keys() else "") == "completed")]

    pending_display = [
        {**t, "overdue": overdue, "due_display": due_display}
        for t in pending
        for (overdue, due_display) in [core_utils.format_due_and_overdue(t["due_date"] if "due_date" in t.keys() else None, today)]
    ]

    completed_display = [
        {**t, "completed_on": core_utils.format_completed_on(t["completed_at"] if "completed_at" in t.keys() else None)}
        for t in completed
    ]

    total_tasks = len(tasks)
    completed_count = len(completed)
    pending_count = len(pending)
    pending_overdue = sum(1 for t in pending_display if t.get("overdue"))
    pending_non_overdue = max(pending_count - pending_overdue, 0)
    compliance_percent = round((completed_count / total_tasks) * 100, 1) if total_tasks else 0

    severity_labels, severity_data = core_utils.tally([t["severity"] if "severity" in t.keys() else None for t in tasks])
    impact_labels, impact_data = core_utils.tally([t["impact"] if "impact" in t.keys() else None for t in tasks])
    completion_data = [completed_count, pending_non_overdue, pending_overdue]

    settings_row = db.admin_get_app_settings()
    app_settings = dict(settings_row) if settings_row else {}

    role = user.get("role")
    role_setting_map = {
        "admin": ("show_user_charts_global", 1),
        "company_admin": ("show_user_charts_company", 1),
        "user": ("show_user_charts_user", 1),
    }
    key, default = role_setting_map.get(role, ("show_user_charts_user", 1))
    show_user_charts = bool(app_settings.get(key, default))

    return render_template(
        "dashboard.html",
        user=user_full,
        pending=pending_display,
        completed=completed_display,
        total_tasks=total_tasks,
        completed_count=completed_count,
        pending_count=pending_count,
        pending_overdue=pending_overdue,
        compliance_percent=compliance_percent,
        severity_labels=severity_labels,
        severity_data=severity_data,
        impact_labels=impact_labels,
        impact_data=impact_data,
        completion_data=completion_data,
        is_company_admin=user.get("role") == "company_admin",
        show_user_charts=show_user_charts,
        app_settings=app_settings,
        page_name="templates/dashboard.html",
    )

@app.route("/dashboard")
@login_required
def dashboard():
    """Dispatch to the appropriate dashboard view based on user role."""
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    if user["role"] == "admin":
        return _admin_view(user)
    if user["role"] == "company_admin" and request.args.get("view") != "personal":
        return _company_admin_view(user)
    return _personal_view(user)


# Helper: resolve acting user/task when admin is acting for someone else.
# Accepts either (user, task_id) or just (task_id,) to gracefully handle any stray calls.
def _resolve_override_from_request(user):
    """Resolve an override user_id from the request for admins/company_admins (module-level helper)."""
    acting_user = None
    acting_user_id = user["id"] if user else None
    override_user = request.args.get("user_id")
    if not (override_user and user and user.get("role") in ("admin", "company_admin")):
        return acting_user_id, acting_user
    try:
        target_id = int(override_user)
    except (TypeError, ValueError):
        return acting_user_id, acting_user
    company_scope = user.get("company_id") if user.get("role") == "company_admin" else None
    target_row = db.admin_get_user(target_id, company_scope)
    if target_row:
        return target_id, target_row
    return acting_user_id, acting_user

def _fetch_task_with_assignments_for(acting_user_id, task_id, user, acting_user):
    """Fetch the task for acting_user_id; ensure assignments and re-fetch once if missing (module-level helper)."""
    t = db.get_task_for_user(acting_user_id, task_id)
    if t is not None or not acting_user_id:
        return t
    # Determine company scope for ensuring assignments
    if acting_user:
        company_scope = acting_user.get("company_id")
    elif user:
        company_scope = user.get("company_id")
    else:
        company_scope = None
    db.ensure_user_assignments(acting_user_id, company_scope)
    return db.get_task_for_user(acting_user_id, task_id)

def _resolve_acting_user_and_task(user_or_task_id, task_id=None):
    """Return (acting_user_id, acting_user_row, task_row) and ensure assignments when needed."""
    # Normalize arguments: allow calling with (task_id,) or (user, task_id)
    if task_id is None:
        task_id = user_or_task_id
        user = current_user()
    else:
        user = user_or_task_id

    acting_user_id, acting_user = _resolve_override_from_request(user)
    t = _fetch_task_with_assignments_for(acting_user_id, task_id, user, acting_user)
    return acting_user_id, acting_user, t


def _format_task_dates_for_template(t):
    """Return (completed_at_display, due_date_display) for template rendering."""
    if t is None:
        return None, None
    # sqlite3.Row does not support .get; normalize to a dict for safe access.
    if not isinstance(t, dict):
        t = dict(t)
    completed_at_display = None
    due_date_display = None
    if t.get("due_date"):
        due_display = t.get("due_date")
        # Try common formats
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                due_dt = datetime.strptime(t["due_date"], fmt)
                due_display = due_dt.strftime(DATE_FMT)
                break
            except ValueError:
                continue
        due_date_display = due_display
    if t.get("completed_at"):
        comp_display = t.get("completed_at")
        try:
            completed_dt = datetime.fromisoformat(t["completed_at"])
            comp_display = completed_dt.strftime(DATE_FMT)
        except ValueError:
            pass
        completed_at_display = comp_display
    return completed_at_display, due_date_display


# Individual task view and answer submission
@app.route("/task/<int:task_id>", methods=["GET", "POST"])
@login_required
def task_detail(task_id):
    """Display a single task and accept an answer submission."""
    user = current_user()
    acting_user_id, acting_user, t = _resolve_acting_user_and_task(user, task_id)

    # If task couldn't be resolved, show not found
    if t is None:
        return "Task not found", 404

    # Normalize to a dict for safe .get access
    if not isinstance(t, dict):
        t = dict(t)

    # Determine editability: completed tasks are read-only for regular users; admins can edit.
    is_completed = t.get("status") == "completed"
    can_edit = True
    if is_completed and user.get("role") not in ("admin", "company_admin"):
        can_edit = False

    if request.method == "GET":
        completed_at_display, due_date_display = _format_task_dates_for_template(t)
        return render_template(
            "task_detail.html",
            task=t,
            completed_at_display=completed_at_display,
            due_date_display=due_date_display,
            is_completed=is_completed,
            can_edit=can_edit,
            acting_user=acting_user,
            page_name="templates/task_detail.html",
        )

    # POST: accept an answer and record the result
    if not can_edit:
        flash("This task is already completed and cannot be edited.")
        if acting_user:
            return redirect(f"/admin/report/{acting_user_id}")
        return redirect(url_for("core.dashboard"))

    user_answer = request.form.get("answer", "").strip()
    expected = (t.get("verification_answer") or "").strip()
    correct = user_answer.lower() == expected.lower()

    db.mark_task_result(acting_user_id, task_id, user_answer, correct)

    flash("Correct! Task completed." if correct else "Incorrect answer.")
    # If acting as another user, return to their admin report; otherwise go to personal dashboard
    if acting_user:
        return redirect(f"/admin/report/{acting_user_id}")
    return redirect(url_for("core.dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
