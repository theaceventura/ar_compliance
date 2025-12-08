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

from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import sys
from pathlib import Path

# Attempt to import the package-level DB module; if import fails (e.g. when running
# the app directly), add the project root to sys.path and retry the import.
try:
    import compliance_app.compliance_app_tailwind.db as db
except ImportError:
    ROOT_DIR = Path(__file__).resolve().parents[2]
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))
    import compliance_app.compliance_app_tailwind.db as db

app = Flask(__name__)
app.secret_key = "change_this_secret_key"
LOGIN_TEMPLATE = "login.html"
LOGIN_PAGE_NAME = "templates/login.html"
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

# Initialize database tables on startup (Flask 3 removed before_first_request)
db.create_tables_if_needed()

# Inject settings into all templates
@app.context_processor
def inject_app_settings():
    """Make app settings available to every template render and build a small banner payload."""
    settings = db.admin_get_app_settings()
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
            "company_admin": "Admin",
            "user": "User",
        }
        return mapping.get(role, role)
    if banner:
        banner["role_label"] = role_label(banner["role"])
    return {"app_settings": settings, "role_label": role_label, "current_user_banner": banner}


# Helper to read the current logged-in user from session
def current_user():
    """Return the current user dict from session, or None if not logged in."""
    if "user_id" not in session:
        return None
    return {
        "id": session["user_id"],
        "username": session["username"],
        "role": session["role"],
        "company_id": session.get("company_id"),
    }

def _is_hashed(pw):
    """Check whether a stored password value is hashed."""
    return isinstance(pw, str) and (pw.startswith("pbkdf2:") or pw.startswith("scrypt:"))

# Decorator to require any logged-in user
def login_required(route_function):
    """Redirect to login if no session user is present."""
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper

# Decorator for company admins
def company_admin_required(route_function):
    """Allow only company_admin role; redirect to login otherwise."""
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None or user["role"] != "company_admin":
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper

# Decorator to require an admin user
def admin_required(route_function):
    """Allow only admin role; redirect or 403 otherwise."""
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            return "Access denied", 403
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper


# Home page -> task dashboard if logged in, otherwise login
@app.route("/")
def index():
    """Send authenticated users to dashboard, others to login."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# Login page and submission
@app.route("/login", methods=["GET", "POST"])
def login():
    """Render the login form or authenticate the submitted credentials."""
    if request.method == "GET":
        user = current_user()
        if user is not None:
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        return render_template(LOGIN_TEMPLATE, page_name=LOGIN_PAGE_NAME)

    # POST handling
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user_row = db.get_user_by_username(username)
    if user_row is None:
        error = "Invalid username or password"
        return render_template(LOGIN_TEMPLATE, error=error, username=username, page_name=LOGIN_PAGE_NAME)

    stored_pw = user_row["password"]
    authed = False
    if _is_hashed(stored_pw):
        authed = check_password_hash(stored_pw, password)
    else:
        authed = stored_pw == password
        if authed:
            # Optionally upgrade plaintext passwords to a hashed value in the DB.
            # Leave as a no-op to avoid assumptions about DB API here.
            pass

    if not authed:
        error = "Invalid username or password"
        return render_template(LOGIN_TEMPLATE, error=error, username=username, page_name=LOGIN_PAGE_NAME)

    session["user_id"] = user_row["id"]
    session["username"] = user_row["username"]
    session["role"] = user_row["role"]
    # sqlite3.Row does not support .get, so pull with a keys check
    session["company_id"] = user_row["company_id"] if "company_id" in user_row.keys() else 1

    # Send all roles to the main dashboard (admin view is included there)
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    """Clear session and return to login page."""
    session.clear()
    return redirect(url_for("login"))


def _parse_color_map(val):
    """Convert a stored palette string like 'High:#f00,Low:#0f0' into a dict."""
    if not val:
        return {}
    mapping = {}
    for part in val.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            mapping[k.strip()] = v.strip()
        else:
            mapping[str(len(mapping))] = part
    return mapping

def _palette_for_labels(labels, fallback, stored_map):
    """Return a list of colors matching each label, using stored_map or fallback palette."""
    colors = []
    for idx, label in enumerate(labels):
        colors.append(stored_map.get(label, fallback[idx % len(fallback)]))
    return colors

def _build_risk_matrix(task_list, severity_order=None, impact_order=None, severity_sort=True):
    """Aggregate tasks into a severity x impact count matrix for the risk view."""
    severities = []
    impacts = []
    for t in task_list:
        sev = t.get("severity") or "Unspecified"
        imp = t.get("impact") or "Unspecified"
        if sev not in severities:
            severities.append(sev)
        if imp not in impacts:
            impacts.append(imp)
    if severity_order is None:
        severity_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    if impact_order is None:
        impact_order = {"Low": 0, "Medium": 1, "High": 2}
    if severity_sort:
        severities_sorted = sorted(severities, key=lambda v: (-severity_order.get(v, -1), v))
    else:
        severities_sorted = sorted(severities)
    impacts_sorted = sorted(impacts, key=lambda v: (impact_order.get(v, len(impact_order)), v))
    counts = {}
    for sev in severities_sorted:
        counts[sev] = dict.fromkeys(impacts_sorted, 0)
    for t in task_list:
        sev = t.get("severity") or "Unspecified"
        imp = t.get("impact") or "Unspecified"
        counts.setdefault(sev, dict.fromkeys(impacts_sorted, 0))
        counts[sev].setdefault(imp, 0)
        counts[sev][imp] += 1
    return {
        "severity_labels": severities_sorted,
        "impact_labels": impacts_sorted,
        "severity_ranks": {k: severity_order.get(k, 0) for k in severities_sorted},
        "impact_ranks": {k: impact_order.get(k, 0) for k in impacts_sorted},
        "counts": counts,
    }

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
    sev_map = _parse_color_map(settings.get("severity_palette"))
    imp_map = _parse_color_map(settings.get("impact_palette"))
    comp_map = _parse_color_map(settings.get("completion_palette"))
    default_palette = ['#2563eb', '#16a34a', '#f59e0b', '#ef4444', '#8b5cf6', '#0ea5e9']
    severity_palette = _palette_for_labels([c["label"] for c in severity_counts], default_palette, sev_map)
    impact_palette = _palette_for_labels([c["label"] for c in impact_counts], default_palette, imp_map)
    completion_labels = ["Completed", "Pending", "Overdue"]
    completion_defaults = ['#16a34a', '#f59e0b', '#ef4444']
    completion_palette = _palette_for_labels(completion_labels, completion_defaults, comp_map)
    return severity_palette, impact_palette, completion_palette

def _task_to_base(t, comp):
    """Normalize a task row with rollup data into the base dict used by templates."""
    base = {k: t[k] for k in t.keys()}
    base["assign_completed"] = comp.get("completed", 0)
    base["assign_total"] = comp.get("total", 0)
    base["fully_completed"] = base["assign_total"] > 0 and base["assign_completed"] == base["assign_total"]
    base["completion_pct"] = round((base["assign_completed"] / base["assign_total"]) * 100, 1) if base["assign_total"] else 0
    overdue_raw = t["overdue"] if "overdue" in t.keys() else False
    base["overdue"] = bool(overdue_raw and not base["fully_completed"])
    base["company_label"] = base["company_name"] if "company_name" in base.keys() and base["company_name"] else "Global"
    return base

def _admin_build_tasks_json(tasks, rollup, selected_company_id):
    tasks_out = []
    unassigned = []
    for t in tasks:
        comp = rollup.get(t["id"], {"completed": 0, "total": 0})
        base = _task_to_base(t, comp)
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
    """Prepare and return a dict of computed values for the admin dashboard to keep _admin_view small."""
    db.admin_ensure_assignments_for_company(selected_company_id)

    summary = db.admin_get_summary_counts(selected_company_id)
    severity_counts = db.admin_task_counts_by("severity", selected_company_id)
    impact_counts = db.admin_task_counts_by("impact", selected_company_id)

    compliance = [dict(r) for r in db.admin_user_compliance(selected_company_id)]
    compliance.sort(key=lambda u: ((u.get("first_name") or "") + (u.get("last_name") or "") + (u.get("username") or "")).lower())

    pending_non_overdue = max(summary.get("total_pending", 0) - summary.get("total_overdue", 0), 0)
    user_metrics = {
        "total_users": len(compliance),
        "completed_users": sum(1 for r in compliance if (r.get("pending_tasks") or 0) == 0),
        "pending_users": sum(1 for r in compliance if (r.get("pending_tasks") or 0) > 0),
        "overdue_users": sum(1 for r in compliance if (r.get("overdue_tasks") or 0) > 0),
    }
    user_metrics["compliance_pct"] = round((user_metrics["completed_users"] / user_metrics["total_users"]) * 100, 1) if user_metrics["total_users"] else 0

    settings_row = db.admin_get_app_settings()
    severity_palette, impact_palette, completion_palette = _admin_build_palettes_from_settings(settings_row, severity_counts, impact_counts)

    tasks = db.admin_get_all_tasks(selected_company_id)
    rollup = db.admin_task_completion_rollup(selected_company_id)
    tasks_json, unassigned_details = _admin_build_tasks_json(tasks, rollup, selected_company_id)

    task_total = len(tasks_json)
    task_overdue = sum(1 for t in tasks_json if t.get("overdue"))
    task_completed = sum(1 for t in tasks_json if t.get("fully_completed"))
    task_pending = max(task_total - task_completed, 0)
    task_compliance_percent = round((task_completed / task_total) * 100, 1) if task_total else 0

    assignment_total = sum(t.get("assign_total") or 0 for t in tasks_json)
    assignment_completed = sum(t.get("assign_completed") or 0 for t in tasks_json)
    assignment_counts = {
        "total": assignment_total,
        "completed": assignment_completed,
        "pending": max(assignment_total - assignment_completed, 0),
        "overdue": sum((t.get("assign_total") or 0) for t in tasks_json if t.get("overdue")),
    }

    user_counts = {
        "total": user_metrics["total_users"],
        "completed": user_metrics["completed_users"],
        "pending": user_metrics["pending_users"],
        "overdue": user_metrics["overdue_users"],
        "compliance": user_metrics["compliance_pct"],
    }

    # Company rollups
    unassigned_seen = set()
    companies_all = db.admin_get_companies(show_inactive=True)
    # Provide a mutable list into which _admin_build_company_rows can append
    company_summaries, company_user_rows = _admin_build_company_rows(companies_all, unassigned_seen, unassigned_details)

    company_summaries = company_summaries or []
    company_user_rows = company_user_rows or {}

    company_summaries.sort(key=lambda r: (r.get("name") or "").lower())

    company_table_rows = company_summaries
    company_totals = _compute_totals(company_table_rows)
    unassigned_tasks = company_totals["unassigned"] if company_totals else 0

    risk_matrix = _build_risk_matrix(tasks_json)
    task_counts = {
        "total": task_total,
        "completed": task_completed,
        "pending": task_pending,
        "overdue": task_overdue,
    }

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
        "task_compliance_percent": task_compliance_percent,
        "assignment_counts": assignment_counts,
        "user_metrics": user_metrics,
        "user_counts": user_counts,
        "companies_all": companies_all,
        "company_summaries": company_summaries,
        "company_user_rows": company_user_rows,
        "company_table_rows": company_table_rows,
        "company_totals": company_totals,
        "unassigned_details": unassigned_details,
        "unassigned_tasks": unassigned_tasks,
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

    # If a specific company is selected, re-order the summaries so selected appears first
    if selected_company_id is not None:
        data["company_summaries"].sort(
            key=lambda r: (0 if r.get("company_id") == selected_company_id else 1, (r.get("name") or "").lower())
        )

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
        unassigned_tasks=data["unassigned_tasks"],
        company_summaries=data["company_summaries"],
        company_totals=data["company_totals"],
        company_user_rows=data["company_user_rows"],
        company_table_rows=data["company_table_rows"],
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
    sev_map = _parse_color_map(settings_local.get("severity_palette"))
    imp_map = _parse_color_map(settings_local.get("impact_palette"))
    comp_map = _parse_color_map(settings_local.get("completion_palette"))
    default_palette = ['#2563eb', '#16a34a', '#f59e0b', '#ef4444', '#8b5cf6', '#0ea5e9']
    severity_palette = _palette_for_labels([c["label"] for c in sev_counts], default_palette, sev_map)
    impact_palette = _palette_for_labels([c["label"] for c in imp_counts], default_palette, imp_map)
    completion_labels = ["Completed", "Pending", "Overdue"]
    completion_defaults = ['#16a34a', '#f59e0b', '#ef4444']
    completion_palette = _palette_for_labels(completion_labels, completion_defaults, comp_map)
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
    risk_matrix = _build_risk_matrix(tasks_json, severity_order=None, impact_order={"Low": 0, "Medium": 1, "High": 2}, severity_sort=False)

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
        risk_matrix=risk_matrix,
        unassigned_details=unassigned_details,
        page_name="templates/admin_task_dashboard.html",
    )

def _format_due_and_overdue(due_str, today_date):
    """Return (is_overdue, due_display) for a due_date string, handling date/datetime."""
    if not due_str:
        return False, None
    parsed_date = None
    # First try plain date
    try:
        parsed_date = datetime.strptime(due_str, "%Y-%m-%d").date()
    except ValueError:
        # Try ISO datetime strings
        try:
            parsed_date = datetime.fromisoformat(due_str).date()
        except ValueError:
            parsed_date = None
    if parsed_date:
        return (parsed_date < today_date), parsed_date.strftime(DATE_FMT)
    return False, due_str

def _format_completed_on(completed_raw):
    """Return a formatted completed date string or the raw value."""
    if not completed_raw:
        return None
    try:
        completed_dt = datetime.fromisoformat(completed_raw)
        return completed_dt.strftime(DATE_FMT)
    except ValueError:
        return completed_raw

def _tally(values):
    """Convert a list of values into (labels, data) where None/empty become 'Unspecified'."""
    counts = {}
    for val in values:
        key = val if val else "Unspecified"
        counts[key] = counts.get(key, 0) + 1
    labels = list(counts.keys())
    data = [counts[k] for k in labels]
    return labels, data

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
        for (overdue, due_display) in [ _format_due_and_overdue(t["due_date"] if "due_date" in t.keys() else None, today) ]
    ]

    completed_display = [
        {**t, "completed_on": _format_completed_on(t["completed_at"] if "completed_at" in t.keys() else None)}
        for t in completed
    ]

    total_tasks = len(tasks)
    completed_count = len(completed)
    pending_count = len(pending)
    pending_overdue = sum(1 for t in pending_display if t.get("overdue"))
    pending_non_overdue = max(pending_count - pending_overdue, 0)
    compliance_percent = round((completed_count / total_tasks) * 100, 1) if total_tasks else 0

    severity_labels, severity_data = _tally([t["severity"] if "severity" in t.keys() else None for t in tasks])
    impact_labels, impact_data = _tally([t["impact"] if "impact" in t.keys() else None for t in tasks])
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
def _resolve_acting_user_and_task(user_or_task_id, task_id=None):
    """Return (acting_user_id, acting_user_row, task_row) and ensure assignments when needed."""
    if task_id is None:
        # If only the task_id was passed, infer the current user.
        task_id = user_or_task_id
        user = current_user()
    else:
        user = user_or_task_id

    acting_user_id = user["id"] if user else None
    acting_user = None
    override_user = request.args.get("user_id")
    if override_user and user and user.get("role") in ("admin", "company_admin"):
        try:
            target_id = int(override_user)
            target_row = db.admin_get_user(
                target_id,
                user.get("company_id") if user.get("role") == "company_admin" else None,
            )
            if target_row:
                acting_user_id = target_id
                acting_user = target_row
        except ValueError:
            pass

    t = db.get_task_for_user(acting_user_id, task_id)
    if t is None and acting_user is not None:
        # Ensure the target user has all applicable assignments
        db.ensure_user_assignments(acting_user_id, acting_user.get("company_id"))
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
        return redirect(url_for("dashboard"))

    user_answer = request.form.get("answer", "").strip()
    expected = (t.get("verification_answer") or "").strip()
    correct = user_answer.lower() == expected.lower()

    db.mark_task_result(acting_user_id, task_id, user_answer, correct)

    flash("Correct! Task completed." if correct else "Incorrect answer.")
    # If acting as another user, return to their admin report; otherwise go to personal dashboard
    if acting_user:
        return redirect(f"/admin/report/{acting_user_id}")
    return redirect(url_for("dashboard"))


# Admin task dashboard (task stats and charts)
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Show counts of users and companies for administrators."""
    admin = current_user()
    users = db.admin_get_all_users(admin["company_id"])
    companies = db.admin_get_companies()
    total_users = sum(1 for u in users if u["role"] == "user")
    total_admins = sum(1 for u in users if u["role"] == "admin")
    total_company_admins = sum(1 for u in users if u["role"] == "company_admin")
    total_companies = len(companies)
    active_companies = sum(1 for c in companies if ("is_active" in c.keys() and c["is_active"]))
    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=total_users,
        total_admins=total_admins,
        total_company_admins=total_company_admins,
        total_companies=total_companies,
        active_companies=active_companies,
        page_name="templates/admin_dashboard.html",
    )


def _select_company_id_for_admin():
    # Admins can pass company_id via query or use session; normalize values
    company_arg = request.args.get("company_id")
    if company_arg is None:
        return session.get("selected_company_id")
    company_arg = company_arg.strip()
    if company_arg in ("", "all"):
        session.pop("selected_company_id", None)
        return None
    try:
        selected = int(company_arg)
        session["selected_company_id"] = selected
        return selected
    except ValueError:
        return None

def _compute_user_metrics_from_compliance(rows):
    total = len(rows)
    completed = sum(1 for r in rows if ((r["pending_tasks"] if "pending_tasks" in r.keys() else 0) == 0))
    pending = sum(1 for r in rows if ((r["pending_tasks"] if "pending_tasks" in r.keys() else 0) > 0))
    overdue = sum(1 for r in rows if ((r["overdue_tasks"] if "overdue_tasks" in r.keys() else 0) > 0))
    pct = round((completed / total) * 100, 1) if total else 0
    return {
        "total_users": total,
        "completed_users": completed,
        "pending_users": pending,
        "overdue_users": overdue,
        "compliance_pct": pct,
    }

@app.route("/dashboard/users")
@login_required
def user_dashboard():
    """User/company-admin view showing user-level metrics and compliance."""
    user = current_user()
    if user["role"] not in ("admin", "company_admin"):
        return "Access denied", 403

    # Determine selected company scope
    if user["role"] == "admin":
        selected_company_id = _select_company_id_for_admin()
    else:
        selected_company_id = user.get("company_id")

    # Keep assignments in sync for the selected scope so compliance data is accurate
    db.admin_ensure_assignments_for_company(selected_company_id)

    summary = db.admin_get_summary_counts(selected_company_id)
    compliance = db.admin_user_compliance(selected_company_id)
    pending_non_overdue = max(summary.get("total_pending", 0) - summary.get("total_overdue", 0), 0)

    user_metrics = _compute_user_metrics_from_compliance(compliance)

    companies = db.admin_get_companies()
    if user["role"] == "company_admin" and selected_company_id:
        companies = [db.admin_get_company(selected_company_id)]

    return render_template(
        "user_dashboard.html",
        user=user,
        summary=summary,
        compliance=compliance,
        pending_non_overdue=pending_non_overdue,
        user_metrics=user_metrics,
        companies=companies,
        selected_company_id=selected_company_id,
        is_company_admin=user["role"] == "company_admin",
        page_name="templates/user_dashboard.html",
    )


# Admin: list/create tasks, manage option lists
def _admin_tasks_get_view(admin):
    """Helper to render the admin tasks GET view (extracted for clarity)."""
    company_arg = request.args.get("company_id", "").strip()
    if company_arg == "all" or company_arg == "":
        selected_company_id = None
    elif company_arg:
        try:
            selected_company_id = int(company_arg)
        except ValueError:
            selected_company_id = None
    else:
        selected_company_id = None

    tasks_raw = db.admin_get_all_tasks(selected_company_id)
    tasks = []
    for t in tasks_raw:
        due_display = None
        if t["due_date"]:
            try:
                due_dt = datetime.strptime(t["due_date"], "%Y-%m-%d")
                due_display = due_dt.strftime("%d/%m/%Y")
            except ValueError:
                due_display = t["due_date"]
        tasks.append({**t, "due_display": due_display})
    impacts = db.admin_get_options("impact", admin["company_id"])
    severities = db.admin_get_options("severity", admin["company_id"])
    users = db.admin_get_all_users(selected_company_id)
    descriptions = db.admin_get_task_field_descriptions()
    companies = db.admin_get_companies()
    company_lookup = {c["id"]: c["name"] for c in companies}
    return render_template(
        "admin_tasks.html",
        tasks=tasks,
        impacts=impacts,
        severities=severities,
        users=users,
        descriptions=descriptions,
        companies=companies,
        company_lookup=company_lookup,
        selected_company_id=selected_company_id,
        page_name="templates/admin_tasks.html",
    )


def _admin_tasks_handle_post(admin):
    """Helper to process the admin tasks POST (creation) action (extracted for clarity)."""
    title = request.form["title"].strip()
    question = request.form["verification_question"].strip()
    answer = request.form["verification_answer"].strip()
    description = request.form.get("description", "").strip()
    due_date = request.form.get("due_date", "").strip()
    impact = request.form.get("impact", "").strip()
    severity = request.form.get("severity", "").strip()
    selected_user_ids = [uid for uid in request.form.getlist("user_ids") if uid]
    assign_all = request.form.get("assign_all") == "on"
    owner_id = selected_user_ids[0] if selected_user_ids else None
    company_val = request.form.get("company_id", "").strip()
    company_id = int(company_val) if company_val else None
    descriptions = db.admin_get_task_field_descriptions()
    # Users limited to company scope if specified

    # Validate required fields based on admin configuration
    def _is_required(field):
        meta = descriptions.get(field, {})
        return meta.get("required", False)

    # Map fields to form values and user-facing labels for compact validation
    field_checks = [
        ("title", title, "Title"),
        ("description", description, "Description"),
        ("due_date", due_date, "Due date"),
        ("impact", impact, "Impact"),
        ("severity", severity, "Severity"),
        ("verification_question", question, "Verification question"),
        ("verification_answer", answer, "Verification answer"),
    ]

    missing = [label for (field, value, label) in field_checks if _is_required(field) and not value]

    # Assignment has special logic (either assign_all or selected_user_ids)
    if _is_required("assignment") and not (assign_all or selected_user_ids):
        missing.append("Assignment (select users or assign all)")

    if missing:
        users_filtered = db.admin_get_all_users(company_id)
        companies = db.admin_get_companies()
        return render_template(
            "admin_tasks.html",
            error="Please fill required fields: " + ", ".join(missing),
            tasks=db.admin_get_all_tasks(admin["company_id"]),
            impacts=db.admin_get_options("impact", admin["company_id"]),
            severities=db.admin_get_options("severity", admin["company_id"]),
            users=users_filtered,
            descriptions=descriptions,
            companies=companies,
            company_lookup={c["id"]: c["name"] for c in companies},
            selected_company_id=company_id,
            page_name="templates/admin_tasks.html",
        )

    db.admin_create_task(title, description, due_date, impact, severity, owner_id, question, answer, company_id, selected_user_ids, assign_all)
    flash("Task created.")
    return redirect(url_for("admin_tasks"))


@app.route("/admin/tasks", methods=["GET", "POST"])
@admin_required
def admin_tasks():
    """List tasks and handle creation in the admin view (delegates to helpers to reduce complexity)."""
    admin = current_user()
    if request.method == "GET":
        return _admin_tasks_get_view(admin)
    return _admin_tasks_handle_post(admin)

@app.route("/admin/task-config")
@admin_required
def admin_task_config():
    """Let admins view task field descriptions and option colors."""
    admin = current_user()
    impacts = db.admin_get_options("impact", admin["company_id"])
    severities = db.admin_get_options("severity", admin["company_id"])
    descriptions = db.admin_get_task_field_descriptions()
    settings_row = db.admin_get_app_settings()
    settings = dict(settings_row) if settings_row else {}
    def _palette_dict(val):
        if not val:
            return {}
        mapping = {}
        for part in val.split(","):
            part = part.strip()
            if not part or ":" not in part:
                continue
            k, v = part.split(":", 1)
            mapping[k.strip()] = v.strip()
        return mapping
    severity_colors = _palette_dict(settings.get("severity_palette"))
    impact_colors = _palette_dict(settings.get("impact_palette"))
    completion_colors = _palette_dict(settings.get("completion_palette"))
    return render_template(
        "admin_task_config.html",
        impacts=impacts,
        severities=severities,
        descriptions=descriptions,
        severity_colors=severity_colors,
        impact_colors=impact_colors,
        completion_colors=completion_colors,
        page_name="templates/admin_task_config.html",
    )


@app.route("/admin/task-config/fields", methods=["POST"])
@admin_required
def admin_task_field_update():
    """Persist admin edits to task field descriptions and required flags."""
    updates = {}
    for field in ("title", "description", "due_date", "impact", "severity", "verification_question", "verification_answer", "assignment"):
        updates[field] = {
            "description": request.form.get(field, "").strip(),
            "required": request.form.get(f"{field}_required") == "on",
        }
    db.admin_update_task_field_descriptions(updates)
    flash("Task field descriptions updated.")
    return redirect(url_for("admin_task_config"))


# Admin: edit a specific task
@app.route("/admin/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_task(task_id):
    """Display or save edits to a specific task."""
    admin = current_user()
    task = db.admin_get_task(task_id, admin["company_id"])
    if task is None:
        return "Task not found", 404
    is_global_scope = task["company_id"] is None
    task_company_scope = None if is_global_scope else (task["company_id"] or admin.get("company_id"))

    if request.method == "GET":
        assigned_ids = db.admin_get_task_assignments(task_id)
        assignment_status = db.admin_get_task_assignment_status(task_id)
        users_scope = db.admin_get_all_users() if is_global_scope else db.admin_get_all_users(task_company_scope)
        all_users = db.admin_get_all_users()
        return render_template(
            "admin_task_edit.html",
            task=task,
            impacts=db.admin_get_options("impact", admin["company_id"]),
            severities=db.admin_get_options("severity", admin["company_id"]),
            users=users_scope,
            all_users=all_users,
            companies=db.admin_get_companies(),
            assigned_ids=assigned_ids,
            assignment_status=assignment_status,
            page_name="templates/admin_task_edit.html",
        )

    title = request.form["title"].strip()
    question = request.form["verification_question"].strip()
    answer = request.form["verification_answer"].strip()
    description = request.form.get("description", "").strip()
    due_date = request.form.get("due_date", "").strip()
    impact = request.form.get("impact", "").strip()
    severity = request.form.get("severity", "").strip()
    owner_id = request.form.get("owner_user_id", "").strip() or None
    company_val = request.form.get("company_id", "").strip()
    company_id = int(company_val) if company_val else None
    assign_all = request.form.get("assign_all") == "on"
    # If global scope, apply to all users
    if company_id is None:
        assign_all = True
    user_ids = request.form.getlist("user_ids")

    if not title or not question or not answer:
        return render_template(
            "admin_task_edit.html",
            task=task,
            impacts=db.admin_get_options("impact", admin["company_id"]),
            severities=db.admin_get_options("severity", admin["company_id"]),
            users=db.admin_get_all_users() if company_id is None else db.admin_get_all_users(task_company_scope),
            all_users=db.admin_get_all_users(),
            companies=db.admin_get_companies(),
            assignment_status=db.admin_get_task_assignment_status(task_id),
            error="Title, question and answer required.",
            assigned_ids=db.admin_get_task_assignments(task_id),
            page_name="templates/admin_task_edit.html",
        )

    db.admin_update_task(task_id, title, description, due_date, impact, severity, owner_id, question, answer, company_id)
    db.admin_update_task_assignments(task_id, company_id, user_ids, assign_all)
    flash("Task updated.")
    return redirect(url_for("admin_tasks"))


# Admin: user list and selection
@app.route("/admin/users")
@admin_required
def admin_users():
    """List users and show a selected user's details for admins."""
    admin = current_user()
    selected_id = request.args.get("user_id", type=int)
    filter_company_id = request.args.get("company_id", type=int)
    selected_user = db.admin_get_user(selected_id) if selected_id else None
    users = db.admin_get_all_users(filter_company_id) if filter_company_id else db.admin_get_all_users()
    companies = db.admin_get_companies()
    company_lookup = {c["id"]: c["name"] for c in companies}
    compliance_rows = db.admin_user_compliance(filter_company_id)
    user_task_counts = {}
    for r in compliance_rows:
        total_tasks_val = r["total_tasks"] if "total_tasks" in r.keys() else 0
        user_task_counts[r["id"]] = total_tasks_val
    unassigned_users_count = sum(1 for u in users if user_task_counts.get(u["id"], 0) == 0)
    return render_template(
        ADMIN_USERS_TEMPLATE,
        users=users,
        selected_user=selected_user,
        companies=companies,
        company_lookup=company_lookup,
        allow_admin_role=True,
        is_company_admin=False,
        selected_company_id=filter_company_id,
        user_task_counts=user_task_counts,
        unassigned_users_count=unassigned_users_count,
        page_name=f"templates/{ADMIN_USERS_TEMPLATE}",
    )


# Admin: create or update a user
def _admin_users_render_error(msg, selected_user_id=None, selected_company_id=None):
    companies = db.admin_get_companies()
    return render_template(
        ADMIN_USERS_TEMPLATE,
        users=db.admin_get_all_users(),
        error=msg,
        selected_user=db.admin_get_user(selected_user_id) if selected_user_id else None,
        companies=companies,
        company_lookup={c["id"]: c["name"] for c in companies},
        selected_company_id=selected_company_id,
        page_name=f"templates/{ADMIN_USERS_TEMPLATE}",
    )

def _admin_users_collect_payload():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "").strip()
    first_name = request.form.get("first_name", "").strip() or None
    last_name = request.form.get("last_name", "").strip() or None
    email = request.form.get("email", "").strip() or None
    mobile = request.form.get("mobile", "").strip() or None
    send_notifications = request.form.get("send_notifications") == "on"
    is_active = request.form.get("is_active") == "on"
    user_id = request.form.get("user_id", type=int)
    company_id = request.form.get("company_id", type=int)
    hashed_pw = generate_password_hash(password) if password else None
    return {
        "username": username,
        "hashed_pw": hashed_pw,
        "role": role,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "mobile": mobile,
        "send_notifications": send_notifications,
        "is_active": is_active,
        "user_id": user_id,
        "company_id": company_id,
    }

def _admin_users_validate_payload(payload):
    # Required fields
    required_pairs = (
        ("Username", "username"),
        ("First Name", "first_name"),
        ("Last Name", "last_name"),
        ("Email", "email"),
    )
    missing = [label for (label, key) in required_pairs if not payload.get(key)]
    # Password required when creating a new user
    if not payload.get("user_id") and not payload.get("hashed_pw"):
        missing.append("Password")
    # Role and company checks
    if payload.get("role") not in ("user", "admin", "company_admin"):
        missing.append("Role")
    if payload.get("company_id") is None:
        missing.append("Company")
    return missing

@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    """Create or update a user from the admin form submission."""
    admin = current_user()
    payload = _admin_users_collect_payload()
    missing = _admin_users_validate_payload(payload)
    if missing:
        return _admin_users_render_error(
            "Missing required fields: " + ", ".join(missing),
            selected_user_id=payload.get("user_id"),
            selected_company_id=None,
        )

    # Perform DB operation (update vs create)
    if payload.get("user_id"):
        error = db.admin_update_user(
            payload["user_id"],
            payload["username"],
            payload["hashed_pw"],
            payload["role"],
            payload["first_name"],
            payload["last_name"],
            payload["email"],
            payload["mobile"],
            payload["send_notifications"],
            payload["company_id"],
            payload.get("is_active"),
        )
    else:
        error = db.admin_create_user(
            payload["username"],
            payload["hashed_pw"],
            payload["role"],
            payload["first_name"],
            payload["last_name"],
            payload["email"],
            payload["mobile"],
            payload["send_notifications"],
            payload["company_id"],
            payload.get("is_active"),
        )

    if error:
        return _admin_users_render_error(error, selected_user_id=payload.get("user_id"))

    flash("User updated." if payload.get("user_id") else "User created.")
    return redirect(url_for("admin_users"))


# Company admin: manage users for their company
def _company_admin_build_context(company_id, selected_id, selected_user=None, users=None, user_task_counts=None):
    """Build the company-admin user list context scoped to their company."""
    if users is None:
        users = db.admin_get_all_users(company_id)

    if selected_user is None:
        if selected_id:
            selected_user = db.admin_get_user(selected_id, company_id)
        else:
            selected_user = None

    company_row = db.admin_get_company(company_id)
    companies = [company_row] if company_row else []
    company_lookup = {company_row["id"]: company_row["name"]} if company_row else {}
    if user_task_counts is None:
        compliance_rows = db.admin_user_compliance(company_id)
        user_task_counts = {r["id"]: (r["total_tasks"] if "total_tasks" in r.keys() else 0) for r in compliance_rows}
    unassigned_users_count = sum(1 for u in users if user_task_counts.get(u["id"], 0) == 0)
    return {
        "users": users,
        "selected_user": selected_user,
        "companies": companies,
        "company_lookup": company_lookup,
        "allow_admin_role": False,
        "is_company_admin": True,
        "user_task_counts": user_task_counts,
        "unassigned_users_count": unassigned_users_count,
        "page_name": COMPANY_ADMIN_USERS_TEMPLATE,
    }

def _company_admin_collect_and_validate(company_id):
    """Collect and validate fields when a company admin creates or updates a user."""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "user")
    if role not in ("user", "company_admin"):
        role = ""
    first_name = request.form.get("first_name", "").strip() or None
    last_name = request.form.get("last_name", "").strip() or None
    email = request.form.get("email", "").strip() or None
    mobile = request.form.get("mobile", "").strip() or None
    send_notifications = request.form.get("send_notifications") == "on"
    user_id = request.form.get("user_id", type=int)
    hashed_pw = generate_password_hash(password) if password else None

    missing = []
    if not username:
        missing.append("Username")
    if not password:
        missing.append("Password")
    if not first_name:
        missing.append("First Name")
    if not last_name:
        missing.append("Last Name")
    if not email:
        missing.append("Email")
    if not role:
        missing.append("Role")
    if not company_id:
        missing.append("Company")

    return {
        "username": username,
        "hashed_pw": hashed_pw,
        "role": role,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "mobile": mobile,
        "send_notifications": send_notifications,
        "user_id": user_id,
        "missing": missing,
    }

def _company_admin_perform_create_or_update(payload, company_id):
    """Execute create/update for company-admin user actions; enforce company scope."""
    if payload["user_id"]:
        target = db.admin_get_user(payload["user_id"])
        if target and target.get("company_id") != company_id:
            return None, True
        error = db.admin_update_user(
            payload["user_id"],
            payload["username"],
            payload["hashed_pw"],
            payload["role"],
            payload["first_name"],
            payload["last_name"],
            payload["email"],
            payload["mobile"],
            payload["send_notifications"],
            company_id,
        )
        return error, False
    else:
        error = db.admin_create_user(
            payload["username"],
            payload["hashed_pw"],
            payload["role"],
            payload["first_name"],
            payload["last_name"],
            payload["email"],
            payload["mobile"],
            payload["send_notifications"],
            company_id,
        )
        return error, False

@app.route("/company-admin/users", methods=["GET", "POST"])
@company_admin_required
def company_admin_users():
    """Company admins manage users within their own company."""
    admin = current_user()
    company_id = admin["company_id"]
    selected_id = request.args.get("user_id", type=int)

    # GET: render list view
    if request.method == "GET":
        ctx = _company_admin_build_context(company_id, selected_id)
        return render_template(ADMIN_USERS_TEMPLATE, **ctx)

    # POST: handle create/update using module-level helpers to keep complexity low
    payload = _company_admin_collect_and_validate(company_id)
    if payload["missing"]:
        users = db.admin_get_all_users(company_id)
        selected_user = db.admin_get_user(payload["user_id"], company_id) if payload["user_id"] else None
        ctx = _company_admin_build_context(company_id, selected_id, selected_user=selected_user, users=users)
        ctx["error"] = "Missing required fields: " + ", ".join(payload["missing"])
        return render_template(ADMIN_USERS_TEMPLATE, **ctx)

    error, forbidden = _company_admin_perform_create_or_update(payload, company_id)
    if forbidden:
        return "Forbidden", 403
    if error:
        users = db.admin_get_all_users(company_id)
        selected_user = db.admin_get_user(payload["user_id"], company_id) if payload["user_id"] else None
        ctx = _company_admin_build_context(company_id, selected_id, selected_user=selected_user, users=users)
        ctx["error"] = error
        return render_template(ADMIN_USERS_TEMPLATE, **ctx)

    flash("User updated." if payload["user_id"] else "User created.")
    return redirect(url_for("company_admin_users"))
# Admin: manage companies
def _admin_companies_active_counts(companies_list):
    """Return two dicts: active user counts and total user counts per company id."""
    active_counts = {}
    total_counts = {}
    for co in companies_list or []:
        users_for_co = db.admin_get_all_users(co["id"])
        total_counts[co["id"]] = len(users_for_co)
        active_counts[co["id"]] = sum(
            1
            for u in users_for_co
            if ("is_active" in u.keys() and u["is_active"]) or ("is_active" not in u.keys())
        )
    return active_counts, total_counts


def _admin_companies_render(companies, selected_company, company_users, active_user_counts, total_user_counts, error=None):
    """Render helper for the admin companies page."""
    return render_template(
        "admin_companies.html",
        companies=companies,
        selected_company=selected_company,
        company_users=company_users,
        active_user_counts=active_user_counts,
        total_user_counts=total_user_counts,
        error=error,
        page_name="templates/admin_companies.html",
    )


def _collect_company_form_data():
    """Extract and normalize company form fields from request."""
    return {
        "company_id": request.form.get("company_id", type=int),
        "name": request.form.get("name", "").strip(),
        "admin_user_id": request.form.get("admin_user_id", type=int),
        "address1": request.form.get("address1", "").strip() or None,
        "address2": request.form.get("address2", "").strip() or None,
        "address3": request.form.get("address3", "").strip() or None,
        "state": request.form.get("state", "").strip() or None,
        "postcode": request.form.get("postcode", "").strip() or None,
        "is_active": request.form.get("is_active") == "on",
    }

def _build_companies_error_response(show_inactive, company_id, selected_company, error_msg):
    """Prepare the standard error response for the companies page."""
    companies = db.admin_get_companies(show_inactive=show_inactive)
    users_for_company = db.admin_get_all_users(company_id) if company_id else []
    active_user_counts, total_user_counts = _admin_companies_active_counts(companies)
    return _admin_companies_render(companies, selected_company, users_for_company, active_user_counts, total_user_counts, error_msg)

def _validate_company_admin_belongs(admin_user_id, company_id):
    """Return an error message if the selected admin user does not belong to the company, otherwise None."""
    if not admin_user_id or not company_id:
        return None
    user_row = db.admin_get_user(admin_user_id)
    if not user_row or ("company_id" in user_row.keys() and user_row["company_id"] != company_id):
        return "Selected company admin must belong to this company."
    return None

@app.route("/admin/companies", methods=["GET", "POST"])
@admin_required
def admin_companies():
    """Create or update companies and assign company admins."""
    admin = current_user()
    selected_id = request.args.get("company_id", type=int)
    show_inactive = bool(request.args.get("show_inactive"))
    selected_company = db.admin_get_company(selected_id) if selected_id else None

    if request.method == "POST":
        payload = _collect_company_form_data()
        company_id = payload["company_id"]
        name = payload["name"]
        admin_user_id = payload["admin_user_id"]
        address1 = payload["address1"]
        address2 = payload["address2"]
        address3 = payload["address3"]
        state = payload["state"]
        postcode = payload["postcode"]
        is_active = payload["is_active"]

        if not name:
            return _build_companies_error_response(show_inactive, company_id, selected_company, "Company name is required.")

        validation_error = _validate_company_admin_belongs(admin_user_id, company_id)
        if validation_error:
            return _build_companies_error_response(show_inactive, company_id, selected_company, validation_error)

        # Create or update the company record
        if company_id:
            error = db.admin_update_company(company_id, name, admin_user_id, address1, address2, address3, state, postcode, is_active)
            flash_msg = "Company updated."
        else:
            error = db.admin_create_company(name, address1, address2, address3, state, postcode, admin_user_id, is_active)
            flash_msg = "Company created."

        if error:
            return _build_companies_error_response(show_inactive, company_id, selected_company, error)

        flash(flash_msg)
        return redirect(url_for("admin_companies"))

    # GET path
    companies = db.admin_get_companies(show_inactive=show_inactive)
    company_users = db.admin_get_all_users(selected_id) if selected_id else []
    active_user_counts, total_user_counts = _admin_companies_active_counts(companies)
    return _admin_companies_render(companies, selected_company, company_users, active_user_counts, total_user_counts)


@app.route("/admin/options/<opt_type>/add", methods=["POST"])
@admin_required
def admin_add_option(opt_type):
    """Add a new impact or severity option."""
    if opt_type not in ("impact", "severity"):
        return INVALID_OPTION_TYPE, 400
    value = request.form.get("value", "").strip()
    color = request.form.get("color", "").strip()
    admin = current_user()
    if not value:
        flash("Value required.")
        return redirect(url_for("admin_tasks"))
    error = db.admin_add_option(opt_type, value, admin["company_id"])
    if error:
        flash(error)
    else:
        flash("Option added.")
        if color:
            db.admin_set_option_color(opt_type, value, color)
    return redirect(url_for("admin_tasks"))


@app.route("/admin/options/<opt_type>/<int:option_id>/delete", methods=["POST"])
@admin_required
def admin_delete_option(opt_type, option_id):
    """Remove an impact or severity option."""
    if opt_type not in ("impact", "severity"):
        return INVALID_OPTION_TYPE, 400
    admin = current_user()
    db.admin_delete_option(opt_type, option_id, admin["company_id"])
    flash("Option removed.")
    return redirect(url_for("admin_tasks"))


@app.route("/admin/options/<opt_type>/<int:option_id>/color", methods=["POST"])
@admin_required
def admin_update_option_color(opt_type, option_id):
    """Update the stored colour for an option label."""
    if opt_type not in ("impact", "severity"):
        return INVALID_OPTION_TYPE, 400
    color = request.form.get("color", "").strip()
    admin = current_user()
    opt = db.admin_get_option(opt_type, option_id, admin["company_id"])
    if opt is None:
        return "Option not found", 404
    if color:
        db.admin_set_option_color(opt_type, opt["value"], color)
        flash("Option colour updated.")
    else:
        flash("Colour is required.")
    return redirect(url_for("admin_task_config"))
# Admin: app settings page
@app.route("/admin/app", methods=["GET", "POST"])
@admin_required
def admin_app_settings():
    """Render and save global app settings and completion colours."""
    settings = db.admin_get_app_settings()
    if request.method == "GET":
        completion_colors = {}
        palette = settings["completion_palette"] if settings else ""
        if palette:
            for part in palette.split(","):
                if ":" in part:
                    k, v = part.split(":", 1)
                    completion_colors[k.strip()] = v.strip()
        return render_template("admin_app.html", settings=settings, completion_colors=completion_colors, page_name="templates/admin_app.html")

    version = request.form.get("version", "").strip()
    show_version = request.form.get("show_version") == "on"
    show_page_name = request.form.get("show_page_name") == "on"
    show_module_tree = request.form.get("show_module_tree") == "on"
    show_cut_icon = request.form.get("show_cut_icon") == "on"
    show_label_edit = request.form.get("show_label_edit") == "on"
    show_task_charts = request.form.get("show_task_charts") == "on"
    show_risk_matrix = request.form.get("show_risk_matrix") == "on"
    show_user_banner = request.form.get("show_user_banner") == "on"
    show_user_charts_global = request.form.get("show_user_charts_global") == "on"
    show_user_charts_company = request.form.get("show_user_charts_company") == "on"
    show_user_charts_user = request.form.get("show_user_charts_user") == "on"
    show_validation_notes = request.form.get("show_validation_notes") == "on"
    db.admin_update_app_settings(
        version,
        show_version,
        show_page_name,
        show_module_tree,
        show_cut_icon,
        show_label_edit,
        show_task_charts,
        show_risk_matrix,
        show_user_banner,
        show_user_charts_global,
        show_user_charts_company,
        show_user_charts_user,
        show_validation_notes,
    )
    flash("Settings updated.")
    return redirect(url_for("admin_app_settings"))

# Admin: save chart colors from task config
@app.route("/admin/task-config/colors", methods=["POST"])
@admin_required
def admin_task_config_colors():
    """Persist completion palette overrides from the task config page."""
    settings_row = db.admin_get_app_settings()
    settings = dict(settings_row) if settings_row else {}
    severity_palette = settings.get("severity_palette", "")
    impact_palette = settings.get("impact_palette", "")
    completion_completed = request.form.get("completion_completed", "").strip()
    completion_pending = request.form.get("completion_pending", "").strip()
    completion_overdue = request.form.get("completion_overdue", "").strip()
    completion_parts = []
    if completion_completed:
        completion_parts.append(f"Completed:{completion_completed}")
    if completion_pending:
        completion_parts.append(f"Pending:{completion_pending}")
    if completion_overdue:
        completion_parts.append(f"Overdue:{completion_overdue}")
    completion_palette = ",".join(completion_parts)
    db.admin_update_chart_palettes(severity_palette, impact_palette, completion_palette)
    flash("Chart colors updated.")
    return redirect(url_for("admin_task_config"))
# Admin: send notifications for overdue tasks (console simulation)
def _get_overdue_titles_for_user(user_row, today_date):
    """Return a list of overdue task titles for the given user and date."""
    titles = []
    tasks = db.get_tasks_for_user(user_row["id"])
    for t in tasks:
        if t.get("status") == "completed":
            continue
        due_str = t.get("due_date")
        if not due_str:
            continue
        try:
            due_obj = datetime.strptime(due_str, "%Y-%m-%d").date()
        except ValueError:
            continue
        if due_obj < today_date:
            titles.append(t.get("title"))
    return titles

@app.route("/admin/notify/overdue")
@admin_required
def admin_notify_overdue():
    """Simulate sending overdue notifications to opted-in users (prints to console)."""
    # Print a simple notice for users who opted in and have overdue tasks
    today = date.today()
    sent = 0
    users = db.admin_get_all_users(current_user()["company_id"])
    for u in users:
        if not u.get("send_notifications"):
            continue
        overdue = _get_overdue_titles_for_user(u, today)
        if not overdue:
            continue
        sent += 1
        print(f"[Notification] To {u['username']} ({u.get('email') or 'no email'}): overdue tasks -> {', '.join(overdue)}")
    flash(f"Notifications sent to {sent} users (printed to console).")
    return redirect(url_for("admin_dashboard"))


# Admin: user report page
def _format_admin_report_task(t):
    if not isinstance(t, dict):
        t = dict(t)
    due_display = t.get("due_date")
    if t.get("due_date"):
        try:
            due_dt = datetime.strptime(t["due_date"], "%Y-%m-%d")
            due_display = due_dt.strftime(DATE_FMT)
        except ValueError:
            due_display = t["due_date"]
    completed_display = t.get("completed_at")
    if t.get("completed_at"):
        try:
            comp_dt = datetime.fromisoformat(t["completed_at"])
            completed_display = comp_dt.strftime(DATE_FMT)
        except ValueError:
            completed_display = t["completed_at"]
    if t.get("company_id"):
        task_type = t.get("company_name") or "Company"
    else:
        task_type = "Global"
    return {
        **t,
        "due_display": due_display,
        "completed_display": completed_display,
        "task_id": t["id"],
        "task_type": task_type,
    }

@app.route("/admin/report/<int:user_id>")
@login_required
def admin_report(user_id):
    """Admin/company-admin view of a single user's task report (role scoped)."""
    viewer = current_user()
    if viewer.get("role") not in ("admin", "company_admin"):
        return "Access denied", 403

    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return USER_NOT_FOUND, 404
    if not isinstance(user_row, dict):
        user_row = dict(user_row)

    # company admins can only view users in their company
    if viewer.get("role") == "company_admin":
        if user_row.get("company_id") != viewer.get("company_id"):
            return NOT_FOUND, 404

    formatted_tasks = [_format_admin_report_task(t) for t in tasks]
    return render_template("admin_report.html", user=user_row, tasks=formatted_tasks, page_name="templates/admin_report.html")


# Admin: export user report CSV
@app.route("/admin/report/<int:user_id>/csv")
@admin_required
def admin_report_csv(user_id):
    """Stream a CSV export of a user's task report."""
    # Build a CSV stream for a single user's tasks
    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return USER_NOT_FOUND, 404
    admin_company_id = current_user().get("company_id")
    if admin_company_id is not None and user_row.get("company_id") != admin_company_id:
        return "Not found", 404
    def generate():
        yield "Title,Due Date,Status,Completed At,Answer\\n"
        for t in tasks:
            title = (t.get("title") or "").replace('"', '""')
            due = t.get("due_date") or ""
            status = t.get("status") or ""
            completed_at = t.get("completed_at") or ""
            answer = (t.get("answer_text") or "").replace('"', '""')
            yield f"\"{title}\",{due},{status},{completed_at},\"{answer}\"\\n"
    return Response(generate(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=report_{user_id}.csv"})

@app.route("/company-admin/report/<int:user_id>")
@company_admin_required
def company_admin_report(user_id):
    """Company admin report view scoped strictly to their company."""
    admin = current_user()
    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return USER_NOT_FOUND, 404
    if not isinstance(user_row, dict):
        user_row = dict(user_row)
    tasks = [dict(t) for t in tasks]
    # Ensure company-admins can only view reports for users in their own company
    if user_row.get("company_id") != admin.get("company_id"):
        return NOT_FOUND, 404

    formatted_tasks = [_format_admin_report_task(t) for t in tasks]
    return render_template("admin_report.html", user=user_row, tasks=formatted_tasks, page_name="templates/admin_report.html")


# Admin: edit own profile
@app.route("/admin/profile", methods=["GET", "POST"])
@login_required
def admin_profile():
    """Let the signed-in user view and edit their profile details."""
    viewer = current_user()
    user = db.admin_get_user(viewer["id"])
    role = viewer.get("role")

    # Determine company selection permissions
    if role == "admin":
        companies = db.admin_get_companies()
        allow_company_change = True
        locked_company_id = None
    else:
        # company_admin and regular users are restricted to their own company
        companies = [c for c in db.admin_get_companies() if c["id"] == viewer.get("company_id")]
        allow_company_change = False
        locked_company_id = viewer.get("company_id")

    # GET: render profile form
    if request.method == "GET":
        return render_template(
            ADMIN_PROFILE_TEMPLATE,
            user=user,
            companies=companies,
            is_company_admin=(role == "company_admin"),
            allow_company_change=allow_company_change,
            page_name=ADMIN_PROFILE_PAGE_NAME,
        )

    # POST: update profile
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    first_name = request.form.get("first_name", "").strip() or None
    last_name = request.form.get("last_name", "").strip() or None
    email = request.form.get("email", "").strip() or None
    mobile = request.form.get("mobile", "").strip() or None
    send_notifications = request.form.get("send_notifications") == "on"
    is_active = request.form.get("is_active") == "on"
    req_company_id = request.form.get("company_id", type=int)

    if role == "admin":
        company_id = req_company_id if req_company_id is not None else None
    else:
        company_id = locked_company_id or user.get("company_id")

    if not username:
        return render_template(
            ADMIN_PROFILE_TEMPLATE,
            user=user,
            companies=companies,
            is_company_admin=(role == "company_admin"),
            allow_company_change=allow_company_change,
            error="Username is required.",
            page_name=ADMIN_PROFILE_PAGE_NAME,
        )

    hashed_pw = generate_password_hash(password) if password else None

    err = db.admin_update_user(
        user["id"],
        username,
        hashed_pw,
        user["role"],
        first_name,
        last_name,
        email,
        mobile,
        send_notifications,
        company_id,
        is_active,
    )

    if err:
        return render_template(
            ADMIN_PROFILE_TEMPLATE,
            user=user,
            companies=companies,
            is_company_admin=(role == "company_admin"),
            allow_company_change=allow_company_change,
            error=err,
            page_name=ADMIN_PROFILE_PAGE_NAME,
        )

    # Keep session in sync
    session["username"] = username
    session["company_id"] = company_id

    flash("Profile updated.")
    return redirect(url_for("admin_profile"))

# Admin: export compliance summary CSV
@app.route("/admin/report/summary.csv")
@admin_required
def admin_summary_csv():
    """Stream a CSV of overall compliance stats for all users."""
    # Stream overall compliance stats for all users
    compliance = db.admin_user_compliance(None)
    def generate():
        yield "Username,Role,Completed,Total,Compliance%\\n"
        for row in compliance:
            total = row["total_tasks"] or 0
            completed = row["completed_tasks"] or 0
            pct = round((completed / total) * 100, 1) if total else 0
            yield f"{row['username']},{row['role']},{completed},{total},{pct}\\n"
    return Response(generate(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=compliance_summary.csv"})


if __name__ == "__main__":
    app.run(debug=True)
