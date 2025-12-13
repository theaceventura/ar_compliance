"""Core (non-admin) routes: auth, dashboard, task detail."""

from datetime import date, datetime

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from compliance_app import db
from compliance_app.auth_helpers import current_user, login_required
from compliance_app.core_utils import (
    format_due_and_overdue,
    format_completed_on,
    tally,
)


LOGIN_TEMPLATE = "login.html"
LOGIN_PAGE_NAME = "templates/login.html"
DATE_FMT = "%d/%m/%Y"
ACCESS_DENIED = "Access denied"

core_bp = Blueprint("core", __name__)


@core_bp.route("/", endpoint="index")
def index():
    """Send authenticated users to dashboard, others to login."""
    if "user_id" in session:
        return redirect(url_for("core.dashboard"))
    return redirect(url_for("core.login"))


@core_bp.route("/login", methods=["GET", "POST"], endpoint="login")
def login():
    """Render the login form or authenticate the submitted credentials."""
    if request.method == "GET":
        user = current_user()
        if user is not None:
            # Always route through the dashboard dispatcher; it will choose the right view.
            return redirect(url_for("core.dashboard"))
        return render_template(LOGIN_TEMPLATE, page_name=LOGIN_PAGE_NAME)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user_row = db.get_user_by_username(username)
    if user_row is None:
        error = "Invalid username or password"
        return render_template(LOGIN_TEMPLATE, error=error, username=username, page_name=LOGIN_PAGE_NAME)

    stored_pw = user_row["password"]
    authed = False
    if isinstance(stored_pw, str) and (stored_pw.startswith("pbkdf2:") or stored_pw.startswith("scrypt:")):
        authed = check_password_hash(stored_pw, password)
    else:
        authed = stored_pw == password

    if not authed:
        error = "Invalid username or password"
        return render_template(LOGIN_TEMPLATE, error=error, username=username, page_name=LOGIN_PAGE_NAME)

    session["user_id"] = user_row["id"]
    session["username"] = user_row["username"]
    session["role"] = user_row["role"]
    session["company_id"] = user_row["company_id"] if "company_id" in user_row.keys() else 1
    return redirect(url_for("core.dashboard"))


@core_bp.route("/logout", endpoint="logout")
def logout():
    """Clear session and return to login page."""
    session.clear()
    return redirect(url_for("core.login"))


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
        for (overdue, due_display) in [format_due_and_overdue(t["due_date"] if "due_date" in t.keys() else None, today)]
    ]

    completed_display = [
        {**t, "completed_on": format_completed_on(t["completed_at"] if "completed_at" in t.keys() else None)}
        for t in completed
    ]

    total_tasks = len(tasks)
    completed_count = len(completed)
    pending_count = len(pending)
    pending_overdue = sum(1 for t in pending_display if t.get("overdue"))
    pending_non_overdue = max(pending_count - pending_overdue, 0)
    compliance_percent = round((completed_count / total_tasks) * 100, 1) if total_tasks else 0

    severity_labels, severity_data = tally([t["severity"] if "severity" in t.keys() else None for t in tasks])
    impact_labels, impact_data = tally([t["impact"] if "impact" in t.keys() else None for t in tasks])
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


@core_bp.route("/dashboard", endpoint="dashboard")
@login_required
def dashboard():
    """Dispatch to the appropriate dashboard view based on user role."""
    user = current_user()
    if user is None:
        return redirect(url_for("core.login"))
    # Admins and company admins get the rich task dashboard from the main app module.
    if user["role"] == "admin":
        from importlib import import_module
        app_module = import_module("compliance_app.app")
        return app_module._admin_view(user)
    if user["role"] == "company_admin" and request.args.get("view") != "personal":
        from importlib import import_module
        app_module = import_module("compliance_app.app")
        return app_module._company_admin_view(user)
    return _personal_view(user)


def _resolve_override_from_request(user):
    """Resolve an override user_id from the request for admins/company_admins."""
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
    """Fetch the task for acting_user_id; ensure assignments and re-fetch once if missing."""
    t = db.get_task_for_user(acting_user_id, task_id)
    if t is not None or not acting_user_id:
        return t
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
    if not isinstance(t, dict):
        t = dict(t)
    completed_at_display = None
    due_date_display = None
    if t.get("due_date"):
        due_display = t.get("due_date")
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


@core_bp.route("/task/<int:task_id>", methods=["GET", "POST"], endpoint="task_detail")
@login_required
def task_detail(task_id):
    """Display a single task and accept an answer submission."""
    user = current_user()
    acting_user_id, acting_user, t = _resolve_acting_user_and_task(user, task_id)

    if t is None:
        return "Task not found", 404

    if not isinstance(t, dict):
        t = dict(t)

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
    if acting_user:
        return redirect(f"/admin/report/{acting_user_id}")
    return redirect(url_for("core.dashboard"))
