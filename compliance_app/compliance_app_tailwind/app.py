from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import sys
from pathlib import Path

# Ensure project root is on path when running directly
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import compliance_app.compliance_app_tailwind.db as db

app = Flask(__name__)
app.secret_key = "change_this_secret_key"

# Initialize database tables on startup (Flask 3 removed before_first_request)
db.create_tables_if_needed()

# Inject settings into all templates
@app.context_processor
def inject_app_settings():
    """Make app settings available to every template render."""
    settings = db.admin_get_app_settings()
    return {"app_settings": settings}


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
    """Render login form and handle authentication."""
    if request.method == "GET":
        user = current_user()
        if user is not None:
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        return render_template("login.html", page_name="templates/login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user_row = db.get_user_by_username(username)

    if user_row is None:
        error = "Invalid username or password"
        return render_template("login.html", error=error, username=username, page_name="templates/login.html")

    stored_pw = user_row["password"]
    authed = False
    if _is_hashed(stored_pw):
        authed = check_password_hash(stored_pw, password)
    else:
        authed = stored_pw == password
        if authed:
            # Upgrade plain text to hashed
            db.set_user_password(user_row["id"], generate_password_hash(password))

    if not authed:
        error = "Invalid username or password"
        return render_template("login.html", error=error, username=username, page_name="templates/login.html")

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


# Task dashboard: users see their tasks, admins see aggregate task stats
@app.route("/dashboard")
@login_required
def dashboard():
    """Show dashboards tailored to admins, company admins, or individual users."""
    user = current_user()
    if user["role"] == "admin":
        selected_company_id = None
        company_arg = request.args.get("company_id")
        if company_arg is not None:
            company_arg = company_arg.strip()
            if company_arg == "all" or company_arg == "":
                selected_company_id = None
                session.pop("selected_company_id", None)
            else:
                try:
                    selected_company_id = int(company_arg)
                    session["selected_company_id"] = selected_company_id
                except ValueError:
                    selected_company_id = None
        else:
            selected_company_id = session.get("selected_company_id")

        summary = db.admin_get_summary_counts(selected_company_id)
        severity_counts = db.admin_task_counts_by("severity", selected_company_id)
        impact_counts = db.admin_task_counts_by("impact", selected_company_id)
        # Task compliance based on fully completed tasks across assignments
        task_compliance_percent = 0
        compliance = db.admin_user_compliance(selected_company_id)
        pending_non_overdue = max(summary["total_pending"] - summary.get("total_overdue", 0), 0)
        user_metrics = {
            "total_users": len(compliance),
            "completed_users": sum(1 for r in compliance if (r["pending_tasks"] or 0) == 0),
            "pending_users": sum(1 for r in compliance if (r["pending_tasks"] or 0) > 0),
            "overdue_users": sum(1 for r in compliance if (r["overdue_tasks"] or 0) > 0),
            "compliance_pct": 0,
        }
        user_metrics["compliance_pct"] = round((user_metrics["completed_users"] / user_metrics["total_users"]) * 100, 1) if user_metrics["total_users"] else 0
        settings_row = db.admin_get_app_settings()
        settings = dict(settings_row) if settings_row else {}
        def _parse_color_map(val):
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
            colors = []
            for idx, label in enumerate(labels):
                colors.append(stored_map.get(label, fallback[idx % len(fallback)]))
            return colors

        severity_map = _parse_color_map(settings.get("severity_palette"))
        impact_map = _parse_color_map(settings.get("impact_palette"))
        completion_map = _parse_color_map(settings.get("completion_palette"))

        default_palette = ['#2563eb','#16a34a','#f59e0b','#ef4444','#8b5cf6','#0ea5e9']
        severity_palette = _palette_for_labels([c["label"] for c in severity_counts], default_palette, severity_map)
        impact_palette = _palette_for_labels([c["label"] for c in impact_counts], default_palette, impact_map)
        completion_labels = ["Completed", "Pending", "Overdue"]
        completion_defaults = ['#16a34a', '#f59e0b', '#ef4444']
        completion_palette = _palette_for_labels(completion_labels, completion_defaults, completion_map)
        tasks = db.admin_get_all_tasks(selected_company_id)
        # Task metrics: base totals on unique tasks, overlay completion from assignments
        rollup = db.admin_task_completion_rollup(selected_company_id)
        tasks_json = []
        for t in tasks:
            base = {k: t[k] for k in t.keys()}
            comp = rollup.get(t["id"], {"completed": 0, "total": 0})
            base["assign_completed"] = comp.get("completed", 0)
            base["assign_total"] = comp.get("total", 0)
            base["fully_completed"] = base["assign_total"] > 0 and base["assign_completed"] == base["assign_total"]
            base["completion_pct"] = round((base["assign_completed"] / base["assign_total"]) * 100, 1) if base["assign_total"] else 0
            tasks_json.append(base)
        task_total = len(tasks_json)
        task_overdue = sum(1 for t in tasks_json if t.get("overdue"))
        task_completed = sum(1 for t in tasks_json if t.get("fully_completed"))
        task_pending = task_total - task_completed
        # Compliance based on fully completed tasks
        task_compliance_percent = round((task_completed / task_total) * 100, 1) if task_total else 0
        # Build a simple severity x impact matrix for a risk view
        def build_risk_matrix(task_list):
            severities = []
            impacts = []
            for t in task_list:
                sev = t.get("severity") or "Unspecified"
                imp = t.get("impact") or "Unspecified"
                if sev not in severities:
                    severities.append(sev)
                if imp not in impacts:
                    impacts.append(imp)
            severities_sorted = sorted(severities)
            impacts_sorted = sorted(impacts)
            counts = {sev: {imp: 0 for imp in impacts_sorted} for sev in severities_sorted}
            for t in task_list:
                sev = t.get("severity") or "Unspecified"
                imp = t.get("impact") or "Unspecified"
                counts.setdefault(sev, {imp_key:0 for imp_key in impacts_sorted})
                counts[sev].setdefault(imp, 0)
                counts[sev][imp] += 1
            return {
                "severity_labels": severities_sorted,
                "impact_labels": impacts_sorted,
                "counts": counts,
            }
        risk_matrix = build_risk_matrix(tasks_json)
        task_counts = {
            "total": task_total,
            "completed": task_completed,
            "pending": task_pending,
            "overdue": task_overdue,
        }
        return render_template(
            "admin_task_dashboard.html",
            summary=summary,
            severity_counts=severity_counts,
            impact_counts=impact_counts,
            compliance_percent=task_compliance_percent,
            compliance=compliance,
            pending_non_overdue=pending_non_overdue,
            severity_palette=severity_palette,
            impact_palette=impact_palette,
            completion_palette=completion_palette,
            companies=db.admin_get_companies(),
            selected_company_id=selected_company_id,
            is_company_admin=False,
            user_metrics=user_metrics,
            user=user,
            tasks=tasks_json,
            task_counts=task_counts,
            risk_matrix=risk_matrix,
            page_name="templates/admin_task_dashboard.html",
        )
    if user["role"] == "company_admin" and request.args.get("view") != "personal":
        selected_company_id = user.get("company_id")
        summary = db.admin_get_summary_counts(selected_company_id)
        severity_counts = db.admin_task_counts_by("severity", selected_company_id)
        impact_counts = db.admin_task_counts_by("impact", selected_company_id)
        task_compliance_percent = 0
        compliance = db.admin_user_compliance(selected_company_id)
        pending_non_overdue = max(summary["total_pending"] - summary.get("total_overdue", 0), 0)
        user_metrics = {
            "total_users": len(compliance),
            "completed_users": sum(1 for r in compliance if (r["pending_tasks"] or 0) == 0),
            "pending_users": sum(1 for r in compliance if (r["pending_tasks"] or 0) > 0),
            "overdue_users": sum(1 for r in compliance if (r["overdue_tasks"] or 0) > 0),
            "compliance_pct": 0,
        }
        user_metrics["compliance_pct"] = round((user_metrics["completed_users"] / user_metrics["total_users"]) * 100, 1) if user_metrics["total_users"] else 0
        settings_row = db.admin_get_app_settings()
        settings = dict(settings_row) if settings_row else {}
        def _parse_color_map(val):
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
            colors = []
            for idx, label in enumerate(labels):
                colors.append(stored_map.get(label, fallback[idx % len(fallback)]))
            return colors

        severity_map = _parse_color_map(settings.get("severity_palette"))
        impact_map = _parse_color_map(settings.get("impact_palette"))
        completion_map = _parse_color_map(settings.get("completion_palette"))

        default_palette = ['#2563eb','#16a34a','#f59e0b','#ef4444','#8b5cf6','#0ea5e9']
        severity_palette = _palette_for_labels([c["label"] for c in severity_counts], default_palette, severity_map)
        impact_palette = _palette_for_labels([c["label"] for c in impact_counts], default_palette, impact_map)
        completion_labels = ["Completed", "Pending", "Overdue"]
        completion_defaults = ['#16a34a', '#f59e0b', '#ef4444']
        completion_palette = _palette_for_labels(completion_labels, completion_defaults, completion_map)
        tasks = db.admin_get_all_tasks(selected_company_id)
        # Task metrics: base totals on unique tasks, overlay completion from assignments
        rollup = db.admin_task_completion_rollup(selected_company_id)
        tasks_json = []
        for t in tasks:
            base = {k: t[k] for k in t.keys()}
            comp = rollup.get(t["id"], {"completed": 0, "total": 0})
            base["assign_completed"] = comp.get("completed", 0)
            base["assign_total"] = comp.get("total", 0)
            base["fully_completed"] = base["assign_total"] > 0 and base["assign_completed"] == base["assign_total"]
            base["completion_pct"] = round((base["assign_completed"] / base["assign_total"]) * 100, 1) if base["assign_total"] else 0
            tasks_json.append(base)
        task_total = len(tasks_json)
        task_overdue = sum(1 for t in tasks_json if t.get("overdue"))
        task_completed = sum(1 for t in tasks_json if t.get("fully_completed"))
        task_pending = task_total - task_completed
        task_compliance_percent = round((task_completed / task_total) * 100, 1) if task_total else 0
        def build_risk_matrix(task_list):
            severities = []
            impacts = []
            for t in task_list:
                sev = t.get("severity") or "Unspecified"
                imp = t.get("impact") or "Unspecified"
                if sev not in severities:
                    severities.append(sev)
                if imp not in impacts:
                    impacts.append(imp)
            severities_sorted = sorted(severities)
            impacts_sorted = sorted(impacts)
            counts = {sev: {imp: 0 for imp in impacts_sorted} for sev in severities_sorted}
            for t in task_list:
                sev = t.get("severity") or "Unspecified"
                imp = t.get("impact") or "Unspecified"
                counts.setdefault(sev, {imp_key:0 for imp_key in impacts_sorted})
                counts[sev].setdefault(imp, 0)
                counts[sev][imp] += 1
            return {
                "severity_labels": severities_sorted,
                "impact_labels": impacts_sorted,
                "counts": counts,
            }
        risk_matrix = build_risk_matrix(tasks_json)
        task_counts = {
            "total": task_total,
            "completed": task_completed,
            "pending": task_pending,
            "overdue": task_overdue,
        }
        return render_template(
            "admin_task_dashboard.html",
            summary=summary,
            severity_counts=severity_counts,
            impact_counts=impact_counts,
            compliance_percent=task_compliance_percent,
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
            risk_matrix=risk_matrix,
            page_name="templates/admin_task_dashboard.html",
        )

    # Default: personal task view (users and company admins in personal mode)
    # Fetch full profile for name display
    profile_row = db.admin_get_user(user["id"], user.get("company_id"))
    user_full = {**user}
    if profile_row:
        user_full["first_name"] = profile_row["first_name"]
        user_full["last_name"] = profile_row["last_name"]

    tasks = db.get_tasks_for_user(user["id"])
    pending = [t for t in tasks if t["status"] != "completed"]
    completed = [t for t in tasks if t["status"] == "completed"]
    today = date.today()
    pending_display = []
    completed_display = []
    for t in pending:
        due_str = t["due_date"]
        due_obj = None
        overdue = False
        due_display = None
        if due_str:
            try:
                due_obj = datetime.strptime(due_str, "%Y-%m-%d").date()
                overdue = due_obj < today
                due_display = due_obj.strftime("%d/%m/%Y")
            except ValueError:
                due_display = due_str
        pending_display.append({**t, "overdue": overdue, "due_display": due_display})
    for t in completed:
        completed_at_display = None
        completed_raw = t["completed_at"]
        if completed_raw:
            try:
                completed_dt = datetime.fromisoformat(completed_raw)
                completed_at_display = completed_dt.strftime("%d/%m/%Y")
            except ValueError:
                completed_at_display = completed_raw
        completed_display.append({**t, "completed_on": completed_at_display})
    total_tasks = len(tasks)
    completed_count = len(completed)
    pending_count = len(pending)
    pending_overdue = sum(1 for t in pending_display if t["overdue"])
    pending_non_overdue = max(pending_count - pending_overdue, 0)
    compliance_percent = round((completed_count / total_tasks) * 100, 1) if total_tasks else 0

    # Pie chart data for this user
    def _tally(values):
        counts = {}
        for val in values:
            key = val if val else "Unspecified"
            counts[key] = counts.get(key, 0) + 1
        labels = list(counts.keys())
        data = [counts[k] for k in labels]
        return labels, data

    severity_labels, severity_data = _tally([t["severity"] if "severity" in t.keys() else None for t in tasks])
    impact_labels, impact_data = _tally([t["impact"] if "impact" in t.keys() else None for t in tasks])
    completion_data = [completed_count, pending_non_overdue, pending_overdue]

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
        is_company_admin=user["role"] == "company_admin",
        page_name="templates/dashboard.html",
    )


# Individual task view and answer submission
@app.route("/task/<int:task_id>", methods=["GET", "POST"])
@login_required
def task_detail(task_id):
    """Display a single task and accept an answer submission."""
    user = current_user()
    t = db.get_task_for_user(user["id"], task_id)
    if t is None:
        return "Not found", 404

    if request.method == "GET":
        completed_at_display = None
        due_date_display = None
        if t["due_date"]:
            try:
                due_dt = datetime.strptime(t["due_date"], "%Y-%m-%d")
                due_date_display = due_dt.strftime("%d/%m/%Y")
            except ValueError:
                due_date_display = t["due_date"]
        if t["completed_at"]:
            try:
                completed_dt = datetime.fromisoformat(t["completed_at"])
                completed_at_display = completed_dt.strftime("%d/%m/%Y %H:%M")
            except ValueError:
                completed_at_display = t["completed_at"]
        return render_template(
            "task_detail.html",
            task=t,
            completed_at_display=completed_at_display,
            due_date_display=due_date_display,
            is_completed=t["status"] == "completed",
            page_name="templates/task_detail.html",
        )

    user_answer = request.form.get("answer", "").strip()
    expected = t["verification_answer"].strip()
    correct = user_answer.lower() == expected.lower()

    db.mark_task_result(user["id"], task_id, user_answer, correct)

    flash("Correct! Task completed." if correct else "Incorrect answer.")
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


@app.route("/dashboard/users")
@login_required
def user_dashboard():
    """User-focused dashboard showing user metrics and completion status."""
    user = current_user()
    if user["role"] not in ("admin", "company_admin"):
        return "Access denied", 403

    # Company selection
    if user["role"] == "admin":
        selected_company_id = None
        company_arg = request.args.get("company_id")
        if company_arg is not None:
            company_arg = company_arg.strip()
            if company_arg == "all" or company_arg == "":
                selected_company_id = None
                session.pop("selected_company_id", None)
            else:
                try:
                    selected_company_id = int(company_arg)
                    session["selected_company_id"] = selected_company_id
                except ValueError:
                    selected_company_id = None
        else:
            selected_company_id = session.get("selected_company_id")
    else:
        selected_company_id = user.get("company_id")

    summary = db.admin_get_summary_counts(selected_company_id)
    compliance = db.admin_user_compliance(selected_company_id)
    pending_non_overdue = max(summary["total_pending"] - summary.get("total_overdue", 0), 0)
    user_metrics = {
        "total_users": len(compliance),
        "completed_users": sum(1 for r in compliance if (r["pending_tasks"] or 0) == 0),
        "pending_users": sum(1 for r in compliance if (r["pending_tasks"] or 0) > 0),
        "overdue_users": sum(1 for r in compliance if (r["overdue_tasks"] or 0) > 0),
    }
    user_metrics["compliance_pct"] = round((user_metrics["completed_users"] / user_metrics["total_users"]) * 100, 1) if user_metrics["total_users"] else 0

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
@app.route("/admin/tasks", methods=["GET", "POST"])
@admin_required
def admin_tasks():
    """List tasks and handle creation in the admin view."""
    if request.method == "GET":
        admin = current_user()
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

        tasks = db.admin_get_all_tasks(selected_company_id)
        impacts = db.admin_get_options("impact", admin["company_id"])
        severities = db.admin_get_options("severity", admin["company_id"])
        users = db.admin_get_all_users(selected_company_id)
        descriptions = db.admin_get_task_field_descriptions()
        companies = db.admin_get_companies()
        company_lookup = {c["id"]: c["name"] for c in companies}
        return render_template("admin_tasks.html", tasks=tasks, impacts=impacts, severities=severities, users=users, descriptions=descriptions, companies=companies, company_lookup=company_lookup, selected_company_id=selected_company_id, page_name="templates/admin_tasks.html")

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
    admin = current_user()
    descriptions = db.admin_get_task_field_descriptions()
    # Users limited to company scope if specified
    users_for_company = db.admin_get_all_users(company_id) if company_id else db.admin_get_all_users()

    # Validate required fields based on admin configuration
    def _is_required(field):
        meta = descriptions.get(field, {})
        return meta.get("required", False)

    missing = []
    if _is_required("title") and not title:
        missing.append("Title")
    if _is_required("description") and not description:
        missing.append("Description")
    if _is_required("due_date") and not due_date:
        missing.append("Due date")
    if _is_required("impact") and not impact:
        missing.append("Impact")
    if _is_required("severity") and not severity:
        missing.append("Severity")
    if _is_required("verification_question") and not question:
        missing.append("Verification question")
    if _is_required("verification_answer") and not answer:
        missing.append("Verification answer")
    if _is_required("assignment") and not (assign_all or selected_user_ids):
        missing.append("Assignment (select users or assign all)")

    if missing:
        users_filtered = db.admin_get_all_users(company_id)
        return render_template(
            "admin_tasks.html",
            error="Please fill required fields: " + ", ".join(missing),
            tasks=db.admin_get_all_tasks(admin["company_id"]),
            impacts=db.admin_get_options("impact", admin["company_id"]),
            severities=db.admin_get_options("severity", admin["company_id"]),
            users=users_filtered,
            descriptions=descriptions,
            companies=db.admin_get_companies(),
            company_lookup={c["id"]: c["name"] for c in db.admin_get_companies()},
            selected_company_id=company_id,
            page_name="templates/admin_tasks.html",
        )

    db.admin_create_task(title, description, due_date, impact, severity, owner_id, question, answer, company_id, selected_user_ids, assign_all)
    flash("Task created.")
    return redirect(url_for("admin_tasks"))

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

    if request.method == "GET":
        return render_template(
            "admin_task_edit.html",
            task=task,
            impacts=db.admin_get_options("impact", admin["company_id"]),
            severities=db.admin_get_options("severity", admin["company_id"]),
            users=db.admin_get_all_users(),
            companies=db.admin_get_companies(),
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

    if not title or not question or not answer:
        return render_template(
            "admin_task_edit.html",
            task=task,
            impacts=db.admin_get_options("impact", admin["company_id"]),
            severities=db.admin_get_options("severity", admin["company_id"]),
            users=db.admin_get_all_users(),
            companies=db.admin_get_companies(),
            error="Title, question and answer required.",
            page_name="templates/admin_task_edit.html",
        )

    db.admin_update_task(task_id, title, description, due_date, impact, severity, owner_id, question, answer, company_id)
    flash("Task updated.")
    return redirect(url_for("admin_tasks"))


# Admin: user list and selection
@app.route("/admin/users")
@admin_required
def admin_users():
    """List users and show a selected user's details for admins."""
    admin = current_user()
    selected_id = request.args.get("user_id", type=int)
    selected_user = db.admin_get_user(selected_id) if selected_id else None
    users = db.admin_get_all_users()
    companies = db.admin_get_companies()
    company_lookup = {c["id"]: c["name"] for c in companies}
    return render_template("admin_users.html", users=users, selected_user=selected_user, companies=companies, company_lookup=company_lookup, allow_admin_role=True, is_company_admin=False, page_name="templates/admin_users.html")


# Admin: create or update a user
@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    """Create or update a user from the admin form submission."""
    admin = current_user()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "user")
    first_name = request.form.get("first_name", "").strip() or None
    last_name = request.form.get("last_name", "").strip() or None
    email = request.form.get("email", "").strip() or None
    mobile = request.form.get("mobile", "").strip() or None
    send_notifications = request.form.get("send_notifications") == "on"
    is_active = request.form.get("is_active") == "on"
    user_id = request.form.get("user_id", type=int)
    company_id = request.form.get("company_id", type=int) or admin["company_id"]

    hashed_pw = generate_password_hash(password) if password else None

    if not username or (not user_id and not password):
        return render_template(
            "admin_users.html",
            users=db.admin_get_all_users(),
            error="Username and password are required.",
            selected_user=db.admin_get_user(user_id) if user_id else None,
            companies=db.admin_get_companies(),
            company_lookup={c["id"]: c["name"] for c in db.admin_get_companies()},
            page_name="templates/admin_users.html",
        )

    if user_id:
        error = db.admin_update_user(user_id, username, hashed_pw, role, first_name, last_name, email, mobile, send_notifications, company_id, is_active)
    else:
        error = db.admin_create_user(username, hashed_pw, role, first_name, last_name, email, mobile, send_notifications, company_id, is_active)

    if error:
        return render_template(
            "admin_users.html",
            users=db.admin_get_all_users(),
            selected_user=db.admin_get_user(user_id) if user_id else None,
            error=error,
            companies=db.admin_get_companies(),
            company_lookup={c["id"]: c["name"] for c in db.admin_get_companies()},
            page_name="templates/admin_users.html",
        )

    flash("User updated." if user_id else "User created.")
    return redirect(url_for("admin_users"))


# Company admin: manage users for their company
@app.route("/company-admin/users", methods=["GET", "POST"])
@company_admin_required
def company_admin_users():
    """Company admins manage users within their own company."""
    admin = current_user()
    company_id = admin["company_id"]
    selected_id = request.args.get("user_id", type=int)

    if request.method == "GET":
        selected_user = db.admin_get_user(selected_id, company_id) if selected_id else None
        users = db.admin_get_all_users(company_id)
        company_row = db.admin_get_company(company_id)
        companies = [company_row] if company_row else []
        company_lookup = {company_row["id"]: company_row["name"]} if company_row else {}
        return render_template("admin_users.html", users=users, selected_user=selected_user, companies=companies, company_lookup=company_lookup, allow_admin_role=False, is_company_admin=True, page_name="templates/company_admin_users.html")

    # POST create/update
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "user")
    # Force role to allowed set
    if role not in ("user", "company_admin"):
        role = "user"
    first_name = request.form.get("first_name", "").strip() or None
    last_name = request.form.get("last_name", "").strip() or None
    email = request.form.get("email", "").strip() or None
    mobile = request.form.get("mobile", "").strip() or None
    send_notifications = request.form.get("send_notifications") == "on"
    user_id = request.form.get("user_id", type=int)
    company_id = admin["company_id"]

    hashed_pw = generate_password_hash(password) if password else None

    if not username or (not user_id and not password):
        users = db.admin_get_all_users(company_id)
        return render_template(
            "admin_users.html",
            users=users,
            error="Username and password are required.",
            selected_user=db.admin_get_user(user_id, company_id) if user_id else None,
            companies=[db.admin_get_company(company_id)] if company_id else [],
            company_lookup={company_id: db.admin_get_company(company_id)["name"]} if company_id else {},
            allow_admin_role=False,
            is_company_admin=True,
            page_name="templates/company_admin_users.html",
        )

    if user_id:
        # Ensure target user is in same company
        target = db.admin_get_user(user_id)
        if target and target["company_id"] != company_id:
            return "Forbidden", 403
        error = db.admin_update_user(user_id, username, hashed_pw, role, first_name, last_name, email, mobile, send_notifications, company_id)
    else:
        error = db.admin_create_user(username, hashed_pw, role, first_name, last_name, email, mobile, send_notifications, company_id)

    if error:
        users = db.admin_get_all_users(company_id)
        return render_template(
            "admin_users.html",
            users=users,
            selected_user=db.admin_get_user(user_id, company_id) if user_id else None,
            error=error,
            companies=[db.admin_get_company(company_id)] if company_id else [],
            company_lookup={company_id: db.admin_get_company(company_id)["name"]} if company_id else {},
            allow_admin_role=False,
            is_company_admin=True,
            page_name="templates/company_admin_users.html",
        )

    flash("User updated." if user_id else "User created.")
    return redirect(url_for("company_admin_users"))


# Admin: manage companies
@app.route("/admin/companies", methods=["GET", "POST"])
@admin_required
def admin_companies():
    """Create or update companies and assign company admins."""
    admin = current_user()
    selected_id = request.args.get("company_id", type=int)
    selected_company = db.admin_get_company(selected_id) if selected_id else None

    if request.method == "POST":
        company_id = request.form.get("company_id", type=int)
        name = request.form.get("name", "").strip()
        admin_user_id = request.form.get("admin_user_id", type=int)
        address1 = request.form.get("address1", "").strip() or None
        address2 = request.form.get("address2", "").strip() or None
        address3 = request.form.get("address3", "").strip() or None
        state = request.form.get("state", "").strip() or None
        postcode = request.form.get("postcode", "").strip() or None
        is_active = request.form.get("is_active") == "on"
        if not name:
            error = "Company name is required."
            companies = db.admin_get_companies()
            users_for_company = db.admin_get_all_users(company_id) if company_id else []
            return render_template("admin_companies.html", companies=companies, selected_company=selected_company, company_users=users_for_company, error=error, page_name="templates/admin_companies.html")
        # Validate admin user belongs to company (when updating existing)
        if admin_user_id and company_id:
            user_row = db.admin_get_user(admin_user_id)
            if not user_row or ("company_id" in user_row.keys() and user_row["company_id"] != company_id):
                error = "Selected company admin must belong to this company."
                companies = db.admin_get_companies()
                users_for_company = db.admin_get_all_users(company_id) if company_id else []
                return render_template("admin_companies.html", companies=companies, selected_company=selected_company, company_users=users_for_company, error=error, page_name="templates/admin_companies.html")
        if company_id:
            error = db.admin_update_company(company_id, name, admin_user_id, address1, address2, address3, state, postcode, is_active)
            flash_msg = "Company updated."
        else:
            error = db.admin_create_company(name, address1, address2, address3, state, postcode, admin_user_id, is_active)
            flash_msg = "Company created."
        if error:
            companies = db.admin_get_companies()
            users_for_company = db.admin_get_all_users(company_id) if company_id else []
            return render_template("admin_companies.html", companies=companies, selected_company=selected_company, company_users=users_for_company, error=error, page_name="templates/admin_companies.html")
        flash(flash_msg)
        return redirect(url_for("admin_companies"))

    companies = db.admin_get_companies()
    company_users = db.admin_get_all_users(selected_id) if selected_id else []
    return render_template("admin_companies.html", companies=companies, selected_company=selected_company, company_users=company_users, page_name="templates/admin_companies.html")


# Admin: add an option (impact/severity)
@app.route("/admin/options/<opt_type>/add", methods=["POST"])
@admin_required
def admin_add_option(opt_type):
    """Add a new impact or severity option."""
    if opt_type not in ("impact", "severity"):
        return "Invalid option type", 400
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


# Admin: delete an option (impact/severity)
@app.route("/admin/options/<opt_type>/<int:option_id>/delete", methods=["POST"])
@admin_required
def admin_delete_option(opt_type, option_id):
    """Remove an impact or severity option."""
    if opt_type not in ("impact", "severity"):
        return "Invalid option type", 400
    admin = current_user()
    db.admin_delete_option(opt_type, option_id, admin["company_id"])
    flash("Option removed.")
    return redirect(url_for("admin_tasks"))


@app.route("/admin/options/<opt_type>/<int:option_id>/color", methods=["POST"])
@admin_required
def admin_update_option_color(opt_type, option_id):
    """Update the stored colour for an option label."""
    if opt_type not in ("impact", "severity"):
        return "Invalid option type", 400
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
    db.admin_update_app_settings(version, show_version, show_page_name, show_module_tree, show_cut_icon)
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
@app.route("/admin/notify/overdue")
@admin_required
def admin_notify_overdue():
    """Simulate sending overdue notifications to opted-in users (prints to console)."""
    # Print a simple notice for users who opted in and have overdue tasks
    admin = current_user()
    today = date.today()
    sent = 0
    users = db.admin_get_all_users(admin["company_id"])
    for u in users:
        if not u["send_notifications"]:
            continue
        tasks = db.get_tasks_for_user(u["id"])
        overdue = []
        for t in tasks:
            if t["status"] == "completed":
                continue
            due_str = t["due_date"]
            if not due_str:
                continue
            try:
                due_obj = datetime.strptime(due_str, "%Y-%m-%d").date()
                if due_obj < today:
                    overdue.append(t["title"])
            except ValueError:
                continue
        if overdue:
            sent += 1
            print(f"[Notification] To {u['username']} ({u['email'] or 'no email'}): overdue tasks -> {', '.join(overdue)}")
    flash(f"Notifications sent to {sent} users (printed to console).")
    return redirect(url_for("admin_dashboard"))


# Admin: user report page
@app.route("/admin/report/<int:user_id>")
@admin_required
def admin_report(user_id):
    """Render a per-user compliance report for admins."""
    admin = current_user()
    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return "User not found", 404
    if admin.get("company_id") is not None and user_row["company_id"] != admin["company_id"]:
        return "Not found", 404
    formatted_tasks = []
    for t in tasks:
        due_display = t["due_date"]
        if t["due_date"]:
            try:
                due_dt = datetime.strptime(t["due_date"], "%Y-%m-%d")
                due_display = due_dt.strftime("%d/%m/%Y")
            except ValueError:
                due_display = t["due_date"]
        completed_display = t["completed_at"]
        if t["completed_at"]:
            try:
                comp_dt = datetime.fromisoformat(t["completed_at"])
                completed_display = comp_dt.strftime("%d/%m/%Y")
            except ValueError:
                completed_display = t["completed_at"]
        formatted_tasks.append({**t, "due_display": due_display, "completed_display": completed_display})
    return render_template("admin_report.html", user=user_row, tasks=formatted_tasks, page_name="templates/admin_report.html")


# Admin: export user report CSV
@app.route("/admin/report/<int:user_id>/csv")
@admin_required
def admin_report_csv(user_id):
    """Stream a CSV export of a user's task report."""
    # Build a CSV stream for a single user's tasks
    admin = current_user()
    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return "User not found", 404
    if admin.get("company_id") is not None and user_row["company_id"] != admin["company_id"]:
        return "Not found", 404
    def generate():
        yield "Title,Due Date,Status,Completed At,Answer\\n"
        for t in tasks:
            title = (t["title"] or "").replace('"', '""')
            due = t["due_date"] or ""
            status = t["status"] or ""
            completed_at = t["completed_at"] or ""
            answer = (t["answer_text"] or "").replace('"', '""')
            yield f"\"{title}\",{due},{status},{completed_at},\"{answer}\"\\n"
    return Response(generate(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=report_{user_id}.csv"})


# Company admin: user report page
@app.route("/company-admin/report/<int:user_id>")
@company_admin_required
def company_admin_report(user_id):
    """Company admin view of a user's report within their company."""
    admin = current_user()
    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return "User not found", 404
    if user_row["company_id"] != admin["company_id"]:
        return "Not found", 404
    formatted_tasks = []
    for t in tasks:
        due_display = t["due_date"]
        if t["due_date"]:
            try:
                due_dt = datetime.strptime(t["due_date"], "%Y-%m-%d")
                due_display = due_dt.strftime("%d/%m/%Y")
            except ValueError:
                due_display = t["due_date"]
        completed_display = t["completed_at"]
        if t["completed_at"]:
            try:
                comp_dt = datetime.fromisoformat(t["completed_at"])
                completed_display = comp_dt.strftime("%d/%m/%Y")
            except ValueError:
                completed_display = t["completed_at"]
        formatted_tasks.append({**t, "due_display": due_display, "completed_display": completed_display})
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
    elif role == "company_admin":
        companies = [c for c in db.admin_get_companies() if c["id"] == viewer.get("company_id")]
        allow_company_change = False
        locked_company_id = viewer.get("company_id")
    else:
        companies = [c for c in db.admin_get_companies() if c["id"] == viewer.get("company_id")]
        allow_company_change = False
        locked_company_id = viewer.get("company_id")
    if request.method == "GET":
        return render_template(
            "admin_profile.html",
            user=user,
            companies=companies,
            is_company_admin=role == "company_admin",
            allow_company_change=allow_company_change,
            page_name="templates/admin_profile.html",
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    first_name = request.form.get("first_name", "").strip() or None
    last_name = request.form.get("last_name", "").strip() or None
    email = request.form.get("email", "").strip() or None
    mobile = request.form.get("mobile", "").strip() or None
    send_notifications = request.form.get("send_notifications") == "on"
    is_active = request.form.get("is_active") == "on"
    req_company_id = request.form.get("company_id", type=int)
    company_id = req_company_id if (req_company_id and allow_company_change) else (locked_company_id or user["company_id"])

    hashed_pw = generate_password_hash(password) if password else None

    if not username:
        return render_template(
            "admin_profile.html",
            user=user,
            companies=companies,
            is_company_admin=role == "company_admin",
            allow_company_change=allow_company_change,
            error="Username is required.",
            page_name="templates/admin_profile.html",
        )

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
            "admin_profile.html",
            user=user,
            companies=companies,
            is_company_admin=role == "company_admin",
            allow_company_change=allow_company_change,
            error=err,
            page_name="templates/admin_profile.html",
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
