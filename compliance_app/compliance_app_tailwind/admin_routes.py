"""Admin and company-admin routes blueprint."""

from datetime import date, datetime

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash

from compliance_app.compliance_app_tailwind import db, risk_utils
from compliance_app.compliance_app_tailwind.auth_helpers import admin_required, company_admin_required, current_user
from compliance_app.compliance_app_tailwind.core_utils import (
    format_completed_on,
    format_due_and_overdue,
    normalize_task_for_dashboard,
    palette_for_labels,
    parse_color_map,
    tally,
)

DATE_FMT = "%d/%m/%Y"
INVALID_OPTION_TYPE = "Invalid option type"
USER_NOT_FOUND = "User not found"
NOT_FOUND = "Not found"

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


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


def _collect_company_form_data():
    """Extract and normalize company form fields from request."""
    return {
        "company_id": request.form.get("company_id", type=int),
        "name": request.form.get("name", "").strip(),
        "admin_user_id": request.form.get("company_admin_id", type=int) or request.form.get("admin_user_id", type=int),
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
    return render_template(
        "admin_companies.html",
        companies=companies,
        selected_company=selected_company,
        company_users=users_for_company,
        active_user_counts=active_user_counts,
        total_user_counts=total_user_counts,
        error=error_msg,
        page_name="templates/admin_companies.html",
    )


def _validate_company_admin_belongs(admin_user_id, company_id):
    """Return an error message if the selected admin user does not belong to the company, otherwise None."""
    if not admin_user_id or not company_id:
        return None
    user_row = db.admin_get_user(admin_user_id)
    if not user_row or ("company_id" in user_row.keys() and user_row["company_id"] != company_id):
        return "Selected company admin must belong to this company."
    return None


def _admin_get_metric_mode(req):
    mode = req.args.get("metric_mode")
    if mode not in ("task", "user"):
        return "task"
    return mode


def _admin_get_selected_company_id(req):
    company_arg = req.args.get("company_id")
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


def _admin_build_palettes_from_settings(settings_row, severity_counts, impact_counts):
    settings_local = dict(settings_row) if settings_row else {}
    sev_map = parse_color_map(settings_local.get("severity_palette"))
    imp_map = parse_color_map(settings_local.get("impact_palette"))
    comp_map = parse_color_map(settings_local.get("completion_palette"))
    default_palette = ["#2563eb", "#16a34a", "#f59e0b", "#ef4444", "#8b5cf6", "#0ea5e9"]
    severity_palette = palette_for_labels([c["label"] for c in severity_counts], default_palette, sev_map)
    impact_palette = palette_for_labels([c["label"] for c in impact_counts], default_palette, imp_map)
    completion_labels = ["Completed", "Pending", "Overdue"]
    completion_defaults = ["#16a34a", "#f59e0b", "#ef4444"]
    completion_palette = palette_for_labels(completion_labels, completion_defaults, comp_map)
    return severity_palette, impact_palette, completion_palette


def _parse_selected_company(arg):
    """Normalize company_id query argument into an int or None."""
    if arg == "all" or arg == "":
        return None
    if not arg:
        return None
    try:
        return int(arg)
    except ValueError:
        return None


def _parse_create_company_id(arg):
    """Handle persisted create-company filter stored in session; return int or None."""
    stored = session.get("task_create_company_filter")
    if arg == "all" or arg == "":
        session.pop("task_create_company_filter", None)
        return None
    if arg:
        try:
            val = int(arg)
            session["task_create_company_filter"] = val
            return val
        except ValueError:
            return stored
    return stored


def _build_tasks_list(rows):
    """Convert raw task rows to a list with due_display populated."""
    out = []
    for t in rows:
        due_display = None
        due_raw = t["due_date"] if "due_date" in t.keys() else None
        if due_raw:
            try:
                due_dt = datetime.strptime(due_raw, "%Y-%m-%d")
                due_display = due_dt.strftime("%d/%m/%Y")
            except ValueError:
                due_display = due_raw
        out.append({**dict(t), "due_display": due_display})
    return out


def _resolve_edit_task_context(param, current_create_company, admin):
    """Resolve edit task, assignments and users scope for the tasks page."""
    edit = None
    assigned = set()
    assign_status = {}
    users_scope = db.admin_get_all_users(current_create_company)
    if not param:
        return edit, assigned, assign_status, users_scope, current_create_company
    try:
        tid = int(param)
    except ValueError:
        return edit, assigned, assign_status, users_scope, current_create_company

    scope = admin.get("company_id") if admin.get("role") == "company_admin" else None
    edit = db.admin_get_task(tid, scope)
    if edit:
        create_co = edit["company_id"] if "company_id" in edit.keys() else None
        assigned = db.admin_get_task_assignments(tid)
        assign_status = db.admin_get_task_assignment_status(tid)
        users_scope = db.admin_get_all_users(create_co)
        return edit, assigned, assign_status, users_scope, create_co
    return edit, assigned, assign_status, users_scope, current_create_company


def _admin_tasks_get_view(admin):
    """Render the basic task admin CRUD view."""
    task_id_param = request.args.get("task_id", "").strip()
    selected_company_id = _parse_selected_company(request.args.get("company_id", "").strip())
    create_company_id = _parse_create_company_id(request.args.get("create_company_id", "").strip())

    tasks_raw = db.admin_get_all_tasks(selected_company_id)
    tasks = _build_tasks_list(tasks_raw)
    impacts = db.admin_get_options("impact", admin["company_id"])
    severities = db.admin_get_options("severity", admin["company_id"])

    edit_task, assigned_ids, assignment_status, users, create_company_id = _resolve_edit_task_context(
        task_id_param, create_company_id, admin
    )

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
        edit_task=edit_task,
        assigned_ids=assigned_ids,
        assignment_status=assignment_status,
        create_company_id=create_company_id,
        page_name="templates/admin_tasks.html",
    )


def _admin_tasks_collect():
    edit_task_id = request.form.get("task_id")
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
    company_val = request.form.get("create_company_id", "").strip()
    company_id = int(company_val) if company_val else None
    return {
        "edit_task_id": edit_task_id,
        "title": title,
        "question": question,
        "answer": answer,
        "description": description,
        "due_date": due_date,
        "impact": impact,
        "severity": severity,
        "selected_user_ids": selected_user_ids,
        "assign_all": assign_all,
        "owner_id": owner_id,
        "company_id": company_id,
    }


def _admin_tasks_validate(payload, descriptions):
    def _is_required(field):
        meta = descriptions.get(field, {})
        return meta.get("required", False)

    field_checks = [
        ("title", payload["title"], "Title"),
        ("description", payload["description"], "Description"),
        ("due_date", payload["due_date"], "Due date"),
        ("impact", payload["impact"], "Impact"),
        ("severity", payload["severity"], "Severity"),
        ("verification_question", payload["question"], "Verification question"),
        ("verification_answer", payload["answer"], "Verification answer"),
    ]
    missing = [label for (field, value, label) in field_checks if _is_required(field) and not value]
    if _is_required("assignment") and not (payload["assign_all"] or payload["selected_user_ids"]):
        missing.append("Assignment (select users or assign all)")
    return missing


def _admin_tasks_render_missing(missing, payload, descriptions, admin):
    users_filtered = db.admin_get_all_users(payload["company_id"])
    companies = db.admin_get_companies()
    edit_task_ctx = None
    if payload.get("edit_task_id"):
        scope = admin.get("company_id") if admin.get("role") == "company_admin" else None
        try:
            edit_task_ctx = db.admin_get_task(int(payload["edit_task_id"]), scope)
        except (TypeError, ValueError):
            edit_task_ctx = None
    return render_template(
        "admin_tasks.html",
        error="Please fill required fields: " + ", ".join(missing),
        tasks=_build_tasks_list(db.admin_get_all_tasks(None)),
        impacts=db.admin_get_options("impact", admin["company_id"]),
        severities=db.admin_get_options("severity", admin["company_id"]),
        users=users_filtered,
        descriptions=descriptions,
        companies=companies,
        company_lookup={c["id"]: c["name"] for c in companies},
        selected_company_id=None,
        create_company_id=payload["company_id"],
        edit_task=edit_task_ctx,
        assigned_ids=db.admin_get_task_assignments(int(payload["edit_task_id"])) if payload.get("edit_task_id") else set(),
        assignment_status=db.admin_get_task_assignment_status(int(payload["edit_task_id"])) if payload.get("edit_task_id") else {},
        page_name="templates/admin_tasks.html",
    )


def _admin_tasks_handle_post(admin):
    """Handle create/update for the basic task admin form."""
    payload = _admin_tasks_collect()
    descriptions = db.admin_get_task_field_descriptions()
    missing = _admin_tasks_validate(payload, descriptions)
    if missing:
        return _admin_tasks_render_missing(missing, payload, descriptions, admin)

    if payload["edit_task_id"]:
        tid = int(payload["edit_task_id"])
        db.admin_update_task(
            tid,
            payload["title"],
            payload["description"],
            payload["due_date"],
            payload["impact"],
            payload["severity"],
            payload["owner_id"],
            payload["question"],
            payload["answer"],
            payload["company_id"],
        )
        db.admin_update_task_assignments(
            tid,
            payload["company_id"],
            payload["selected_user_ids"],
            payload["assign_all"] or payload["company_id"] is None,
        )
        flash("Task updated.")
    else:
        db.admin_create_task(
            payload["title"],
            payload["description"],
            payload["due_date"],
            payload["impact"],
            payload["severity"],
            payload["owner_id"],
            payload["question"],
            payload["answer"],
            payload["company_id"],
            payload["selected_user_ids"],
            payload["assign_all"],
        )
        flash("Task created.")

    return redirect(
        url_for(
            "admin.admin_tasks",
            company_id=request.args.get("company_id", "all"),
            create_company_id=payload["company_id"] or "all",
        )
    )


@admin_bp.route("/dashboard", endpoint="admin_dashboard")
@admin_required
def admin_dashboard():
    """Show counts of users and companies for administrators."""
    admin = current_user()
    users = db.admin_get_all_users_any(None)
    companies = db.admin_get_companies(show_inactive=True)
    total_users = sum(1 for u in users if u["role"] == "user")
    total_admins = sum(1 for u in users if u["role"] == "admin")
    total_company_admins = sum(1 for u in users if u["role"] == "company_admin")
    total_companies = len(companies)
    active_companies = sum(1 for c in companies if ("is_active" in c.keys() and c["is_active"]))
    task_summary = db.admin_get_summary_counts(None)
    task_total = task_summary.get("total_tasks", 0)
    task_completed = task_summary.get("total_completed", 0)
    task_pending = task_summary.get("total_pending", 0)
    task_overdue = task_summary.get("total_overdue", 0)
    task_compliance = round((task_completed / task_total) * 100, 1) if task_total else 0
    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=total_users,
        total_admins=total_admins,
        total_company_admins=total_company_admins,
        total_companies=total_companies,
        active_companies=active_companies,
        task_total=task_total,
        task_completed=task_completed,
        task_pending=task_pending,
        task_overdue=task_overdue,
        task_compliance=task_compliance,
        page_name="templates/admin_dashboard.html",
    )


@admin_bp.route("/tasks", methods=["GET", "POST"], endpoint="admin_tasks")
@admin_required
def admin_tasks():
    """List tasks and handle creation in the admin view (delegates to helpers to reduce complexity)."""
    admin = current_user()
    if request.method == "GET":
        return _admin_tasks_get_view(admin)
    return _admin_tasks_handle_post(admin)


@admin_bp.route("/tasks/<int:task_id>/edit", endpoint="admin_edit_task_redirect")
@admin_required
def admin_edit_task_redirect(task_id):
    return redirect(url_for("admin.admin_tasks", task_id=task_id))


@admin_bp.route("/task-config", endpoint="admin_task_config")
@admin_required
def admin_task_config():
    """Legacy task config page removed."""
    return abort(404)


@admin_bp.route("/task-config/fields", methods=["POST"], endpoint="admin_task_field_update")
@admin_required
def admin_task_field_update():
    """Legacy task field editor removed."""
    return abort(404)


@admin_bp.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"], endpoint="admin_edit_task")
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
    if company_id is None:
        assign_all = True
    user_ids = request.form.getlist("user_ids")

    if not title or not question or not answer:
        flash("Title, question, and answer are required.")
        return redirect(url_for("admin.admin_edit_task", task_id=task_id))

    db.admin_update_task(
        task_id,
        title,
        description,
        due_date,
        impact,
        severity,
        question,
        answer,
        owner_id,
        company_id,
        user_ids,
        assign_all,
    )

    flash("Task updated.")
    return redirect(url_for("admin.admin_tasks"))


@admin_bp.route("/users", endpoint="admin_users")
@admin_required
def admin_users():
    """Render admin user management page."""
    admin = current_user()
    companies = db.admin_get_companies(show_inactive=True)
    raw_users = db.admin_get_all_users_any(None)
    users = [dict(u) for u in raw_users]
    active_users = [u for u in users if u.get("is_active")]
    inactive_users = [u for u in users if not u.get("is_active")]
    return render_template(
        "admin_users.html",
        users=users,
        companies=companies,
        active_users=active_users,
        inactive_users=inactive_users,
        page_name="templates/admin_users.html",
    )


@admin_bp.route("/users", methods=["POST"], endpoint="admin_create_user")
@admin_required
def admin_create_user():
    """Create or update a user from the admin users page."""
    user_id = request.form.get("user_id", type=int)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "").strip()
    first_name = request.form.get("first_name", "").strip() or None
    last_name = request.form.get("last_name", "").strip() or None
    email = request.form.get("email", "").strip() or None
    mobile = request.form.get("mobile", "").strip() or None
    send_notifications = request.form.get("send_notifications") == "on"
    is_active = request.form.get("is_active") == "on"
    company_id = request.form.get("company_id", type=int)

    if not username:
        flash("Username is required.")
        return redirect(url_for("admin.admin_users"))

    hashed_pw = generate_password_hash(password) if password else None
    if user_id:
        err = db.admin_update_user(
            user_id,
            username,
            hashed_pw,
            role,
            first_name,
            last_name,
            email,
            mobile,
            send_notifications,
            company_id,
            is_active,
        )
    else:
        err = db.admin_create_user(
            username,
            hashed_pw,
            role,
            first_name,
            last_name,
            email,
            mobile,
            send_notifications,
            company_id,
            is_active,
        )
    if err:
        flash(err)
    else:
        flash("User saved.")
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/companies", methods=["GET", "POST"], endpoint="admin_companies")
@admin_required
def admin_companies():
    """Company management view (admin only)."""
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

        if company_id:
            error = db.admin_update_company(company_id, name, admin_user_id, address1, address2, address3, state, postcode, is_active)
            flash_msg = "Company updated."
        else:
            error = db.admin_create_company(name, address1, address2, address3, state, postcode, admin_user_id, is_active)
            flash_msg = "Company created."

        if error:
            return _build_companies_error_response(show_inactive, company_id, selected_company, error)

        flash(flash_msg)
        return redirect(url_for("admin.admin_companies"))

    companies = db.admin_get_companies(show_inactive=show_inactive)
    company_users = db.admin_get_all_users(selected_id) if selected_id else []
    active_user_counts, total_user_counts = _admin_companies_active_counts(companies)
    return render_template(
        "admin_companies.html",
        companies=companies,
        selected_company=selected_company,
        company_users=company_users,
        active_user_counts=active_user_counts,
        total_user_counts=total_user_counts,
        page_name="templates/admin_companies.html",
    )


@admin_bp.route("/options/<opt_type>/add", methods=["POST"], endpoint="admin_add_option")
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
        return redirect(url_for("admin.admin_tasks"))
    error = db.admin_add_option(opt_type, value, admin["company_id"])
    if error:
        flash(error)
    else:
        flash("Option added.")
        if color:
            db.admin_set_option_color(opt_type, value, color)
    return redirect(url_for("admin.admin_tasks"))


@admin_bp.route("/options/<opt_type>/<int:option_id>/delete", methods=["POST"], endpoint="admin_delete_option")
@admin_required
def admin_delete_option(opt_type, option_id):
    """Remove an impact or severity option."""
    if opt_type not in ("impact", "severity"):
        return INVALID_OPTION_TYPE, 400
    admin = current_user()
    db.admin_delete_option(opt_type, option_id, admin["company_id"])
    flash("Option removed.")
    return redirect(url_for("admin.admin_tasks"))


@admin_bp.route("/options/<opt_type>/<int:option_id>/color", methods=["POST"], endpoint="admin_update_option_color")
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
    return redirect(url_for("admin.admin_tasks"))


@admin_bp.route("/app", methods=["GET", "POST"], endpoint="admin_app_settings")
@admin_required
def admin_app_settings():
    """Render and save global app settings and completion colours."""
    settings = db.admin_get_app_settings()
    if request.method == "GET":
        if settings is None:
            settings = {}
        if isinstance(settings, dict) and not settings.get("app_name"):
            settings["app_name"] = "Compliance Tracker"
        completion_colors = {}
        palette = settings.get("completion_palette", "") if settings else ""
        if palette:
            for part in palette.split(","):
                if ":" in part:
                    k, v = part.split(":", 1)
                    completion_colors[k.strip()] = v.strip()
        return render_template("admin_app.html", settings=settings, completion_colors=completion_colors, page_name="templates/admin_app.html")

    app_name = request.form.get("app_name", "").strip() or (settings.get("app_name") if settings else "Compliance Tracker")
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
        app_name,
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
    return redirect(url_for("admin.admin_app_settings"))


@admin_bp.route("/task-config/colors", methods=["POST"], endpoint="admin_task_config_colors")
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
    db.admin_update_app_settings_completion_colors(severity_palette, impact_palette, completion_palette)
    flash("Chart colours updated.")
    return redirect(url_for("admin.admin_task_config"))


@admin_bp.route("/notify/overdue", endpoint="admin_notify_overdue")
@admin_required
def admin_notify_overdue():
    """Simulate sending overdue notifications to opted-in users (prints to console)."""
    today = date.today()
    sent = 0
    users = db.admin_get_all_users(current_user()["company_id"])
    for u in users:
        if not u.get("send_notifications"):
            continue
        overdue_titles = []
        tasks = db.get_tasks_for_user(u["id"])
        for t in tasks:
            if (t.get("status") or "") == "completed":
                continue
            due_str = t.get("due_date")
            if not due_str:
                continue
            try:
                due_obj = datetime.strptime(due_str, "%Y-%m-%d").date()
            except ValueError:
                continue
            if due_obj < today:
                overdue_titles.append(t.get("title"))
        if not overdue_titles:
            continue
        sent += 1
        print(f"[Notification] To {u['username']} ({u.get('email') or 'no email'}): overdue tasks -> {', '.join(overdue_titles)}")
    flash(f"Notifications sent to {sent} users (printed to console).")
    return redirect(url_for("admin.admin_dashboard"))


def _format_admin_report_task(t):
    if not isinstance(t, dict):
        t = dict(t)
    due_display = t.get("due_date")
    if t.get("due_date"):
        try:
            due_dt = datetime.strptime(t["due_date"], "%Y-%m-%d")
            due_display = due_dt.strftime(DATE_FMT)
        except ValueError:
            pass
    completed_display = format_completed_on(t.get("completed_at"))
    task_type = "global" if not t.get("company_id") else "company"
    return {
        **t,
        "due_display": due_display,
        "completed_display": completed_display,
        "task_id": t["id"],
        "task_type": task_type,
    }


@admin_bp.route("/report/<int:user_id>", endpoint="admin_report")
@admin_required
def admin_report(user_id):
    viewer = current_user()
    if viewer.get("role") not in ("admin", "company_admin"):
        return "Access denied", 403

    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return USER_NOT_FOUND, 404
    if not isinstance(user_row, dict):
        user_row = dict(user_row)

    if viewer.get("role") == "company_admin":
        if user_row.get("company_id") != viewer.get("company_id"):
            return NOT_FOUND, 404

    formatted_tasks = [_format_admin_report_task(t) for t in tasks]
    total = len(formatted_tasks)
    completed = sum(1 for t in formatted_tasks if t.get("status") == "completed")
    pending = total - completed
    overdue = sum(1 for t in formatted_tasks if t.get("overdue"))
    compliance = round((completed / total) * 100, 1) if total else 0
    return render_template(
        "admin_report.html",
        user=user_row,
        tasks=formatted_tasks,
        total=total,
        completed=completed,
        pending=pending,
        overdue=overdue,
        compliance=compliance,
        page_name="templates/admin_report.html",
    )


@admin_bp.route("/report/<int:user_id>/csv", endpoint="admin_report_csv")
@admin_required
def admin_report_csv(user_id):
    """Stream a CSV export of a user's task report."""
    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return USER_NOT_FOUND, 404
    admin_company_id = current_user().get("company_id")
    if admin_company_id is not None and user_row.get("company_id") != admin_company_id:
        return "Not found", 404

    def generate():
        yield "Title,Due Date,Status,Completed At,Answer\n"
        for t in tasks:
            title = (t.get("title") or "").replace('"', '""')
            due = t.get("due_date") or ""
            status = t.get("status") or ""
            completed_at = t.get("completed_at") or ""
            answer = (t.get("answer_text") or "").replace('"', '""')
            yield f'"{title}",{due},{status},{completed_at},"{answer}"\n'

    from flask import Response

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=report_{user_id}.csv"},
    )


@admin_bp.route("/profile", methods=["GET", "POST"], endpoint="admin_profile")
@admin_required
def admin_profile():
    """Let the signed-in user view and edit their profile details."""
    viewer = current_user()
    user = db.admin_get_user(viewer["id"])
    role = viewer.get("role")

    if role == "admin":
        companies = db.admin_get_companies()
        allow_company_change = True
        locked_company_id = None
    else:
        companies = [c for c in db.admin_get_companies() if c["id"] == viewer.get("company_id")]
        allow_company_change = False
        locked_company_id = viewer.get("company_id")

    if request.method == "GET":
        return render_template(
            "admin_profile.html",
            user=user,
            companies=companies,
            is_company_admin=(role == "company_admin"),
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

    if role == "admin":
        company_id = req_company_id if req_company_id is not None else None
    else:
        company_id = locked_company_id or user.get("company_id")

    if not username:
        return render_template(
            "admin_profile.html",
            user=user,
            companies=companies,
            is_company_admin=(role == "company_admin"),
            allow_company_change=allow_company_change,
            error="Username is required.",
            page_name="templates/admin_profile.html",
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
            "admin_profile.html",
            user=user,
            companies=companies,
            is_company_admin=(role == "company_admin"),
            allow_company_change=allow_company_change,
            error=err,
            page_name="templates/admin_profile.html",
        )

    session["username"] = username
    session["company_id"] = company_id

    flash("Profile updated.")
    return redirect(url_for("admin.admin_profile"))


@admin_bp.route("/report/summary.csv", endpoint="admin_summary_csv")
@admin_required
def admin_summary_csv():
    """Stream a CSV of overall compliance stats for all users."""
    compliance = db.admin_user_compliance(None)

    def generate():
        yield "Username,Role,Completed,Total,Compliance%\n"
        for row in compliance:
            total = row["total_tasks"] or 0
            completed = row["completed_tasks"] or 0
            pct = round((completed / total) * 100, 1) if total else 0
            yield f"{row['username']},{row['role']},{completed},{total},{pct}\n"

    from flask import Response

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=compliance_summary.csv"},
    )
