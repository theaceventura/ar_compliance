from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import compliance_app.compliance_app_tailwind.db as db

app = Flask(__name__)
app.secret_key = "change_this_secret_key"

# Initialize database tables on startup (Flask 3 removed before_first_request)
db.create_tables_if_needed()

# Inject settings into all templates
@app.context_processor
def inject_app_settings():
    settings = db.admin_get_app_settings()
    return {"app_settings": settings}


# Helper to read the current logged-in user from session
def current_user():
    if "user_id" not in session:
        return None
    return {
        "id": session["user_id"],
        "username": session["username"],
        "role": session["role"],
    }

def _is_hashed(pw):
    return isinstance(pw, str) and (pw.startswith("pbkdf2:") or pw.startswith("scrypt:"))

# Decorator to require any logged-in user
def login_required(route_function):
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper


# Decorator to require an admin user
def admin_required(route_function):
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            return "Access denied", 403
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper


# Home page is a simple landing page
@app.route("/")
def index():
    return render_template("home.html", page_name="templates/home.html")


# Login page and submission
@app.route("/login", methods=["GET", "POST"])
def login():
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

    if user_row["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Task dashboard: users see their tasks, admins see aggregate task stats
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user["role"] == "admin":
        summary = db.admin_get_summary_counts()
        severity_counts = db.admin_task_counts_by("severity")
        impact_counts = db.admin_task_counts_by("impact")
        compliance_percent = 0
        if summary["total_tasks"]:
            compliance_percent = round((summary["total_completed"] / summary["total_tasks"]) * 100, 1)
        compliance = db.admin_user_compliance()
        return render_template(
            "admin_task_dashboard.html",
            summary=summary,
            severity_counts=severity_counts,
            impact_counts=impact_counts,
            compliance_percent=compliance_percent,
            compliance=compliance,
            page_name="templates/admin_task_dashboard.html",
        )

    tasks = db.get_tasks_for_user(user["id"])
    pending = [t for t in tasks if t["status"] != "completed"]
    completed = [t for t in tasks if t["status"] == "completed"]
    today = date.today()
    pending_display = []
    for t in pending:
        due_str = t["due_date"]
        due_obj = None
        overdue = False
        if due_str:
            try:
                due_obj = datetime.strptime(due_str, "%Y-%m-%d").date()
                overdue = due_obj < today
            except ValueError:
                pass
        pending_display.append({**t, "overdue": overdue})
    total_tasks = len(tasks)
    completed_count = len(completed)
    compliance_percent = round((completed_count / total_tasks) * 100, 1) if total_tasks else 0

    return render_template(
        "dashboard.html",
        user=user,
        pending=pending_display,
        completed=completed,
        compliance_percent=compliance_percent,
        page_name="templates/dashboard.html",
    )


# Individual task view and answer submission
@app.route("/task/<int:task_id>", methods=["GET", "POST"])
@login_required
def task_detail(task_id):
    user = current_user()
    t = db.get_task_for_user(user["id"], task_id)
    if t is None:
        return "Not found", 404

    if request.method == "GET":
        return render_template("task_detail.html", task=t, page_name="templates/task_detail.html")

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
    users = db.admin_get_all_users()
    total_users = sum(1 for u in users if u["role"] == "user")
    total_admins = sum(1 for u in users if u["role"] == "admin")
    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=total_users,
        total_admins=total_admins,
        page_name="templates/admin_dashboard.html",
    )


# Admin: list/create tasks, manage option lists
@app.route("/admin/tasks", methods=["GET", "POST"])
@admin_required
def admin_tasks():
    if request.method == "GET":
        tasks = db.admin_get_all_tasks()
        impacts = db.admin_get_options("impact")
        severities = db.admin_get_options("severity")
        users = db.admin_get_all_users()
        return render_template("admin_tasks.html", tasks=tasks, impacts=impacts, severities=severities, users=users, page_name="templates/admin_tasks.html")

    title = request.form["title"].strip()
    question = request.form["verification_question"].strip()
    answer = request.form["verification_answer"].strip()
    description = request.form.get("description", "").strip()
    due_date = request.form.get("due_date", "").strip()
    impact = request.form.get("impact", "").strip()
    severity = request.form.get("severity", "").strip()
    owner_id = request.form.get("owner_user_id", "").strip() or None

    if not title or not question or not answer:
        return render_template(
            "admin_tasks.html",
            error="Title, question and answer required.",
            tasks=db.admin_get_all_tasks(),
            impacts=db.admin_get_options("impact"),
            severities=db.admin_get_options("severity"),
            users=db.admin_get_all_users(),
            page_name="templates/admin_tasks.html",
        )

    db.admin_create_task(title, description, due_date, impact, severity, owner_id, question, answer)
    flash("Task created.")
    return redirect(url_for("admin_tasks"))


# Admin: edit a specific task
@app.route("/admin/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_task(task_id):
    task = db.admin_get_task(task_id)
    if task is None:
        return "Task not found", 404

    if request.method == "GET":
        return render_template(
            "admin_task_edit.html",
            task=task,
            impacts=db.admin_get_options("impact"),
            severities=db.admin_get_options("severity"),
            users=db.admin_get_all_users(),
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

    if not title or not question or not answer:
        return render_template(
            "admin_task_edit.html",
            task=task,
            impacts=db.admin_get_options("impact"),
            severities=db.admin_get_options("severity"),
            users=db.admin_get_all_users(),
            error="Title, question and answer required.",
            page_name="templates/admin_task_edit.html",
        )

    db.admin_update_task(task_id, title, description, due_date, impact, severity, owner_id, question, answer)
    flash("Task updated.")
    return redirect(url_for("admin_tasks"))


# Admin: user list and selection
@app.route("/admin/users")
@admin_required
def admin_users():
    selected_id = request.args.get("user_id", type=int)
    selected_user = db.admin_get_user(selected_id) if selected_id else None
    users = db.admin_get_all_users()
    return render_template("admin_users.html", users=users, selected_user=selected_user, page_name="templates/admin_users.html")


# Admin: create or update a user
@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "user")
    first_name = request.form.get("first_name", "").strip() or None
    last_name = request.form.get("last_name", "").strip() or None
    email = request.form.get("email", "").strip() or None
    mobile = request.form.get("mobile", "").strip() or None
    send_notifications = request.form.get("send_notifications") == "on"
    user_id = request.form.get("user_id", type=int)

    hashed_pw = generate_password_hash(password) if password else None

    if not username or (not user_id and not password):
        return render_template(
            "admin_users.html",
            users=db.admin_get_all_users(),
            error="Username and password are required.",
            selected_user=db.admin_get_user(user_id) if user_id else None,
            page_name="templates/admin_users.html",
        )

    if user_id:
        error = db.admin_update_user(user_id, username, hashed_pw, role, first_name, last_name, email, mobile, send_notifications)
    else:
        error = db.admin_create_user(username, hashed_pw, role, first_name, last_name, email, mobile, send_notifications)

    if error:
        return render_template(
            "admin_users.html",
            users=db.admin_get_all_users(),
            selected_user=db.admin_get_user(user_id) if user_id else None,
            error=error,
            page_name="templates/admin_users.html",
        )

    flash("User updated." if user_id else "User created.")
    return redirect(url_for("admin_users"))


# Admin: add an option (impact/severity)
@app.route("/admin/options/<opt_type>/add", methods=["POST"])
@admin_required
def admin_add_option(opt_type):
    if opt_type not in ("impact", "severity"):
        return "Invalid option type", 400
    value = request.form.get("value", "").strip()
    if not value:
        flash("Value required.")
        return redirect(url_for("admin_tasks"))
    error = db.admin_add_option(opt_type, value)
    if error:
        flash(error)
    else:
        flash("Option added.")
    return redirect(url_for("admin_tasks"))


# Admin: delete an option (impact/severity)
@app.route("/admin/options/<opt_type>/<int:option_id>/delete", methods=["POST"])
@admin_required
def admin_delete_option(opt_type, option_id):
    if opt_type not in ("impact", "severity"):
        return "Invalid option type", 400
    db.admin_delete_option(opt_type, option_id)
    flash("Option removed.")
    return redirect(url_for("admin_tasks"))


# Admin: app settings page
@app.route("/admin/app", methods=["GET", "POST"])
@admin_required
def admin_app_settings():
    settings = db.admin_get_app_settings()
    if request.method == "GET":
        return render_template("admin_app.html", settings=settings, page_name="templates/admin_app.html")

    version = request.form.get("version", "").strip()
    show_version = request.form.get("show_version") == "on"
    show_page_name = request.form.get("show_page_name") == "on"
    show_module_tree = request.form.get("show_module_tree") == "on"
    db.admin_update_app_settings(version, show_version, show_page_name, show_module_tree)
    flash("Settings updated.")
    return redirect(url_for("admin_app_settings"))

# Admin: send notifications for overdue tasks (console simulation)
@app.route("/admin/notify/overdue")
@admin_required
def admin_notify_overdue():
    # Print a simple notice for users who opted in and have overdue tasks
    today = date.today()
    sent = 0
    users = db.admin_get_all_users()
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
    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return "User not found", 404
    return render_template("admin_report.html", user=user_row, tasks=tasks, page_name="templates/admin_report.html")


# Admin: export user report CSV
@app.route("/admin/report/<int:user_id>/csv")
@admin_required
def admin_report_csv(user_id):
    # Build a CSV stream for a single user's tasks
    user_row, tasks = db.admin_get_user_report(user_id)
    if user_row is None:
        return "User not found", 404
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


# Admin: export compliance summary CSV
@app.route("/admin/report/summary.csv")
@admin_required
def admin_summary_csv():
    # Stream overall compliance stats for all users
    compliance = db.admin_user_compliance()
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
