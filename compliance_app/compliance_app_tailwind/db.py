import sqlite3
from datetime import datetime
from pathlib import Path

# Anchor the database to the project root so it is consistent regardless of the
# working directory (e.g., when running from an IDE).
DB_NAME = str(Path(__file__).resolve().parents[2] / "compliance.db")


def get_connection():
    """Open a SQLite connection to the compliance database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# Check if a column exists in a table (used for lightweight migrations)
def _column_exists(cur, table, column):
    """Return True if the given column exists on the table."""
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())


# Ensure tables/columns exist and seed defaults
def _create_base_tables(cur):
    # Create base tables
    cur.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            company_admin_id INTEGER,
            address_line1 TEXT,
            address_line2 TEXT,
            address_line3 TEXT,
            state TEXT,
            postcode TEXT,
            is_active INTEGER DEFAULT 1
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            is_global_admin INTEGER DEFAULT 0,
            first_name TEXT,
            last_name TEXT,
            email TEXT,
            mobile TEXT,
            send_notifications INTEGER DEFAULT 0,
            company_id INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            due_date TEXT,
            verification_question TEXT,
            verification_answer TEXT,
            company_id INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            task_id INTEGER,
            status TEXT,
            answer_text TEXT,
            completed_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS impact_options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT UNIQUE,
            company_id INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS severity_options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT UNIQUE,
            company_id INTEGER
        )
    """)


def _run_migrations(cur):
    migrations = [
        # tasks table additions
        ("tasks", "impact", "ALTER TABLE tasks ADD COLUMN impact TEXT"),
        ("tasks", "severity", "ALTER TABLE tasks ADD COLUMN severity TEXT"),
        ("tasks", "owner_user_id", "ALTER TABLE tasks ADD COLUMN owner_user_id INTEGER"),
        ("tasks", "company_id", "ALTER TABLE tasks ADD COLUMN company_id INTEGER", "UPDATE tasks SET company_id=1 WHERE company_id IS NULL"),
        # users table additions
        ("users", "first_name", "ALTER TABLE users ADD COLUMN first_name TEXT"),
        ("users", "last_name", "ALTER TABLE users ADD COLUMN last_name TEXT"),
        ("users", "email", "ALTER TABLE users ADD COLUMN email TEXT"),
        ("users", "mobile", "ALTER TABLE users ADD COLUMN mobile TEXT"),
        ("users", "send_notifications", "ALTER TABLE users ADD COLUMN send_notifications INTEGER DEFAULT 0"),
        ("users", "is_active", "ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1"),
        ("users", "is_global_admin", "ALTER TABLE users ADD COLUMN is_global_admin INTEGER DEFAULT 0"),
        ("users", "company_id", "ALTER TABLE users ADD COLUMN company_id INTEGER", "UPDATE users SET company_id=1 WHERE company_id IS NULL"),
        # impact/severity options company_id
        ("impact_options", "company_id", "ALTER TABLE impact_options ADD COLUMN company_id INTEGER", "UPDATE impact_options SET company_id=1 WHERE company_id IS NULL"),
        ("severity_options", "company_id", "ALTER TABLE severity_options ADD COLUMN company_id INTEGER", "UPDATE severity_options SET company_id=1 WHERE company_id IS NULL"),
        # companies additions
        ("companies", "company_admin_id", "ALTER TABLE companies ADD COLUMN company_admin_id INTEGER"),
        ("companies", "address_line1", "ALTER TABLE companies ADD COLUMN address_line1 TEXT"),
        ("companies", "address_line2", "ALTER TABLE companies ADD COLUMN address_line2 TEXT"),
        ("companies", "address_line3", "ALTER TABLE companies ADD COLUMN address_line3 TEXT"),
        ("companies", "state", "ALTER TABLE companies ADD COLUMN state TEXT"),
        ("companies", "postcode", "ALTER TABLE companies ADD COLUMN postcode TEXT"),
        ("companies", "is_active", "ALTER TABLE companies ADD COLUMN is_active INTEGER DEFAULT 1"),
    ]

    for item in migrations:
        table, column, ddl = item[0], item[1], item[2]
        if not _column_exists(cur, table, column):
            cur.execute(ddl)
            # optional follow-up SQL provided as 4th element
            if len(item) > 3:
                cur.execute(item[3])


def _ensure_app_settings(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version TEXT,
            show_version INTEGER DEFAULT 0,
            show_page_name INTEGER DEFAULT 0,
            show_module_tree INTEGER DEFAULT 0,
            show_cut_icon INTEGER DEFAULT 0,
            show_label_edit INTEGER DEFAULT 0,
            show_task_charts INTEGER DEFAULT 1,
            show_risk_matrix INTEGER DEFAULT 1,
            show_user_banner INTEGER DEFAULT 1,
            show_user_charts_global INTEGER DEFAULT 1,
            show_user_charts_company INTEGER DEFAULT 1,
            show_user_charts_user INTEGER DEFAULT 1,
            show_validation_notes INTEGER DEFAULT 1,
            severity_palette TEXT,
            impact_palette TEXT,
            completion_palette TEXT
        )
    """)

    app_settings_columns = [
        ("show_module_tree", "ALTER TABLE app_settings ADD COLUMN show_module_tree INTEGER DEFAULT 0"),
        ("show_cut_icon", "ALTER TABLE app_settings ADD COLUMN show_cut_icon INTEGER DEFAULT 0"),
        ("show_label_edit", "ALTER TABLE app_settings ADD COLUMN show_label_edit INTEGER DEFAULT 0"),
        ("show_task_charts", "ALTER TABLE app_settings ADD COLUMN show_task_charts INTEGER DEFAULT 1"),
        ("show_risk_matrix", "ALTER TABLE app_settings ADD COLUMN show_risk_matrix INTEGER DEFAULT 1"),
        ("show_user_banner", "ALTER TABLE app_settings ADD COLUMN show_user_banner INTEGER DEFAULT 1"),
        ("show_user_charts_global", "ALTER TABLE app_settings ADD COLUMN show_user_charts_global INTEGER DEFAULT 1"),
        ("show_user_charts_company", "ALTER TABLE app_settings ADD COLUMN show_user_charts_company INTEGER DEFAULT 1"),
        ("show_user_charts_user", "ALTER TABLE app_settings ADD COLUMN show_user_charts_user INTEGER DEFAULT 1"),
        ("show_validation_notes", "ALTER TABLE app_settings ADD COLUMN show_validation_notes INTEGER DEFAULT 1"),
        ("severity_palette", "ALTER TABLE app_settings ADD COLUMN severity_palette TEXT"),
        ("impact_palette", "ALTER TABLE app_settings ADD COLUMN impact_palette TEXT"),
        ("completion_palette", "ALTER TABLE app_settings ADD COLUMN completion_palette TEXT"),
    ]
    for col, ddl in app_settings_columns:
        if not _column_exists(cur, "app_settings", col):
            cur.execute(ddl)

    cur.execute("SELECT 1 FROM app_settings WHERE id=1")
    if cur.fetchone() is None:
        cur.execute("""
            INSERT INTO app_settings (id, version, show_version, show_page_name, show_module_tree, show_cut_icon, show_label_edit, show_task_charts, show_risk_matrix, show_user_banner, show_user_charts_global, show_user_charts_company, show_user_charts_user, show_validation_notes, severity_palette, impact_palette, completion_palette)
            VALUES (1, '', 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, '', '', '')
        """)
    else:
        cur.execute("""
            UPDATE app_settings
            SET show_user_charts_global = COALESCE(show_user_charts_global, 1),
                show_user_charts_company = COALESCE(show_user_charts_company, 1),
                show_user_charts_user = COALESCE(show_user_charts_user, 1)
            WHERE id = 1
        """)


def _ensure_task_field_descriptions(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS task_field_descriptions (
            field TEXT PRIMARY KEY,
            description TEXT,
            is_required INTEGER DEFAULT 0
        )
    """)
    if not _column_exists(cur, "task_field_descriptions", "is_required"):
        cur.execute("ALTER TABLE task_field_descriptions ADD COLUMN is_required INTEGER DEFAULT 0")

    defaults = {
        "title": ("Short name shown in lists.", 1),
        "description": ("Optional details shown on the task page.", 0),
        "due_date": ("Deadline (dd/mm/yyyy) used for overdue status.", 0),
        "impact": ("Select a label for reporting.", 0),
        "severity": ("Select a label for reporting.", 0),
        "verification_question": ("What the user must answer to complete the task.", 1),
        "verification_answer": ("Correct response that marks the task complete.", 1),
        "assignment": ("Choose specific users or apply to everyone.", 0),
    }
    cur.execute("SELECT field FROM task_field_descriptions")
    existing = {row[0] for row in cur.fetchall()}
    for field, (desc, req) in defaults.items():
        if field not in existing:
            cur.execute(
                "INSERT INTO task_field_descriptions (field, description, is_required) VALUES (?, ?, ?)",
                (field, desc, 1 if req else 0),
            )


def _ensure_default_company_and_admin(cur):
    # Create default company if missing
    cur.execute("SELECT id FROM companies WHERE id=1")
    if cur.fetchone() is None:
        cur.execute("INSERT INTO companies (id, name) VALUES (1, 'Default')")

    # Ensure admin user exists and is global admin
    cur.execute("SELECT * FROM users WHERE username='admin'")
    admin_row = cur.fetchone()
    if admin_row is None:
        cur.execute(
            "INSERT INTO users (username,password,role,first_name,last_name,email,mobile,send_notifications,company_id) VALUES ('admin','secret','admin','','','','',0,1)"
        )
        cur.execute("UPDATE users SET is_global_admin=1 WHERE username='admin'")
    else:
        cur.execute("UPDATE users SET is_global_admin=1 WHERE username='admin'")


def _seed_impact_severity_defaults(cur):
    cur.execute("SELECT COUNT(*) FROM impact_options WHERE company_id=1")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO impact_options (value, company_id) VALUES (?,1)",
            [("Low",), ("Medium",), ("High",)],
        )
    cur.execute("SELECT COUNT(*) FROM severity_options WHERE company_id=1")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO severity_options (value, company_id) VALUES (?,1)",
            [("Low",), ("Medium",), ("High",), ("Critical",)],
        )


def create_tables_if_needed():
    """Create tables, add missing columns, and seed default data."""
    conn = get_connection()
    cur = conn.cursor()

    _create_base_tables(cur)
    _run_migrations(cur)
    _ensure_app_settings(cur)
    _ensure_task_field_descriptions(cur)
    _ensure_default_company_and_admin(cur)
    _seed_impact_severity_defaults(cur)

    conn.commit()
    conn.close()

# Set a specific user's password (already hashed)
def set_user_password(user_id, hashed_password):
    """Update a user's password to the provided hashed value."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, user_id))
    conn.commit()
    conn.close()

# Look up a user by username
def get_user_by_username(username):
    """Return a user row by username or None if missing."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


# All tasks assigned to a user (with status)
def get_tasks_for_user(user_id):
    """Fetch tasks assigned to a user along with status info."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT tasks.*, user_tasks.status, user_tasks.completed_at
        FROM tasks
        JOIN user_tasks ON tasks.id = user_tasks.task_id
        JOIN users ON users.id = user_tasks.user_id
        WHERE user_tasks.user_id=?
          AND (tasks.company_id = users.company_id OR tasks.company_id IS NULL)
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


# Single task for a user (used in detail view)
def get_task_for_user(user_id, task_id):
    """Fetch a single task row for a user including answer/status."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT tasks.*, user_tasks.status, user_tasks.answer_text, user_tasks.completed_at,
               tasks.verification_answer
        FROM tasks
        JOIN user_tasks ON tasks.id=user_tasks.task_id
        JOIN users ON users.id = user_tasks.user_id
        WHERE user_tasks.user_id=? AND tasks.id=?
          AND (tasks.company_id = users.company_id OR tasks.company_id IS NULL)
    """, (user_id, task_id))
    row = cur.fetchone()
    conn.close()
    return row


# Record whether a user's answer was correct
def mark_task_result(user_id, task_id, answer, correct):
    """Store a task answer and mark completion status."""
    conn = get_connection()
    cur = conn.cursor()

    if correct:
        cur.execute("""
            UPDATE user_tasks SET status='completed', answer_text=?, completed_at=?
            WHERE user_id=? AND task_id=?
        """, (answer, datetime.now().isoformat(), user_id, task_id))
    else:
        cur.execute("""
            UPDATE user_tasks SET status='pending', answer_text=?, completed_at=NULL
            WHERE user_id=? AND task_id=?
        """, (answer, user_id, task_id))

    conn.commit()
    conn.close()


# Admin: summary counts for dashboards
def admin_get_summary_counts(company_id):
    """Return aggregate task/user counts, optionally filtered by company."""
    conn = get_connection()
    cur = conn.cursor()
    if company_id is None:
        cur.execute("SELECT COUNT(*) FROM users WHERE role='user'")
        users = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(*)
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            LEFT JOIN tasks t ON t.id = ut.task_id
            WHERE (t.company_id = u.company_id OR t.company_id IS NULL)
        """)
        tasks = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(*)
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            LEFT JOIN tasks t ON t.id = ut.task_id
            WHERE ut.status='completed'
              AND (t.company_id = u.company_id OR t.company_id IS NULL)
        """)
        completed = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(*)
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            LEFT JOIN tasks t ON t.id = ut.task_id
            WHERE ut.status='pending'
              AND (t.company_id = u.company_id OR t.company_id IS NULL)
        """)
        pending = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(*)
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            LEFT JOIN tasks t ON t.id = ut.task_id
            WHERE ut.status != 'completed'
              AND t.due_date IS NOT NULL
              AND t.due_date != ''
              AND DATE(t.due_date) < DATE('now')
              AND (t.company_id = u.company_id OR t.company_id IS NULL)
        """)
        overdue = cur.fetchone()[0]
    else:
        cur.execute("SELECT COUNT(*) FROM users WHERE role='user' AND company_id=?", (company_id,))
        users = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*)
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            LEFT JOIN tasks t ON t.id = ut.task_id
            WHERE u.company_id=?
              AND (t.company_id = u.company_id OR t.company_id IS NULL)
        """, (company_id,))
        tasks = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*)
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            LEFT JOIN tasks t ON t.id = ut.task_id
            WHERE ut.status='completed' AND u.company_id=?
              AND (t.company_id = u.company_id OR t.company_id IS NULL)
        """, (company_id,))
        completed = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*)
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            LEFT JOIN tasks t ON t.id = ut.task_id
            WHERE ut.status='pending' AND u.company_id=?
              AND (t.company_id = u.company_id OR t.company_id IS NULL)
        """, (company_id,))
        pending = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*)
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            LEFT JOIN tasks t ON t.id = ut.task_id
            WHERE ut.status != 'completed'
              AND t.due_date IS NOT NULL
              AND t.due_date != ''
              AND DATE(t.due_date) < DATE('now')
              AND u.company_id=?
              AND (t.company_id = u.company_id OR t.company_id IS NULL)
        """, (company_id,))
        overdue = cur.fetchone()[0]

    conn.close()
    return {
        "total_users": users,
        "total_tasks": tasks,
        "total_completed": completed,
        "total_pending": pending,
        "total_overdue": overdue,
    }


# Admin: list users
def admin_get_all_users(company_id=None):
    """Return all users, optionally filtered to a company."""
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        # Exclude global admins from company-scoped lists
        cur.execute("""
            SELECT *
            FROM users
            WHERE company_id=?
              AND LOWER(role) NOT IN ('admin','global admin')
              AND COALESCE(is_global_admin,0)=0
            ORDER BY username
        """, (company_id,))
    else:
        # Default: hide global admin accounts from the main listing
        cur.execute("""
            SELECT *
            FROM users
            WHERE LOWER(role) NOT IN ('admin','global admin')
              AND COALESCE(is_global_admin,0)=0
            ORDER BY username
        """)
    rows = cur.fetchall()
    conn.close()
    return rows


def admin_get_user(user_id, company_id=None):
    """Return a single user row by id, optionally scoped by company."""
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        cur.execute("SELECT * FROM users WHERE id=? AND company_id=?", (user_id, company_id))
    else:
        cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


# Admin: option lists (impact/severity)
def admin_get_options(opt_type, company_id=None):
    """List impact or severity options, optionally filtered to a company."""
    table = "impact_options" if opt_type == "impact" else "severity_options"
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        cur.execute(f"SELECT * FROM {table} WHERE company_id=? ORDER BY value", (company_id,))
    else:
        cur.execute(f"SELECT * FROM {table} ORDER BY value")
    rows = cur.fetchall()
    conn.close()
    return rows


def admin_get_option(opt_type, option_id, company_id=None):
    """Get a single impact or severity option by id."""
    table = "impact_options" if opt_type == "impact" else "severity_options"
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        cur.execute(f"SELECT * FROM {table} WHERE id=? AND company_id=?", (option_id, company_id))
    else:
        cur.execute(f"SELECT * FROM {table} WHERE id=?", (option_id,))
    row = cur.fetchone()
    conn.close()
    return row


def admin_add_option(opt_type, value, company_id=1):
    """Insert a new option; return error text on duplicate."""
    table = "impact_options" if opt_type == "impact" else "severity_options"
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(f"INSERT INTO {table} (value, company_id) VALUES (?, ?)", (value, company_id))
        conn.commit()
        return None
    except sqlite3.IntegrityError:
        conn.rollback()
        return "That option already exists."
    finally:
        conn.close()


# Admin: delete an option value
def admin_delete_option(opt_type, option_id, company_id=None):
    """Remove an option row."""
    table = "impact_options" if opt_type == "impact" else "severity_options"
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        cur.execute(f"DELETE FROM {table} WHERE id=? AND company_id=?", (option_id, company_id))
    else:
        cur.execute(f"DELETE FROM {table} WHERE id=?", (option_id,))
    conn.commit()
    conn.close()


# Admin: read app settings
def admin_get_app_settings():
    """Read the single row of global app settings."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM app_settings WHERE id=1")
    row = cur.fetchone()
    conn.close()
    return row


# Admin: update app settings
def admin_update_app_settings(version, show_version, show_page_name, show_module_tree, show_cut_icon, show_label_edit, show_task_charts, show_risk_matrix, show_user_banner, show_user_charts_global, show_user_charts_company, show_user_charts_user, show_validation_notes):
    """Persist the main app setting flags and version string."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE app_settings
        SET version=?, show_version=?, show_page_name=?, show_module_tree=?, show_cut_icon=?, show_label_edit=?, show_task_charts=?, show_risk_matrix=?, show_user_banner=?, show_user_charts_global=?, show_user_charts_company=?, show_user_charts_user=?, show_validation_notes=?
        WHERE id=1
    """, (
        version,
        1 if show_version else 0,
        1 if show_page_name else 0,
        1 if show_module_tree else 0,
        1 if show_cut_icon else 0,
        1 if show_label_edit else 0,
        1 if show_task_charts else 0,
        1 if show_risk_matrix else 0,
        1 if show_user_banner else 0,
        1 if show_user_charts_global else 0,
        1 if show_user_charts_company else 0,
        1 if show_user_charts_user else 0,
        1 if show_validation_notes else 0,
    ))
    conn.commit()
    conn.close()


# Admin: update chart palettes (CSV hex strings)
def admin_update_chart_palettes(severity_palette, impact_palette, completion_palette):
    """Store chart palette strings for severity, impact, and completion."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE app_settings
        SET severity_palette=?, impact_palette=?, completion_palette=?
        WHERE id=1
    """, (severity_palette, impact_palette, completion_palette))
    conn.commit()
    conn.close()


# Palette helpers
def _palette_to_dict(palette_str):
    """Convert a stored palette string into a dict of label->color."""
    if not palette_str:
        return {}
    mapping = {}
    for part in palette_str.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        k, v = part.split(":", 1)
        mapping[k.strip()] = v.strip()
    return mapping


def _dict_to_palette(mapping):
    """Convert a palette dict back to a storage string."""
    return ",".join(f"{k}:{v}" for k, v in mapping.items())


def admin_set_option_color(opt_type, label, color_hex):
    """Save a hex colour for an impact/severity label in app settings."""
    col = "impact_palette" if opt_type == "impact" else "severity_palette"
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT {col} FROM app_settings WHERE id=1")
    row = cur.fetchone()
    existing = row[col] if row else ""
    palette = _palette_to_dict(existing)
    palette[label] = color_hex
    cur.execute(f"UPDATE app_settings SET {col}=? WHERE id=1", (_dict_to_palette(palette),))
    conn.commit()
    conn.close()


# Admin: task field descriptions
def admin_get_task_field_descriptions():
    """Return task field metadata keyed by field name."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT field, description, is_required FROM task_field_descriptions")
    rows = cur.fetchall()
    conn.close()
    return {
        row["field"]: {
            "description": row["description"] or "",
            "required": bool(row["is_required"]),
        }
        for row in rows
    }


def admin_update_task_field_descriptions(updates):
    """Upsert task field descriptions and required flags."""
    conn = get_connection()
    cur = conn.cursor()
    for field, payload in updates.items():
        desc = payload.get("description", "")
        required = 1 if payload.get("required") else 0
        cur.execute("""
            INSERT INTO task_field_descriptions (field, description)
            VALUES (?, ?)
            ON CONFLICT(field) DO UPDATE SET description=excluded.description, is_required=?
        """, (field, desc, required))
    conn.commit()
    conn.close()


# Admin: create user
def admin_create_user(username, password, role="user", first_name=None, last_name=None, email=None, mobile=None, send_notifications=False, company_id=1, is_active=True):
    """Create a user and assign existing tasks; return error text on conflict."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO users (username, password, role, first_name, last_name, email, mobile, send_notifications, company_id, is_active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (username, password, role, first_name, last_name, email, mobile, 1 if send_notifications else 0, company_id, 1 if is_active else 0),
        )
        user_id = cur.lastrowid

        # Assign existing tasks to the new user as pending.
        # Include both company-specific tasks and global tasks (company_id is NULL/0).
        cur.execute("SELECT id FROM tasks WHERE company_id=? OR company_id IS NULL OR company_id=0", (company_id,))
        for t in cur.fetchall():
            cur.execute(
                "INSERT INTO user_tasks (user_id, task_id, status) VALUES (?, ?, 'pending')",
                (user_id, t["id"]),
            )

        conn.commit()
        return None
    except sqlite3.IntegrityError:
        conn.rollback()
        return "Username already exists."
    finally:
        conn.close()


# Admin: update user
def _check_not_last_admin(cur, current_role, new_role):
    """Return error message if attempting to remove the last global admin, otherwise None."""
    if new_role == "admin":
        return None
    # Only care if user was previously an admin
    if current_role != "admin":
        return None
    cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    total_admins = cur.fetchone()[0]
    if total_admins <= 1:
        return "At least one global admin is required."
    return None

def _build_user_update_query(password, company_id):
    """Return (sql, params_ordering_list) pieces for updating the users row."""
    fields = ["username = ?", "role = ?", "first_name = ?", "last_name = ?", "email = ?", "mobile = ?", "send_notifications = ?", "is_active = ?"]
    if password:
        # place password immediately after username for clarity
        fields.insert(1, "password = ?")
    if company_id is not None:
        fields.append("company_id = ?")
    sql = "UPDATE users SET " + ", ".join(fields) + " WHERE id = ?"
    return sql, fields

def _execute_user_update(cur, sql, username, password, role, first_name, last_name, email, mobile, send_notifications, is_active, company_id, user_id):
    """Execute an update on users with a consistent parameter order."""
    params = [username]
    if "password = ?" in sql:
        params.append(password)
    params.extend([role, first_name, last_name, email, mobile, 1 if send_notifications else 0, 1 if is_active else 0])
    if company_id is not None:
        params.append(company_id)
    params.append(user_id)
    cur.execute(sql, tuple(params))

def _replace_company_assignments_on_change(cur, user_id, new_company_id):
    """Remove assignments that don't apply to the new company and add missing pending assignments."""
    # Drop any assignments where the task's company does not match the new company (but keep global tasks)
    cur.execute("""
        DELETE FROM user_tasks
        WHERE user_id=?
          AND task_id IN (
              SELECT id FROM tasks WHERE company_id IS NOT NULL AND company_id != ?
          )
    """, (user_id, new_company_id))
    # Assign missing tasks for the new company scope and global tasks
    cur.execute("""
        INSERT INTO user_tasks (user_id, task_id, status)
        SELECT ?, t.id, 'pending'
        FROM tasks t
        LEFT JOIN user_tasks ut ON ut.user_id=? AND ut.task_id=t.id
        WHERE ut.id IS NULL
          AND (t.company_id IS NULL OR t.company_id=0 OR t.company_id=?)
    """, (user_id, user_id, new_company_id))

def admin_update_user(user_id, username, password, role, first_name, last_name, email, mobile, send_notifications, company_id=None, is_active=True):
    """Update user fields; guard against removing the last admin."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Track original company/role to clean up assignments if the company changes
        cur.execute("SELECT role, company_id FROM users WHERE id=?", (user_id,))
        current_row = cur.fetchone()
        current_role = current_row["role"] if current_row else None
        current_company = current_row["company_id"] if current_row else None

        # Prevent removing the last global admin
        err = _check_not_last_admin(cur, current_role, role)
        if err:
            return err

        # Build and run a single UPDATE statement (password/company_id included conditionally)
        sql, _ = _build_user_update_query(password, company_id)
        _execute_user_update(cur, sql, username, password, role, first_name, last_name, email, mobile, send_notifications, is_active, company_id, user_id)

        # If the user changed companies, update assignments accordingly
        if company_id is not None and company_id != current_company:
            _replace_company_assignments_on_change(cur, user_id, company_id)

        conn.commit()
        return None
    except sqlite3.IntegrityError:
        conn.rollback()
        return "Username already exists."
    finally:
        conn.close()


# Admin: compliance counts per user (totals/completed)
def admin_user_compliance(company_id):
    """Return per-user compliance counts (completed, pending, overdue)."""
    conn = get_connection()
    cur = conn.cursor()
    _assign_tasks_for_company(cur, company_id)
    # Exclude global admins from per-company rollups, even if the role label was
    # stored as "Global Admin" instead of the canonical "admin".
    if company_id is None:
        cur.execute("""
            SELECT users.id, users.username, users.role, users.first_name, users.last_name,
                   COUNT(user_tasks.id) as total_tasks,
                   SUM(CASE WHEN user_tasks.status='completed' THEN 1 ELSE 0 END) as completed_tasks,
                   SUM(CASE WHEN user_tasks.status!='completed' THEN 1 ELSE 0 END) as pending_tasks,
                   SUM(CASE WHEN user_tasks.status!='completed'
                            AND tasks.due_date IS NOT NULL
                            AND tasks.due_date != ''
                            AND DATE(tasks.due_date) < DATE('now') THEN 1 ELSE 0 END) as overdue_tasks
            FROM users
            LEFT JOIN user_tasks ON users.id = user_tasks.user_id
            LEFT JOIN tasks ON tasks.id = user_tasks.task_id
            WHERE (tasks.company_id = users.company_id OR tasks.company_id IS NULL)
              AND LOWER(users.role) NOT IN ('admin', 'global admin')
              AND COALESCE(users.is_global_admin,0)=0
            GROUP BY users.id, users.username, users.role, users.first_name, users.last_name
            ORDER BY users.username
        """)
    else:
        cur.execute("""
            SELECT users.id, users.username, users.role, users.first_name, users.last_name,
                   COUNT(user_tasks.id) as total_tasks,
                   SUM(CASE WHEN user_tasks.status='completed' THEN 1 ELSE 0 END) as completed_tasks,
                   SUM(CASE WHEN user_tasks.status!='completed' THEN 1 ELSE 0 END) as pending_tasks,
                   SUM(CASE WHEN user_tasks.status!='completed'
                            AND tasks.due_date IS NOT NULL
                            AND tasks.due_date != ''
                            AND DATE(tasks.due_date) < DATE('now') THEN 1 ELSE 0 END) as overdue_tasks
            FROM users
            LEFT JOIN user_tasks ON users.id = user_tasks.user_id
            LEFT JOIN tasks ON tasks.id = user_tasks.task_id
            WHERE users.company_id=?
              AND LOWER(users.role) NOT IN ('admin', 'global admin')
              AND COALESCE(users.is_global_admin,0)=0
              AND (tasks.company_id = users.company_id OR tasks.company_id IS NULL)
            GROUP BY users.id, users.username, users.role, users.first_name, users.last_name
            ORDER BY users.username
        """, (company_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


# Admin: list tasks (with assignment summary)
def admin_get_all_tasks(company_id=None):
    """List tasks with owner, company, assignment scope, and overdue flag."""
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        _assign_tasks_for_company(cur, company_id)
        cur.execute("""
            SELECT tasks.*,
                   users.username AS owner_username,
                   companies.name AS company_name,
                   CASE
                       WHEN (
                           SELECT COUNT(*) FROM user_tasks ut
                           JOIN users u2 ON ut.user_id = u2.id
                           WHERE ut.task_id = tasks.id AND u2.company_id = ?
                       ) = (SELECT COUNT(*) FROM users WHERE role='user' AND company_id=?)
                       THEN 'All users'
                       ELSE 'Selected users'
                   END AS assignment_scope,
                   CASE
                       WHEN tasks.due_date IS NOT NULL AND tasks.due_date != '' AND DATE(tasks.due_date) < DATE('now')
                       THEN 1 ELSE 0
                   END AS overdue
            FROM tasks
            LEFT JOIN users ON tasks.owner_user_id = users.id
            LEFT JOIN companies ON companies.id = tasks.company_id
            WHERE (tasks.company_id=? OR tasks.company_id IS NULL OR tasks.company_id=0)
            ORDER BY due_date
        """, (company_id, company_id, company_id))
    else:
        _assign_tasks_for_company(cur, None)
        cur.execute("""
            SELECT tasks.*,
                   users.username AS owner_username,
                   companies.name AS company_name,
                   CASE
                       WHEN EXISTS (
                           SELECT 1 FROM user_tasks ut WHERE ut.task_id = tasks.id
                           GROUP BY ut.task_id
                           HAVING COUNT(*) = (SELECT COUNT(*) FROM users WHERE role='user')
                       ) THEN 'All users'
                       ELSE 'Selected users'
                   END AS assignment_scope,
                   CASE
                       WHEN tasks.due_date IS NOT NULL AND tasks.due_date != '' AND DATE(tasks.due_date) < DATE('now')
                       THEN 1 ELSE 0
                   END AS overdue
            FROM tasks
            LEFT JOIN users ON tasks.owner_user_id = users.id
            LEFT JOIN companies ON companies.id = tasks.company_id
            ORDER BY due_date
        """)
    rows = cur.fetchall()
    conn.close()
    return rows


# Admin: get single task
def admin_get_task(task_id, company_id=None):
    """Fetch a single task row by id, optionally scoping to company."""
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        cur.execute("""
            SELECT tasks.*, users.username AS owner_username
            FROM tasks
            LEFT JOIN users ON tasks.owner_user_id = users.id
            WHERE tasks.id=? AND (tasks.company_id=? OR tasks.company_id IS NULL)
        """, (task_id, company_id))
    else:
        cur.execute("""
            SELECT tasks.*, users.username AS owner_username
            FROM tasks
            LEFT JOIN users ON tasks.owner_user_id = users.id
            WHERE tasks.id=?
        """, (task_id,))
    row = cur.fetchone()
    conn.close()
    return row


# Admin: update task
def admin_update_task(task_id, title, description, due_date, impact, severity, owner_user_id, question, answer, company_id=None):
    """Update task fields for an existing task."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE tasks
        SET title=?, description=?, due_date=?, impact=?, severity=?, owner_user_id=?, verification_question=?, verification_answer=?, company_id=?
        WHERE id=?
    """, (title, description, due_date, impact, severity, owner_user_id, question, answer, company_id, task_id))
    conn.commit()
    conn.close()


def admin_get_task_assignments(task_id):
    """Return a set of user_ids currently assigned to the task."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM user_tasks WHERE task_id=?", (task_id,))
    rows = cur.fetchall()
    conn.close()
    return {r["user_id"] for r in rows}


def admin_get_task_assignment_status(task_id):
    """Return a mapping of user_id -> status for assignments on a task."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, status FROM user_tasks WHERE task_id=?", (task_id,))
    rows = cur.fetchall()
    conn.close()
    return {r["user_id"]: r["status"] for r in rows}

def admin_ensure_assignments_for_company(company_id=None):
    """Assign any missing user_tasks rows for the given company (or all companies) so dashboards stay in sync."""
    conn = get_connection()
    cur = conn.cursor()
    _assign_tasks_for_company(cur, company_id)
    conn.commit()
    conn.close()


def ensure_user_assignments(user_id, company_id=None):
    """Assign all applicable tasks (company-specific or global) to the given user if missing."""
    conn = get_connection()
    cur = conn.cursor()
    # Pull tasks that match the user's company or are global
    cur.execute("""
        INSERT INTO user_tasks (user_id, task_id, status)
        SELECT ?, t.id, 'pending'
        FROM tasks t
        LEFT JOIN user_tasks ut ON ut.user_id=? AND ut.task_id=t.id
        WHERE ut.id IS NULL
          AND (t.company_id IS NULL OR t.company_id=0 OR t.company_id=?)
    """, (user_id, user_id, company_id))
    conn.commit()
    conn.close()


def _get_company_user_ids(cur, company_id):
    """Return a set of user ids for the given company (or all users if company_id is None)."""
    if company_id is None:
        cur.execute("SELECT id FROM users WHERE role='user'")
    else:
        cur.execute("SELECT id FROM users WHERE role='user' AND company_id=?", (company_id,))
    return {u["id"] for u in cur.fetchall()}

def _filter_requested_user_ids(cur, requested_set, company_id):
    """Return only those requested ids that belong to the given company (or all if company_id is None)."""
    if company_id is None:
        return requested_set
    if not requested_set:
        return set()
    placeholders = ",".join("?" for _ in requested_set)
    cur.execute(f"SELECT id FROM users WHERE company_id=? AND id IN ({placeholders})", (company_id, *requested_set))
    return {r["id"] for r in cur.fetchall()}

def admin_update_task_assignments(task_id, company_id=None, user_ids=None, assign_all=False):
    """Update task assignments while preserving existing statuses for kept users."""
    conn = get_connection()
    cur = conn.cursor()
    user_ids = user_ids or []

    # Decide recipients: explicit selection, assign-all, or all users in scope
    if assign_all or not user_ids:
        recipients = _get_company_user_ids(cur, company_id)
    else:
        requested = {int(uid) for uid in user_ids}
        recipients = _filter_requested_user_ids(cur, requested, company_id)

    # Fetch existing rows to preserve status and detect completed users
    cur.execute("SELECT user_id, status, answer_text, completed_at FROM user_tasks WHERE task_id=?", (task_id,))
    rows = cur.fetchall()
    existing = {row["user_id"]: row for row in rows}
    completed_users = {uid for uid, row in existing.items() if row["status"] == "completed"}

    # Ensure completed assignments are not removed
    recipients |= completed_users

    # Delete rows for users no longer assigned (but keep completed ones due to recipients union)
    if existing:
        if recipients:
            placeholders = ",".join("?" for _ in recipients)
            params = (task_id, *recipients)
            cur.execute(f"DELETE FROM user_tasks WHERE task_id=? AND user_id NOT IN ({placeholders})", params)
        else:
            cur.execute("DELETE FROM user_tasks WHERE task_id=?", (task_id,))

    # Insert rows for new recipients, preserving existing rows
    for uid in recipients:
        if uid in existing:
            continue
        cur.execute(
            "INSERT INTO user_tasks (user_id, task_id, status) VALUES (?, ?, 'pending')",
            (uid, task_id),
        )

    conn.commit()
    conn.close()


# Admin: counts grouped by a column (impact/severity)
def admin_task_counts_by(column, company_id=None):
    """Count tasks grouped by impact or severity, optionally by company."""
    if column not in ("impact", "severity"):
        return []
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        cur.execute(f"""
            SELECT COALESCE({column}, 'Unspecified') as label, COUNT(*) as count
            FROM tasks
            WHERE (company_id=? OR company_id IS NULL)
              AND EXISTS (
                  SELECT 1 FROM user_tasks ut
                  JOIN users u ON u.id = ut.user_id
                  WHERE ut.task_id = tasks.id AND u.company_id = ?
              )
            GROUP BY COALESCE({column}, 'Unspecified')
        """, (company_id, company_id))
    else:
        cur.execute(f"""
            SELECT COALESCE({column}, 'Unspecified') as label, COUNT(*) as count
            FROM tasks
            GROUP BY COALESCE({column}, 'Unspecified')
        """)
    rows = cur.fetchall()
    conn.close()
    return rows


# Admin: create task and assign
def admin_create_task(title, description, due_date, impact, severity, owner_user_id, question, answer, company_id, user_ids=None, assign_all=False):
    """Create a task and assign it to selected or all eligible users."""
    conn = get_connection()
    cur = conn.cursor()
    user_ids = user_ids or []

    cur.execute("""
        INSERT INTO tasks (title,description,due_date,impact,severity,owner_user_id,verification_question,verification_answer,company_id)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (title, description, due_date, impact, severity, owner_user_id, question, answer, company_id))

    task_id = cur.lastrowid

    # Decide recipients: explicit selection, assign-all, or fallback to all users in scope (company or all)
    if assign_all or not user_ids:
        if company_id is None:
            cur.execute("SELECT id FROM users WHERE role='user'")
        else:
            cur.execute("SELECT id FROM users WHERE role='user' AND company_id=?", (company_id,))
        recipients = [u["id"] for u in cur.fetchall()]
    else:
        requested = [int(uid) for uid in user_ids]
        if company_id is None:
            recipients = requested
        else:
            placeholders = ",".join("?" for _ in requested) or "NULL"
            cur.execute(f"SELECT id FROM users WHERE company_id=? AND id IN ({placeholders})", (company_id, *requested))
            recipients = [r["id"] for r in cur.fetchall()]

    for uid in recipients:
        cur.execute("""
            INSERT INTO user_tasks (user_id,task_id,status)
            VALUES (?, ?, 'pending')
        """, (uid, task_id))

    # If no owner was set but we have recipients, set the first recipient as owner for display
    if owner_user_id is None and recipients:
        cur.execute("UPDATE tasks SET owner_user_id=? WHERE id=?", (recipients[0], task_id))

    # If global task, make sure all companies' users get it
    if company_id is None:
        _assign_tasks_for_company(cur, None)

    conn.commit()
    conn.close()


# Admin: user report with their tasks
def admin_get_user_report(user_id):
    """Return a user row and all their task rows for reporting."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return None, []

    cur.execute("""
        SELECT tasks.id,
               tasks.title,
               tasks.due_date,
               tasks.company_id,
               companies.name AS company_name,
               user_tasks.status,
               user_tasks.completed_at,
               user_tasks.answer_text,
               CASE
                   WHEN user_tasks.status != 'completed'
                        AND tasks.due_date IS NOT NULL AND tasks.due_date != ''
                        AND DATE(tasks.due_date) < DATE('now')
                   THEN 1
                   ELSE 0
               END AS overdue
        FROM tasks
        JOIN user_tasks ON tasks.id=user_tasks.task_id
        JOIN users ON users.id = user_tasks.user_id
        LEFT JOIN companies ON companies.id = tasks.company_id
        WHERE user_tasks.user_id=?
          AND (tasks.company_id = users.company_id OR tasks.company_id IS NULL)
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return user, rows


def _assign_tasks_for_company(cur, company_id=None):
    """Ensure tasks are assigned to users.

    - Global tasks (company_id NULL/0) -> all users or users in the given company.
    - Company tasks (company_id matches) -> users in that company.
    """
    # Prune mismatched assignments where a company-specific task is assigned to a user from another company.
    cur.execute("""
        DELETE FROM user_tasks
        WHERE id IN (
            SELECT ut.id
            FROM user_tasks ut
            JOIN tasks t ON t.id = ut.task_id
            JOIN users u ON u.id = ut.user_id
            WHERE t.company_id IS NOT NULL
              AND u.company_id IS NOT NULL
              AND t.company_id != u.company_id
              AND (? IS NULL OR t.company_id = ? OR u.company_id = ?)
        )
    """, (company_id, company_id, company_id))

    if company_id is None:
        # Global tasks to all users
        cur.execute("""
            INSERT INTO user_tasks (user_id, task_id, status)
            SELECT u.id, t.id, 'pending'
            FROM users u
            JOIN tasks t ON (t.company_id IS NULL OR t.company_id=0)
            LEFT JOIN user_tasks ut ON ut.user_id = u.id AND ut.task_id = t.id
            WHERE ut.id IS NULL
              AND u.role='user'
        """)
    else:
        # Global tasks to users in this company
        cur.execute("""
            INSERT INTO user_tasks (user_id, task_id, status)
            SELECT u.id, t.id, 'pending'
            FROM users u
            JOIN tasks t ON (t.company_id IS NULL OR t.company_id=0)
            LEFT JOIN user_tasks ut ON ut.user_id = u.id AND ut.task_id = t.id
            WHERE ut.id IS NULL
              AND u.role='user'
              AND u.company_id=?
        """, (company_id,))
        # Company-specific tasks to users in this company
        cur.execute("""
            INSERT INTO user_tasks (user_id, task_id, status)
            SELECT u.id, t.id, 'pending'
            FROM users u
            JOIN tasks t ON t.company_id = ?
            LEFT JOIN user_tasks ut ON ut.user_id = u.id AND ut.task_id = t.id
            WHERE ut.id IS NULL
              AND u.role='user'
              AND u.company_id=?
        """, (company_id, company_id))


# Admin: companies helpers
def admin_get_companies(show_inactive=False):
    """List companies (active by default; include inactive when requested)."""
    conn = get_connection()
    cur = conn.cursor()
    if show_inactive:
        cur.execute("SELECT * FROM companies ORDER BY name")
    else:
        cur.execute("SELECT * FROM companies WHERE is_active=1 ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    # Ensure dict access works uniformly
    return [dict(r) for r in rows]


def admin_get_company(company_id):
    """Get a single company row by id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id=?", (company_id,))
    row = cur.fetchone()
    conn.close()
    return row


def admin_create_company(name, address1=None, address2=None, address3=None, state=None, postcode=None, admin_user_id=None, is_active=1):
    """Insert a new company and optionally promote a user to company_admin."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO companies (name, address_line1, address_line2, address_line3, state, postcode, company_admin_id, is_active) VALUES (?,?,?,?,?,?,?,?)",
            (name, address1, address2, address3, state, postcode, admin_user_id, 1 if is_active else 0),
        )
        if admin_user_id:
            cur.execute("UPDATE users SET role='company_admin' WHERE id=?", (admin_user_id,))
        conn.commit()
        return None
    except sqlite3.IntegrityError:
        conn.rollback()
        return "Company name must be unique."
    finally:
        conn.close()


def admin_update_company(company_id, name, admin_user_id=None, address1=None, address2=None, address3=None, state=None, postcode=None, is_active=1):
    """Update company details and optionally assign a company admin."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Prevent inactivating a company that still has active users
        if not is_active:
            cur.execute("SELECT COUNT(*) FROM users WHERE company_id=? AND COALESCE(is_active,1)=1", (company_id,))
            active_users = cur.fetchone()[0]
            if active_users > 0:
                return "Cannot deactivate a company while it has active users."
        cur.execute("""
            UPDATE companies
            SET name=?, company_admin_id=?, address_line1=?, address_line2=?, address_line3=?, state=?, postcode=?, is_active=?
            WHERE id=?
        """, (name, admin_user_id, address1, address2, address3, state, postcode, 1 if is_active else 0, company_id))
        if admin_user_id:
            cur.execute("UPDATE users SET role='company_admin' WHERE id=?", (admin_user_id,))
        conn.commit()
        return None
    except sqlite3.IntegrityError:
        conn.rollback()
        return "Company name must be unique."
    finally:
        conn.close()

# Admin: task completion rollup (assignments)
def admin_task_completion_rollup(company_id=None):
    """Return per-task assignment counts (completed vs total); auto-fills any missing assignments first."""
    conn = get_connection()
    cur = conn.cursor()
    if company_id is None:
        _assign_tasks_for_company(cur, None)
        cur.execute("""
            SELECT ut.task_id,
                   SUM(CASE WHEN ut.status='completed' THEN 1 ELSE 0 END) as completed,
                   COUNT(*) as total
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            JOIN tasks t ON t.id = ut.task_id
            WHERE (t.company_id IS NULL OR t.company_id = u.company_id)
              AND LOWER(u.role) NOT IN ('admin','global admin')
              AND COALESCE(u.is_global_admin,0)=0
            GROUP BY ut.task_id
        """)
    else:
        _assign_tasks_for_company(cur, company_id)
        cur.execute("""
            SELECT ut.task_id,
                   SUM(CASE WHEN ut.status='completed' THEN 1 ELSE 0 END) as completed,
                   COUNT(*) as total
            FROM user_tasks ut
            JOIN users u ON u.id = ut.user_id
            JOIN tasks t ON t.id = ut.task_id
            WHERE u.company_id=?
              AND (t.company_id IS NULL OR t.company_id = u.company_id)
              AND LOWER(u.role) NOT IN ('admin','global admin')
              AND COALESCE(u.is_global_admin,0)=0
            GROUP BY ut.task_id
        """, (company_id,))
    rows = cur.fetchall()
    conn.close()
    return {row["task_id"]: {"completed": row["completed"], "total": row["total"]} for row in rows}
