import sqlite3
from datetime import datetime

DB_NAME = "compliance.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# Check if a column exists in a table (used for lightweight migrations)
def _column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())


# Ensure tables/columns exist and seed defaults
def create_tables_if_needed():
    conn = get_connection()
    cur = conn.cursor()

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

    if not _column_exists(cur, "tasks", "impact"):
        cur.execute("ALTER TABLE tasks ADD COLUMN impact TEXT")
    if not _column_exists(cur, "tasks", "severity"):
        cur.execute("ALTER TABLE tasks ADD COLUMN severity TEXT")
    if not _column_exists(cur, "tasks", "owner_user_id"):
        cur.execute("ALTER TABLE tasks ADD COLUMN owner_user_id INTEGER")
    if not _column_exists(cur, "users", "first_name"):
        cur.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
    if not _column_exists(cur, "users", "last_name"):
        cur.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
    if not _column_exists(cur, "users", "email"):
        cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if not _column_exists(cur, "users", "mobile"):
        cur.execute("ALTER TABLE users ADD COLUMN mobile TEXT")
    if not _column_exists(cur, "users", "send_notifications"):
        cur.execute("ALTER TABLE users ADD COLUMN send_notifications INTEGER DEFAULT 0")
    if not _column_exists(cur, "users", "company_id"):
        cur.execute("ALTER TABLE users ADD COLUMN company_id INTEGER")
        cur.execute("UPDATE users SET company_id=1 WHERE company_id IS NULL")
    if not _column_exists(cur, "tasks", "company_id"):
        cur.execute("ALTER TABLE tasks ADD COLUMN company_id INTEGER")
        cur.execute("UPDATE tasks SET company_id=1 WHERE company_id IS NULL")
    if not _column_exists(cur, "impact_options", "company_id"):
        cur.execute("ALTER TABLE impact_options ADD COLUMN company_id INTEGER")
        cur.execute("UPDATE impact_options SET company_id=1 WHERE company_id IS NULL")
    if not _column_exists(cur, "severity_options", "company_id"):
        cur.execute("ALTER TABLE severity_options ADD COLUMN company_id INTEGER")
        cur.execute("UPDATE severity_options SET company_id=1 WHERE company_id IS NULL")
    if not _column_exists(cur, "companies", "company_admin_id"):
        cur.execute("ALTER TABLE companies ADD COLUMN company_admin_id INTEGER")
    if not _column_exists(cur, "companies", "address_line1"):
        cur.execute("ALTER TABLE companies ADD COLUMN address_line1 TEXT")
    if not _column_exists(cur, "companies", "address_line2"):
        cur.execute("ALTER TABLE companies ADD COLUMN address_line2 TEXT")
    if not _column_exists(cur, "companies", "address_line3"):
        cur.execute("ALTER TABLE companies ADD COLUMN address_line3 TEXT")
    if not _column_exists(cur, "companies", "state"):
        cur.execute("ALTER TABLE companies ADD COLUMN state TEXT")
    if not _column_exists(cur, "companies", "postcode"):
        cur.execute("ALTER TABLE companies ADD COLUMN postcode TEXT")
    if not _column_exists(cur, "companies", "is_active"):
        cur.execute("ALTER TABLE companies ADD COLUMN is_active INTEGER DEFAULT 1")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version TEXT,
            show_version INTEGER DEFAULT 0,
            show_page_name INTEGER DEFAULT 0,
            show_module_tree INTEGER DEFAULT 0,
            show_cut_icon INTEGER DEFAULT 0,
            severity_palette TEXT,
            impact_palette TEXT,
            completion_palette TEXT
        )
    """)
    if not _column_exists(cur, "app_settings", "show_module_tree"):
        cur.execute("ALTER TABLE app_settings ADD COLUMN show_module_tree INTEGER DEFAULT 0")
    if not _column_exists(cur, "app_settings", "show_cut_icon"):
        cur.execute("ALTER TABLE app_settings ADD COLUMN show_cut_icon INTEGER DEFAULT 0")
    if not _column_exists(cur, "app_settings", "severity_palette"):
        cur.execute("ALTER TABLE app_settings ADD COLUMN severity_palette TEXT")
    if not _column_exists(cur, "app_settings", "impact_palette"):
        cur.execute("ALTER TABLE app_settings ADD COLUMN impact_palette TEXT")
    if not _column_exists(cur, "app_settings", "completion_palette"):
        cur.execute("ALTER TABLE app_settings ADD COLUMN completion_palette TEXT")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS task_field_descriptions (
            field TEXT PRIMARY KEY,
            description TEXT,
            is_required INTEGER DEFAULT 0
        )
    """)
    if not _column_exists(cur, "task_field_descriptions", "is_required"):
        cur.execute("ALTER TABLE task_field_descriptions ADD COLUMN is_required INTEGER DEFAULT 0")
    cur.execute("SELECT 1 FROM app_settings WHERE id=1")
    if cur.fetchone() is None:
        cur.execute("""
            INSERT INTO app_settings (id, version, show_version, show_page_name, show_module_tree, show_cut_icon, severity_palette, impact_palette, completion_palette)
            VALUES (1, '', 0, 0, 0, 0, '', '', '')
        """)
    # Seed default task field descriptions
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

    # Create default company if not exists
    cur.execute("SELECT id FROM companies WHERE id=1")
    if cur.fetchone() is None:
        cur.execute("INSERT INTO companies (id, name) VALUES (1, 'Default')")

    # Create admin if not exists
    cur.execute("SELECT * FROM users WHERE username='admin'")
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO users (username,password,role,first_name,last_name,email,mobile,send_notifications,company_id) VALUES ('admin','secret','admin','','','','',0,1)"
        )

    # Seed default options
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

    conn.commit()
    conn.close()

# Set a specific user's password (already hashed)
def set_user_password(user_id, hashed_password):
    # Update a user's password to a hashed value
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, user_id))
    conn.commit()
    conn.close()

# Look up a user by username
def get_user_by_username(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


# All tasks assigned to a user (with status)
def get_tasks_for_user(user_id):
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
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
        cur.execute("SELECT * FROM users WHERE company_id=? ORDER BY username", (company_id,))
    else:
        cur.execute("SELECT * FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    return rows


def admin_get_user(user_id, company_id=None):
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
    # Read the single row of app-level settings
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM app_settings WHERE id=1")
    row = cur.fetchone()
    conn.close()
    return row


# Admin: update app settings
def admin_update_app_settings(version, show_version, show_page_name, show_module_tree, show_cut_icon):
    # Save version and UI toggle flags
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE app_settings
        SET version=?, show_version=?, show_page_name=?, show_module_tree=?, show_cut_icon=?
        WHERE id=1
    """, (version, 1 if show_version else 0, 1 if show_page_name else 0, 1 if show_module_tree else 0, 1 if show_cut_icon else 0))
    conn.commit()
    conn.close()


# Admin: update chart palettes (CSV hex strings)
def admin_update_chart_palettes(severity_palette, impact_palette, completion_palette):
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
    return ",".join(f"{k}:{v}" for k, v in mapping.items())


def admin_set_option_color(opt_type, label, color_hex):
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
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO users (username, password, role, first_name, last_name, email, mobile, send_notifications, company_id, is_active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (username, password, role, first_name, last_name, email, mobile, 1 if send_notifications else 0, company_id, 1 if is_active else 0),
        )
        user_id = cur.lastrowid

        # Assign existing tasks to the new user as pending
        cur.execute("SELECT id FROM tasks WHERE company_id=?", (company_id,))
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
def admin_update_user(user_id, username, password, role, first_name, last_name, email, mobile, send_notifications, company_id=None, is_active=True):
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Prevent removing the last global admin
        if role != "admin":
            cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
            total_admins = cur.fetchone()[0]
            cur.execute("SELECT role FROM users WHERE id=?", (user_id,))
            current_role_row = cur.fetchone()
            current_role = current_role_row[0] if current_role_row else None
            if current_role == "admin" and total_admins <= 1:
                return "At least one global admin is required."
        if password:
            cur.execute("""
                UPDATE users
                SET username=?, password=?, role=?, first_name=?, last_name=?, email=?, mobile=?, send_notifications=?, is_active=? {company_clause}
                WHERE id=?
            """.format(company_clause=", company_id=?" if company_id is not None else ""),
            (username, password, role, first_name, last_name, email, mobile, 1 if send_notifications else 0, 1 if is_active else 0, company_id, user_id) if company_id is not None else (username, password, role, first_name, last_name, email, mobile, 1 if send_notifications else 0, 1 if is_active else 0, user_id))
        else:
            cur.execute("""
                UPDATE users
                SET username=?, role=?, first_name=?, last_name=?, email=?, mobile=?, send_notifications=?, is_active=? {company_clause}
                WHERE id=?
            """.format(company_clause=", company_id=?" if company_id is not None else ""),
            (username, role, first_name, last_name, email, mobile, 1 if send_notifications else 0, 1 if is_active else 0, company_id, user_id) if company_id is not None else (username, role, first_name, last_name, email, mobile, 1 if send_notifications else 0, 1 if is_active else 0, user_id))
        conn.commit()
        return None
    except sqlite3.IntegrityError:
        conn.rollback()
        return "Username already exists."
    finally:
        conn.close()


# Admin: compliance counts per user (totals/completed)
def admin_user_compliance(company_id):
    # Get total/completed counts per user for summaries
    conn = get_connection()
    cur = conn.cursor()
    if company_id is None:
        cur.execute("""
            SELECT users.id, users.username, users.role,
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
            GROUP BY users.id, users.username, users.role
            ORDER BY users.username
        """)
    else:
        cur.execute("""
            SELECT users.id, users.username, users.role,
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
              AND (tasks.company_id = users.company_id OR tasks.company_id IS NULL)
            GROUP BY users.id, users.username, users.role
            ORDER BY users.username
        """, (company_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


# Admin: list tasks (with assignment summary)
def admin_get_all_tasks(company_id=None):
    conn = get_connection()
    cur = conn.cursor()
    if company_id:
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
            WHERE (tasks.company_id=? OR tasks.company_id IS NULL)
              AND EXISTS (
                  SELECT 1 FROM user_tasks ut2
                  JOIN users uu ON uu.id = ut2.user_id
                  WHERE ut2.task_id = tasks.id AND uu.company_id = ?
              )
            ORDER BY due_date
        """, (company_id, company_id, company_id, company_id))
    else:
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
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE tasks
        SET title=?, description=?, due_date=?, impact=?, severity=?, owner_user_id=?, verification_question=?, verification_answer=?, company_id=?
        WHERE id=?
    """, (title, description, due_date, impact, severity, owner_user_id, question, answer, company_id, task_id))
    conn.commit()
    conn.close()


# Admin: counts grouped by a column (impact/severity)
def admin_task_counts_by(column, company_id=None):
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
    conn = get_connection()
    cur = conn.cursor()
    user_ids = user_ids or []

    cur.execute("""
        INSERT INTO tasks (title,description,due_date,impact,severity,owner_user_id,verification_question,verification_answer,company_id)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (title, description, due_date, impact, severity, owner_user_id, question, answer, company_id))

    task_id = cur.lastrowid

    # Decide recipients: explicit selection, assign-all, or fallback to all users in company
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

    conn.commit()
    conn.close()


# Admin: user report with their tasks
def admin_get_user_report(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return None, []

    cur.execute("""
        SELECT tasks.title, tasks.due_date, user_tasks.status, user_tasks.completed_at,
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
        WHERE user_tasks.user_id=?
          AND (tasks.company_id = users.company_id OR tasks.company_id IS NULL)
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return user, rows


# Admin: companies helpers
def admin_get_companies():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    return rows


def admin_get_company(company_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id=?", (company_id,))
    row = cur.fetchone()
    conn.close()
    return row


def admin_create_company(name, address1=None, address2=None, address3=None, state=None, postcode=None, admin_user_id=None, is_active=1):
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
    conn = get_connection()
    cur = conn.cursor()
    try:
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
