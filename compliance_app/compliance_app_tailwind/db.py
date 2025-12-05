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
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            first_name TEXT,
            last_name TEXT,
            email TEXT,
            mobile TEXT,
            send_notifications INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            due_date TEXT,
            verification_question TEXT,
            verification_answer TEXT
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
            value TEXT UNIQUE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS severity_options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT UNIQUE
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version TEXT,
            show_version INTEGER DEFAULT 0,
            show_page_name INTEGER DEFAULT 0,
            show_module_tree INTEGER DEFAULT 0
        )
    """)
    if not _column_exists(cur, "app_settings", "show_module_tree"):
        cur.execute("ALTER TABLE app_settings ADD COLUMN show_module_tree INTEGER DEFAULT 0")
    cur.execute("SELECT 1 FROM app_settings WHERE id=1")
    if cur.fetchone() is None:
        cur.execute("INSERT INTO app_settings (id, version, show_version, show_page_name, show_module_tree) VALUES (1, '', 0, 0, 0)")

    # Create admin if not exists
    cur.execute("SELECT * FROM users WHERE username='admin'")
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO users (username,password,role,first_name,last_name,email,mobile,send_notifications) VALUES ('admin','secret','admin','','','','',0)"
        )

    # Seed default options
    cur.execute("SELECT COUNT(*) FROM impact_options")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO impact_options (value) VALUES (?)",
            [("Low",), ("Medium",), ("High",)],
        )
    cur.execute("SELECT COUNT(*) FROM severity_options")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO severity_options (value) VALUES (?)",
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
        WHERE user_tasks.user_id=?
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
        WHERE user_tasks.user_id=? AND tasks.id=?
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
def admin_get_summary_counts():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users WHERE role='user'")
    users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM tasks")
    tasks = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM user_tasks WHERE status='completed'")
    completed = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM user_tasks WHERE status='pending'")
    pending = cur.fetchone()[0]

    conn.close()
    return {
        "total_users": users,
        "total_tasks": tasks,
        "total_completed": completed,
        "total_pending": pending,
    }


# Admin: list users
def admin_get_all_users():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    return rows


def admin_get_user(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


# Admin: option lists (impact/severity)
def admin_get_options(opt_type):
    table = "impact_options" if opt_type == "impact" else "severity_options"
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table} ORDER BY value")
    rows = cur.fetchall()
    conn.close()
    return rows


def admin_add_option(opt_type, value):
    table = "impact_options" if opt_type == "impact" else "severity_options"
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(f"INSERT INTO {table} (value) VALUES (?)", (value,))
        conn.commit()
        return None
    except sqlite3.IntegrityError:
        conn.rollback()
        return "That option already exists."
    finally:
        conn.close()


# Admin: delete an option value
def admin_delete_option(opt_type, option_id):
    table = "impact_options" if opt_type == "impact" else "severity_options"
    conn = get_connection()
    cur = conn.cursor()
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
def admin_update_app_settings(version, show_version, show_page_name, show_module_tree):
    # Save version and UI toggle flags
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE app_settings
        SET version=?, show_version=?, show_page_name=?, show_module_tree=?
        WHERE id=1
    """, (version, 1 if show_version else 0, 1 if show_page_name else 0, 1 if show_module_tree else 0))
    conn.commit()
    conn.close()


# Admin: create user
def admin_create_user(username, password, role="user", first_name=None, last_name=None, email=None, mobile=None, send_notifications=False):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO users (username, password, role, first_name, last_name, email, mobile, send_notifications)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (username, password, role, first_name, last_name, email, mobile, 1 if send_notifications else 0),
        )
        user_id = cur.lastrowid

        # Assign existing tasks to the new user as pending
        cur.execute("SELECT id FROM tasks")
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
def admin_update_user(user_id, username, password, role, first_name, last_name, email, mobile, send_notifications):
    conn = get_connection()
    cur = conn.cursor()
    try:
        if password:
            cur.execute("""
                UPDATE users
                SET username=?, password=?, role=?, first_name=?, last_name=?, email=?, mobile=?, send_notifications=?
                WHERE id=?
            """, (username, password, role, first_name, last_name, email, mobile, 1 if send_notifications else 0, user_id))
        else:
            cur.execute("""
                UPDATE users
                SET username=?, role=?, first_name=?, last_name=?, email=?, mobile=?, send_notifications=?
                WHERE id=?
            """, (username, role, first_name, last_name, email, mobile, 1 if send_notifications else 0, user_id))
        conn.commit()
        return None
    except sqlite3.IntegrityError:
        conn.rollback()
        return "Username already exists."
    finally:
        conn.close()


# Admin: compliance counts per user (totals/completed)
def admin_user_compliance():
    # Get total/completed counts per user for summaries
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT users.id, users.username, users.role,
               COUNT(user_tasks.id) as total_tasks,
               SUM(CASE WHEN user_tasks.status='completed' THEN 1 ELSE 0 END) as completed_tasks
        FROM users
        LEFT JOIN user_tasks ON users.id = user_tasks.user_id
        GROUP BY users.id, users.username, users.role
        ORDER BY users.username
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


# Admin: list tasks (with owner)
def admin_get_all_tasks():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT tasks.*, users.username AS owner_username
        FROM tasks
        LEFT JOIN users ON tasks.owner_user_id = users.id
        ORDER BY due_date
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


# Admin: get single task
def admin_get_task(task_id):
    conn = get_connection()
    cur = conn.cursor()
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
def admin_update_task(task_id, title, description, due_date, impact, severity, owner_user_id, question, answer):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE tasks
        SET title=?, description=?, due_date=?, impact=?, severity=?, owner_user_id=?, verification_question=?, verification_answer=?
        WHERE id=?
    """, (title, description, due_date, impact, severity, owner_user_id, question, answer, task_id))
    conn.commit()
    conn.close()


# Admin: counts grouped by a column (impact/severity)
def admin_task_counts_by(column):
    if column not in ("impact", "severity"):
        return []
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"""
        SELECT COALESCE({column}, 'Unspecified') as label, COUNT(*) as count
        FROM tasks
        GROUP BY COALESCE({column}, 'Unspecified')
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


# Admin: create task and assign
def admin_create_task(title, description, due_date, impact, severity, owner_user_id, question, answer):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO tasks (title,description,due_date,impact,severity,owner_user_id,verification_question,verification_answer)
        VALUES (?,?,?,?,?,?,?,?)
    """, (title, description, due_date, impact, severity, owner_user_id, question, answer))

    task_id = cur.lastrowid

    # Assign to owner if provided, otherwise all users (backward compatible)
    if owner_user_id:
        cur.execute("""
            INSERT INTO user_tasks (user_id,task_id,status)
            VALUES (?, ?, 'pending')
        """, (owner_user_id, task_id))
    else:
        cur.execute("SELECT id FROM users WHERE role='user'")
        users = cur.fetchall()
        for u in users:
            cur.execute("""
                INSERT INTO user_tasks (user_id,task_id,status)
                VALUES (?, ?, 'pending')
            """, (u["id"], task_id))

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
               user_tasks.answer_text
        FROM tasks
        JOIN user_tasks ON tasks.id=user_tasks.task_id
        WHERE user_tasks.user_id=?
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return user, rows
