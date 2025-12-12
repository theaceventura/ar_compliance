import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

# Anchor the database to the project root so it is consistent regardless of the
# working directory (e.g., when running from an IDE).
DB_NAME = str(Path(__file__).resolve().parents[2] / "compliance.db")


def get_connection():
    """Open a SQLite connection to the compliance database."""
    # Add a generous timeout and WAL to reduce "database is locked" errors
    conn = sqlite3.connect(DB_NAME, timeout=30.0)
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    conn.row_factory = sqlite3.Row
    return conn

def ensure_indexes():
    """Create helpful indexes if they do not exist (best-effort).

    Returns a dict with status and timestamp for logging.
    """
    conn = get_connection()
    cur = conn.cursor()
    ts = datetime.utcnow().isoformat()
    status = "ok"
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_cve_id ON threat_objects(cve_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_contrib_sources ON threat_objects(contrib_sources)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_source ON threat_objects(source)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_source_sev_pub ON threat_objects(source, severity, published_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_published ON threat_objects(published_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_updated ON threat_objects(updated_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_ingest_id ON threat_objects(ingest_id)")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_cve_id ON threat_objects(cve_id) WHERE cve_id IS NOT NULL")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_history_cve ON cve_history(cve_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_history_created_at ON cve_history(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ingest_runs_source ON ingest_runs(source)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ingest_runs_started ON ingest_runs(started_at)")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_feed_entry_unique ON threat_feed_entries(cve_id, source)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_feed_entry_source ON threat_feed_entries(source)")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_kev_cve ON cve_kev_enrichment(cve_id)")
        conn.commit()
        status = "created/exists"
    except Exception as exc:
        status = f"error: {exc}"
    finally:
        conn.close()
    return {"status": status, "checked_at": ts}

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
        CREATE TABLE IF NOT EXISTS threat_objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            item_type TEXT,
            cve_id TEXT,
            title TEXT,
            summary TEXT,
            link TEXT,
            published_at TEXT,
            last_modified_at TEXT,
            severity TEXT,
            cvss_version TEXT,
            cvss_vector TEXT,
            cvss_base_score REAL,
            cvss_av TEXT,
            cvss_ac TEXT,
            cvss_pr TEXT,
            cvss_ui TEXT,
            cvss_s TEXT,
            cvss_c TEXT,
            cvss_i TEXT,
            cvss_a TEXT,
            kev_flag INTEGER DEFAULT 0,
            exploit_status TEXT,
            products_text TEXT,
            vendor_refs TEXT,
            raw_payload TEXT,
            created_at TEXT,
            updated_at TEXT,
            is_enriched INTEGER DEFAULT 0,
            enriched_at TEXT,
            cwe_id TEXT,
            nvd_product_family TEXT,
            contrib_sources TEXT,
            ingest_id INTEGER
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
        # extended task metadata for question library/risk
        ("tasks", "question_type", "ALTER TABLE tasks ADD COLUMN question_type TEXT"),
        ("tasks", "response_options", "ALTER TABLE tasks ADD COLUMN response_options TEXT"),
        ("tasks", "impact_weight", "ALTER TABLE tasks ADD COLUMN impact_weight INTEGER"),
        ("tasks", "severity_weight", "ALTER TABLE tasks ADD COLUMN severity_weight INTEGER"),
        ("tasks", "risk_band", "ALTER TABLE tasks ADD COLUMN risk_band TEXT"),
        ("tasks", "domain", "ALTER TABLE tasks ADD COLUMN domain TEXT"),
        ("tasks", "alignment", "ALTER TABLE tasks ADD COLUMN alignment TEXT"),
        ("tasks", "acs_alignment", "ALTER TABLE tasks ADD COLUMN acs_alignment TEXT"),
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
        # threat objects table for threat ingestion
        ("threat_objects", "kev_flag", "ALTER TABLE threat_objects ADD COLUMN kev_flag INTEGER DEFAULT 0"),
        ("threat_objects", "products_text", "ALTER TABLE threat_objects ADD COLUMN products_text TEXT"),
        ("threat_objects", "raw_payload", "ALTER TABLE threat_objects ADD COLUMN raw_payload TEXT"),
        ("threat_objects", "created_at", "ALTER TABLE threat_objects ADD COLUMN created_at TEXT"),
        ("threat_objects", "updated_at", "ALTER TABLE threat_objects ADD COLUMN updated_at TEXT"),
        ("threat_objects", "is_enriched", "ALTER TABLE threat_objects ADD COLUMN is_enriched INTEGER DEFAULT 0"),
        ("threat_objects", "enriched_at", "ALTER TABLE threat_objects ADD COLUMN enriched_at TEXT"),
        ("threat_objects", "cvss_vector", "ALTER TABLE threat_objects ADD COLUMN cvss_vector TEXT"),
        ("threat_objects", "cvss_base_score", "ALTER TABLE threat_objects ADD COLUMN cvss_base_score REAL"),
        ("threat_objects", "cvss_version", "ALTER TABLE threat_objects ADD COLUMN cvss_version TEXT"),
        ("threat_objects", "cvss_av", "ALTER TABLE threat_objects ADD COLUMN cvss_av TEXT"),
        ("threat_objects", "cvss_ac", "ALTER TABLE threat_objects ADD COLUMN cvss_ac TEXT"),
        ("threat_objects", "cvss_pr", "ALTER TABLE threat_objects ADD COLUMN cvss_pr TEXT"),
        ("threat_objects", "cvss_ui", "ALTER TABLE threat_objects ADD COLUMN cvss_ui TEXT"),
        ("threat_objects", "cvss_s", "ALTER TABLE threat_objects ADD COLUMN cvss_s TEXT"),
        ("threat_objects", "cvss_c", "ALTER TABLE threat_objects ADD COLUMN cvss_c TEXT"),
        ("threat_objects", "cvss_i", "ALTER TABLE threat_objects ADD COLUMN cvss_i TEXT"),
        ("threat_objects", "cvss_a", "ALTER TABLE threat_objects ADD COLUMN cvss_a TEXT"),
        ("threat_objects", "last_modified_at", "ALTER TABLE threat_objects ADD COLUMN last_modified_at TEXT"),
        ("threat_objects", "exploit_status", "ALTER TABLE threat_objects ADD COLUMN exploit_status TEXT"),
        ("threat_objects", "vendor_refs", "ALTER TABLE threat_objects ADD COLUMN vendor_refs TEXT"),
        ("threat_objects", "cwe_id", "ALTER TABLE threat_objects ADD COLUMN cwe_id TEXT"),
        ("threat_objects", "cvss_vector", "ALTER TABLE threat_objects ADD COLUMN cvss_vector TEXT"),
        ("threat_objects", "cvss_base_score", "ALTER TABLE threat_objects ADD COLUMN cvss_base_score REAL"),
        ("threat_objects", "nvd_product_family", "ALTER TABLE threat_objects ADD COLUMN nvd_product_family TEXT"),
        ("threat_objects", "contrib_sources", "ALTER TABLE threat_objects ADD COLUMN contrib_sources TEXT"),
        ("threat_objects", "ingest_id", "ALTER TABLE threat_objects ADD COLUMN ingest_id INTEGER"),
        ("cve_kev_enrichment", "kev_required_action", "ALTER TABLE cve_kev_enrichment ADD COLUMN kev_required_action TEXT"),
    ]

    for item in migrations:
        table, column, ddl = item[0], item[1], item[2]
        if not _column_exists(cur, table, column):
            cur.execute(ddl)
            # optional follow-up SQL provided as 4th element
            if len(item) > 3:
                cur.execute(item[3])

    # CVE history table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cve_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            source TEXT,
            action TEXT,
            changed_fields TEXT,
            raw_payload TEXT,
            created_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            started_at TEXT,
            finished_at TEXT,
            status TEXT,
            message TEXT,
            inserted INTEGER,
            updated INTEGER,
            config_snapshot TEXT
        )
        """
    )
    # Feed entries (secondary source payloads) unique by (cve_id, source)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_feed_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            source TEXT,
            products_text TEXT,
            kev_flag INTEGER DEFAULT 0,
            raw_payload TEXT,
            ingest_id INTEGER,
            fetched_at TEXT,
            status TEXT,
            message TEXT,
            UNIQUE(cve_id, source)
        )
        """
    )
    # KEV enrichment table (one row per CVE)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cve_kev_enrichment (
            cve_id TEXT PRIMARY KEY,
            kev_date_added TEXT,
            kev_due_date TEXT,
            kev_description TEXT,
            kev_vendor TEXT,
            kev_product TEXT,
            kev_action_required INTEGER DEFAULT 0,
            kev_required_action TEXT,
            kev_source_url TEXT,
            known_exploited INTEGER DEFAULT 1,
            raw_payload TEXT,
            fetched_at TEXT,
            ingest_id INTEGER
        )
        """
    )
    # MSRC enrichment table (one row per CVE)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cve_msrc_enrichment (
            cve_id TEXT PRIMARY KEY,
            msrc_release_id TEXT,
            msrc_release_title TEXT,
            msrc_initial_release_utc TEXT,
            msrc_current_release_utc TEXT,
            msrc_cvrf_url TEXT,
            msrc_title TEXT,
            msrc_threat_category TEXT,
            msrc_customer_action_required INTEGER DEFAULT 0,
            msrc_publicly_disclosed INTEGER DEFAULT 0,
            msrc_exploited INTEGER DEFAULT 0,
            msrc_exploitability_assessment TEXT,
            msrc_cvss_base_score REAL,
            msrc_cvss_temporal_score REAL,
            msrc_cvss_vector TEXT,
            msrc_affected_products TEXT,
            msrc_fixed_build TEXT,
            msrc_remediation_urls TEXT,
            msrc_summary_text TEXT,
            last_seen_utc TEXT,
            ingest_id INTEGER
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_msrc_enrich_cve ON cve_msrc_enrichment(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_msrc_enrich_seen ON cve_msrc_enrichment(last_seen_utc)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            started_at TEXT,
            finished_at TEXT,
            status TEXT,
            message TEXT,
            inserted INTEGER,
            updated INTEGER,
            config_snapshot TEXT
        )
        """
    )


def _ensure_app_settings(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            app_name TEXT,
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
        ("app_name", "ALTER TABLE app_settings ADD COLUMN app_name TEXT"),
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
            INSERT INTO app_settings (id, app_name, version, show_version, show_page_name, show_module_tree, show_cut_icon, show_label_edit, show_task_charts, show_risk_matrix, show_user_banner, show_user_charts_global, show_user_charts_company, show_user_charts_user, show_validation_notes, severity_palette, impact_palette, completion_palette)
            VALUES (1, 'Compliance Tracker', '', 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, '', '', '')
        """)
    else:
        cur.execute("""
            UPDATE app_settings
            SET app_name = COALESCE(app_name, 'Compliance Tracker'),
                show_user_charts_global = COALESCE(show_user_charts_global, 1),
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
    _seed_threat_table_defaults(cur)

    conn.commit()
    conn.close()

# Threat ingestion helpers
def _seed_threat_table_defaults(cur):
    """Ensure the threat_objects table exists (legacy safety)."""
    cur.execute("""
        CREATE TABLE IF NOT EXISTS threat_objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            item_type TEXT,
            cve_id TEXT,
            title TEXT,
            summary TEXT,
            link TEXT,
            published_at TEXT,
            severity TEXT,
            kev_flag INTEGER DEFAULT 0,
            products_text TEXT,
            raw_payload TEXT,
            created_at TEXT
        )
    """)

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
        SELECT tasks.*,
               user_tasks.status,
               user_tasks.answer_text,
               user_tasks.completed_at,
               tasks.verification_answer,
               users.username AS assigned_username,
               users.first_name AS assigned_first_name,
               users.last_name AS assigned_last_name
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

def admin_get_all_users_any(company_id=None):
    """Return all users including admins, optionally filtered to a company."""
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
    return dict(row) if row else {}


# Admin: update app settings
def admin_update_app_settings(app_name, version, show_version, show_page_name, show_module_tree, show_cut_icon, show_label_edit, show_task_charts, show_risk_matrix, show_user_banner, show_user_charts_global, show_user_charts_company, show_user_charts_user, show_validation_notes):
    """Persist the main app setting flags and version string."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE app_settings
        SET app_name=?, version=?, show_version=?, show_page_name=?, show_module_tree=?, show_cut_icon=?, show_label_edit=?, show_task_charts=?, show_risk_matrix=?, show_user_banner=?, show_user_charts_global=?, show_user_charts_company=?, show_user_charts_user=?, show_validation_notes=?
        WHERE id=1
    """, (
        app_name.strip() if app_name is not None else "",
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

# Threat queries
def admin_list_threats(source=None, q=None, severity=None, kev_filter=None):
    """Return a list of threat_objects filtered by source, severity, kev_flag, and optional search term."""
    conn = get_connection()
    cur = conn.cursor()
    base = "SELECT * FROM threat_objects WHERE 1=1"
    params = []
    if source:
        base += " AND source=?"
        params.append(source)
    if severity:
        base += " AND LOWER(severity)=LOWER(?)"
        params.append(severity)
    if kev_filter:
        if kev_filter == "yes":
            base += " AND kev_flag=1"
        elif kev_filter == "no":
            base += " AND (kev_flag IS NULL OR kev_flag=0)"
    if q:
        like = f"%{q}%"
        base += " AND (title LIKE ? OR summary LIKE ? OR cve_id LIKE ?)"
        params.extend([like, like, like])
    base += " ORDER BY published_at DESC"
    cur.execute(base, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def admin_threat_stats(sources=None):
    """Return counts and last ingested timestamps per source."""
    conn = get_connection()
    cur = conn.cursor()
    stats = {}
    source_filter = ""
    params = []
    if sources:
        placeholders = ",".join("?" for _ in sources)
        source_filter = f" WHERE source IN ({placeholders})"
        params = list(sources)
    cur.execute(
        f"""
        SELECT source, COUNT(*) as cnt, MAX(created_at) as last_created
        FROM threat_objects
        {source_filter}
        GROUP BY source
        """,
        params,
    )
    for row in cur.fetchall():
        stats[row["source"]] = {
            "count": row["cnt"],
            "last_created": row["last_created"],
        }
    conn.close()
    return stats

def admin_threat_summary(sources):
    """Return counts and last ingested timestamps plus time-bucket counts per source."""
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)
    summary = {}
    for src in sources:
        # overall count and last created
        cur.execute(
            """
            SELECT
                COUNT(*) as cnt,
                MAX(created_at) as last_created,
                MAX(COALESCE(updated_at, created_at)) as last_activity
            FROM threat_objects WHERE source=?
            """,
            (src,),
        )
        row = cur.fetchone()
        row = dict(row) if row else {}
        total = row.get("cnt") or 0
        last_created = row.get("last_created")
        last_activity = row.get("last_activity")
        # buckets
        cur.execute(
            """
            SELECT
                SUM(COALESCE(updated_at, created_at) >= ?) AS today_cnt,
                SUM(COALESCE(updated_at, created_at) >= ?) AS week_cnt,
                SUM(COALESCE(updated_at, created_at) >= ?) AS month_cnt
            FROM threat_objects
            WHERE source=?
            """,
            (
                today_start.isoformat(),
                week_start.isoformat(),
                month_start.isoformat(),
                src,
            ),
        )
        buckets = cur.fetchone()
        buckets = dict(buckets) if buckets else {}
        summary[src] = {
            "count": total,
            "last_created": last_created,
            "last_activity": last_activity,
            "today": buckets.get("today_cnt") or 0,
            "week": buckets.get("week_cnt") or 0,
            "month": buckets.get("month_cnt") or 0,
        }
    conn.close()
    return summary


def admin_feed_entry_counts(sources):
    """Return counts of stored feed entries for given sources."""
    conn = get_connection()
    cur = conn.cursor()
    out = {}
    for src in sources:
        cur.execute("SELECT COUNT(*) as cnt FROM threat_feed_entries WHERE source=?", (src,))
        row = cur.fetchone()
        out[src] = row["cnt"] if row and "cnt" in row.keys() else 0
    conn.close()
    return out

def admin_threat_recent_counts(sources, days=7):
    """Return counts of new and updated threats per source within the last `days`."""
    conn = get_connection()
    cur = conn.cursor()
    cutoff = datetime.utcnow() - timedelta(days=days)
    cutoff_iso = cutoff.isoformat()
    out = {}
    for src in sources:
        cur.execute(
            """
            SELECT
                SUM(created_at >= ?) AS new_cnt,
                SUM(
                    created_at IS NOT NULL
                    AND updated_at IS NOT NULL
                    AND updated_at > created_at
                    AND updated_at >= ?
                ) AS updated_cnt
            FROM threat_objects
            WHERE source=?
            """,
            (cutoff_iso, cutoff_iso, src),
        )
        row = cur.fetchone()
        row = dict(row) if row else {}
        out[src] = {
            "new": row.get("new_cnt") or 0,
            "updated": row.get("updated_cnt") or 0,
        }
    conn.close()
    return out


# Ingest run helpers
def start_ingest_run(source, status="running", message=None, config_snapshot=None):
    conn = get_connection()
    cur = conn.cursor()
    started = datetime.utcnow().isoformat()
    cur.execute(
        """
        INSERT INTO ingest_runs (source, started_at, status, message, config_snapshot)
        VALUES (?, ?, ?, ?, ?)
        """,
        (source, started, status, message, json.dumps(config_snapshot) if config_snapshot is not None else None),
    )
    run_id = cur.lastrowid
    conn.commit()
    conn.close()
    return run_id


def finish_ingest_run(run_id, status="completed", inserted=0, updated=0, message=None):
    if not run_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    finished = datetime.utcnow().isoformat()
    cur.execute(
        """
        UPDATE ingest_runs
        SET finished_at=?, status=?, inserted=?, updated=?, message=?
        WHERE id=?
        """,
        (finished, status, inserted, updated, message, run_id),
    )
    conn.commit()
    conn.close()


def get_ingest_runs(source, limit=10):
    """Return recent ingest_runs for a source."""
    conn = get_connection()
    cur = conn.cursor()
    src = (source or "").upper()
    cur.execute(
        """
        SELECT * FROM ingest_runs
        WHERE UPPER(source)=?
        ORDER BY datetime(started_at) DESC
        LIMIT ?
        """,
        (src, limit),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def rollback_last_ingest(source):
    """Delete rows created in the last ingest for this source (inserts only)."""
    conn = get_connection()
    cur = conn.cursor()
    src = (source or "").upper()
    cur.execute(
        """
        SELECT * FROM ingest_runs
        WHERE UPPER(source)=?
        ORDER BY datetime(started_at) DESC
        LIMIT 1
        """,
        (src,),
    )
    run = cur.fetchone()
    if not run:
        conn.close()
        return 0, None
    run_id = run["id"]
    # Only delete rows that were inserted in that ingest (updated_at == created_at)
    cur.execute(
        """
        DELETE FROM threat_objects
        WHERE ingest_id=? AND (updated_at IS NULL OR updated_at = created_at)
        """,
        (run_id,),
    )
    deleted = cur.rowcount
    cur.execute(
        """
        UPDATE ingest_runs
        SET finished_at=?, status=?, message=?
        WHERE id=?
        """,
        (
            datetime.utcnow().isoformat(),
            "rolled_back",
            f"Rolled back {deleted} inserted rows",
            run_id,
        ),
    )
    conn.commit()
    conn.close()
    return deleted, dict(run)


# Feed entry helpers
def upsert_feed_entry(cve_id, source, *, products_text=None, kev_flag=False, raw_payload=None, ingest_id=None, status=None, message=None):
    if not source or not cve_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute(
        """
        INSERT INTO threat_feed_entries (cve_id, source, products_text, kev_flag, raw_payload, ingest_id, fetched_at, status, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id, source) DO UPDATE SET
            products_text=excluded.products_text,
            kev_flag=excluded.kev_flag,
            raw_payload=excluded.raw_payload,
            ingest_id=excluded.ingest_id,
            fetched_at=excluded.fetched_at,
            status=excluded.status,
            message=excluded.message
        """,
        (
            cve_id,
            source,
            products_text,
            1 if kev_flag else 0,
            raw_payload,
            ingest_id,
            now,
            status,
            message,
        ),
    )
    conn.commit()
    conn.close()


def get_feed_entries_by_cve(cve_id):
    """Return all feed entries for a given CVE."""
    if not cve_id:
        return []
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM threat_feed_entries
        WHERE cve_id=?
        ORDER BY datetime(fetched_at) DESC
        """,
        (cve_id,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def upsert_kev_enrichment(
    cve_id,
    *,
    kev_date_added=None,
    kev_due_date=None,
    kev_description=None,
    kev_vendor=None,
    kev_product=None,
    kev_action_required=False,
    kev_required_action=None,
    kev_source_url=None,
    known_exploited=True,
    raw_payload=None,
    ingest_id=None,
):
    """Upsert KEV enrichment data for a CVE."""
    if not cve_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute(
        """
        INSERT INTO cve_kev_enrichment (
            cve_id, kev_date_added, kev_due_date, kev_description, kev_vendor, kev_product,
            kev_action_required, kev_required_action, kev_source_url, known_exploited, raw_payload, fetched_at, ingest_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            kev_date_added=excluded.kev_date_added,
            kev_due_date=excluded.kev_due_date,
            kev_description=excluded.kev_description,
            kev_vendor=excluded.kev_vendor,
            kev_product=excluded.kev_product,
            kev_action_required=excluded.kev_action_required,
            kev_required_action=excluded.kev_required_action,
            kev_source_url=excluded.kev_source_url,
            known_exploited=excluded.known_exploited,
            raw_payload=excluded.raw_payload,
            fetched_at=excluded.fetched_at,
            ingest_id=excluded.ingest_id
        """,
        (
            cve_id,
            kev_date_added,
            kev_due_date,
            kev_description,
            kev_vendor,
            kev_product,
            1 if kev_action_required else 0,
            kev_required_action,
            kev_source_url,
            1 if known_exploited else 0,
            raw_payload,
            now,
            ingest_id,
        ),
    )
    conn.commit()
    conn.close()


def get_kev_enrichment(cve_id):
    """Return KEV enrichment for a CVE."""
    if not cve_id:
        return None
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cve_kev_enrichment WHERE cve_id=?", (cve_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# Ingest run helpers
def start_ingest_run(source, status="running", message=None, config_snapshot=None):
    conn = get_connection()
    cur = conn.cursor()
    started = datetime.utcnow().isoformat()
    cur.execute(
        """
        INSERT INTO ingest_runs (source, started_at, status, message, config_snapshot)
        VALUES (?, ?, ?, ?, ?)
        """,
        (source, started, status, message, json.dumps(config_snapshot) if config_snapshot is not None else None),
    )
    run_id = cur.lastrowid
    conn.commit()
    conn.close()
    return run_id


def finish_ingest_run(run_id, status="completed", inserted=0, updated=0, message=None):
    if not run_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    finished = datetime.utcnow().isoformat()
    cur.execute(
        """
        UPDATE ingest_runs
        SET finished_at=?, status=?, inserted=?, updated=?, message=?
        WHERE id=?
        """,
        (finished, status, inserted, updated, message, run_id),
    )
    conn.commit()
    conn.close()

def admin_get_threat(threat_id):
    """Return a single threat_object by id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threat_objects WHERE id=?", (threat_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def admin_get_threat_by_cve(cve_id):
    """Return a single threat_object by CVE (prefers NVD)."""
    if not cve_id:
        return None
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM threat_objects
        WHERE UPPER(cve_id)=?
        ORDER BY CASE source WHEN 'NVD' THEN 0 ELSE 1 END, datetime(COALESCE(updated_at, created_at)) DESC
        LIMIT 1
        """,
        ((cve_id or "").upper(),),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def admin_delete_threats_by_source(source):
    """Delete all threat_objects for a given source (for testing). Returns count deleted."""
    if not source:
        return 0
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM threat_objects WHERE source=?", (source,))
    row = cur.fetchone()
    count = row["cnt"] if row else 0
    cur.execute("DELETE FROM threat_objects WHERE source=?", (source,))
    conn.commit()
    conn.close()
    return count


def admin_delete_feed_entries_by_source(source):
    """Delete stored feed entries for a given source. Returns count deleted."""
    if not source:
        return 0
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM threat_feed_entries WHERE source=?", (source,))
    row = cur.fetchone()
    count = row["cnt"] if row else 0
    cur.execute("DELETE FROM threat_feed_entries WHERE source=?", (source,))
    conn.commit()
    conn.close()
    return count


def admin_delete_kev_enrichment():
    """Delete all KEV enrichment rows."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM cve_kev_enrichment")
    row = cur.fetchone()
    count = row["cnt"] if row else 0
    cur.execute("DELETE FROM cve_kev_enrichment")
    conn.commit()
    conn.close()
    return count

def count_nvd_with_feed(feed_source):
    """Count NVD CVEs that have a corresponding feed entry for the given source."""
    if not feed_source:
        return 0
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COUNT(*) as cnt
        FROM threat_objects t
        WHERE t.source='NVD'
        AND EXISTS (
            SELECT 1 FROM threat_feed_entries f
            WHERE f.source=? AND UPPER(f.cve_id)=UPPER(t.cve_id)
        )
        """,
        (feed_source,),
    )
    row = cur.fetchone()
    conn.close()
    return row["cnt"] if row else 0


def upsert_msrc_enrichment(
    cve_id,
    *,
    msrc_release_id=None,
    msrc_release_title=None,
    msrc_initial_release_utc=None,
    msrc_current_release_utc=None,
    msrc_cvrf_url=None,
    msrc_title=None,
    msrc_threat_category=None,
    msrc_customer_action_required=False,
    msrc_publicly_disclosed=False,
    msrc_exploited=False,
    msrc_exploitability_assessment=None,
    msrc_cvss_base_score=None,
    msrc_cvss_temporal_score=None,
    msrc_cvss_vector=None,
    msrc_affected_products=None,
    msrc_fixed_build=None,
    msrc_remediation_urls=None,
    msrc_summary_text=None,
    last_seen_utc=None,
    ingest_id=None,
):
    """Upsert MSRC enrichment data for a CVE."""
    if not cve_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cve_msrc_enrichment (
            cve_id,
            msrc_release_id,
            msrc_release_title,
            msrc_initial_release_utc,
            msrc_current_release_utc,
            msrc_cvrf_url,
            msrc_title,
            msrc_threat_category,
            msrc_customer_action_required,
            msrc_publicly_disclosed,
            msrc_exploited,
            msrc_exploitability_assessment,
            msrc_cvss_base_score,
            msrc_cvss_temporal_score,
            msrc_cvss_vector,
            msrc_affected_products,
            msrc_fixed_build,
            msrc_remediation_urls,
            msrc_summary_text,
            last_seen_utc,
            ingest_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            msrc_release_id=excluded.msrc_release_id,
            msrc_release_title=excluded.msrc_release_title,
            msrc_initial_release_utc=excluded.msrc_initial_release_utc,
            msrc_current_release_utc=excluded.msrc_current_release_utc,
            msrc_cvrf_url=excluded.msrc_cvrf_url,
            msrc_title=excluded.msrc_title,
            msrc_threat_category=excluded.msrc_threat_category,
            msrc_customer_action_required=excluded.msrc_customer_action_required,
            msrc_publicly_disclosed=excluded.msrc_publicly_disclosed,
            msrc_exploited=excluded.msrc_exploited,
            msrc_exploitability_assessment=excluded.msrc_exploitability_assessment,
            msrc_cvss_base_score=excluded.msrc_cvss_base_score,
            msrc_cvss_temporal_score=excluded.msrc_cvss_temporal_score,
            msrc_cvss_vector=excluded.msrc_cvss_vector,
            msrc_affected_products=excluded.msrc_affected_products,
            msrc_fixed_build=excluded.msrc_fixed_build,
            msrc_remediation_urls=excluded.msrc_remediation_urls,
            msrc_summary_text=excluded.msrc_summary_text,
            last_seen_utc=excluded.last_seen_utc,
            ingest_id=excluded.ingest_id
        """,
        (
            cve_id,
            msrc_release_id,
            msrc_release_title,
            msrc_initial_release_utc,
            msrc_current_release_utc,
            msrc_cvrf_url,
            msrc_title,
            msrc_threat_category,
            1 if msrc_customer_action_required else 0,
            1 if msrc_publicly_disclosed else 0,
            1 if msrc_exploited else 0,
            msrc_exploitability_assessment,
            msrc_cvss_base_score,
            msrc_cvss_temporal_score,
            msrc_cvss_vector,
            msrc_affected_products,
            msrc_fixed_build,
            msrc_remediation_urls,
            msrc_summary_text,
            last_seen_utc,
            ingest_id,
        ),
    )
    conn.commit()
    conn.close()


def get_msrc_enrichment(cve_id):
    """Return MSRC enrichment for a CVE."""
    if not cve_id:
        return None
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cve_msrc_enrichment WHERE cve_id=?", (cve_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# Enrichment helpers
def get_threats_by_source(source):
    """Return all threat_objects for a given source as a list of dicts."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threat_objects WHERE source=?", (source,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def insert_cve_history(cve_id, source, action, changed_fields=None, raw_payload=None):
    """Record a history entry for a CVE."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cve_history (cve_id, source, action, changed_fields, raw_payload, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (cve_id, source, action, changed_fields, raw_payload, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_cve_history(cve_id):
    """Return history entries for a CVE ordered by newest first."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM cve_history
        WHERE cve_id=?
        ORDER BY created_at DESC
        """,
        (cve_id,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_nvd_threat_by_cve(cve_id):
    """Return the most recent NVD threat for a CVE, or None."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM threat_objects
        WHERE source='NVD' AND cve_id=?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (cve_id,),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def update_nvd_threat_for_enrichment(threat_id, *, kev_flag=None, merged_raw_payload=None, products_text=None):
    """Update selected fields on an NVD threat for enrichment."""
    sets = []
    params = []
    if kev_flag is not None:
        sets.append("kev_flag=?")
        params.append(1 if kev_flag else 0)
    if merged_raw_payload is not None:
        sets.append("raw_payload=?")
        params.append(merged_raw_payload)
    if products_text is not None:
        sets.append("products_text=?")
        params.append(products_text)
    # mark enrichment
    sets.append("is_enriched=?")
    params.append(1)
    sets.append("enriched_at=?")
    params.append(datetime.utcnow().isoformat())
    sets.append("updated_at=?")
    params.append(datetime.utcnow().isoformat())
    if not sets:
        return
    params.append(threat_id)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"UPDATE threat_objects SET {', '.join(sets)} WHERE id=?", params)
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
               users.username AS assigned_username,
               users.first_name AS assigned_first_name,
               users.last_name AS assigned_last_name,
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
