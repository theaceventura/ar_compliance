"""Shared helpers for core dashboards and task views."""

from datetime import datetime
from typing import Any, Dict, Iterable, Tuple

DATE_FMT = "%d/%m/%Y"


def format_due_and_overdue(due_str: str, today_date) -> Tuple[bool, Any]:
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


def format_completed_on(completed_raw: str):
    """Return a formatted completed date string or the raw value."""
    if not completed_raw:
        return None
    try:
        completed_dt = datetime.fromisoformat(completed_raw)
        return completed_dt.strftime(DATE_FMT)
    except ValueError:
        return completed_raw


def tally(values: Iterable) -> Tuple[list, list]:
    """Convert a list of values into (labels, data) where None/empty become 'Unspecified'."""
    counts: Dict[str, int] = {}
    for val in values:
        key = val if val else "Unspecified"
        counts[key] = counts.get(key, 0) + 1
    labels = list(counts.keys())
    data = [counts[k] for k in labels]
    return labels, data


def parse_color_map(val: str) -> Dict[str, str]:
    """Convert a stored palette string like 'High:#f00,Low:#0f0' into a dict."""
    if not val:
        return {}
    mapping: Dict[str, str] = {}
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


def palette_for_labels(labels, fallback, stored_map):
    """Return a list of colors matching each label, using stored_map or fallback palette."""
    colors = []
    for idx, label in enumerate(labels):
        colors.append(stored_map.get(label, fallback[idx % len(fallback)]))
    return colors


def normalize_task_for_dashboard(task_row, comp_row, today_date):
    """Normalize a task row with rollup data for dashboards."""
    t = dict(task_row)
    comp = comp_row or {}
    assign_total = comp.get("total", 0)
    assign_completed = comp.get("completed", 0)
    assign_overdue = comp.get("overdue", 0)
    assign_pending = max(assign_total - assign_completed, 0)
    fully_completed = assign_total > 0 and assign_completed == assign_total
    completion_pct = round((assign_completed / assign_total) * 100, 1) if assign_total else 0

    overdue_raw = t.get("overdue", False)
    is_overdue_date, due_display = format_due_and_overdue(t.get("due_date"), today_date)

    company_label = t.get("company_name") if t.get("company_name") else "Global"

    base = {
        **t,
        "assign_total": assign_total,
        "assign_completed": assign_completed,
        "assign_overdue": assign_overdue,
        "assign_pending": assign_pending,
        "fully_completed": fully_completed,
        "completion_pct": completion_pct,
        "due_display": due_display,
        "overdue": bool((overdue_raw or is_overdue_date) and not fully_completed),
        "company_label": company_label,
    }
    return base
