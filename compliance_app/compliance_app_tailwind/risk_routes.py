"""Risk matrix admin routes (optional extension)."""

from flask import Blueprint, render_template

from compliance_app.compliance_app_tailwind import db
from compliance_app.compliance_app_tailwind.auth_helpers import admin_required, current_user


def _parse_palette_row(settings_row, key):
    """Parse palette string (k:v comma separated) into dict."""
    if not settings_row:
        return {}
    val = settings_row[key] if key in settings_row.keys() else None
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


risk_bp = Blueprint("risk", __name__, url_prefix="/admin")


@risk_bp.route("/risk-config")
@admin_required
def admin_risk_config():
    """Risk matrix admin page: manage impact/severity options and colors."""
    admin = current_user()
    impacts = db.admin_get_options("impact", admin["company_id"])
    severities = db.admin_get_options("severity", admin["company_id"])
    settings_row = db.admin_get_app_settings()
    severity_colors = _parse_palette_row(settings_row, "severity_palette")
    impact_colors = _parse_palette_row(settings_row, "impact_palette")
    return render_template(
        "admin_risk_config.html",
        impacts=impacts,
        severities=severities,
        severity_colors=severity_colors,
        impact_colors=impact_colors,
        page_name="templates/admin_risk_config.html",
    )
