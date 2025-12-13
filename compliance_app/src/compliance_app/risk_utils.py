"""Risk matrix helpers used by dashboards and the optional risk admin module."""

def build_risk_matrix(task_list, severity_order=None, impact_order=None, severity_sort=True):
    """Aggregate tasks into a severity x impact count matrix for the risk view."""
    severities = []
    impacts = []
    for t in task_list:
        sev = t.get("severity") or "Unspecified"
        imp = t.get("impact") or "Unspecified"
        if sev not in severities:
            severities.append(sev)
        if imp not in impacts:
            impacts.append(imp)
    if severity_order is None:
        severity_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    if impact_order is None:
        impact_order = {"Low": 0, "Medium": 1, "High": 2}
    if severity_sort:
        severities_sorted = sorted(severities, key=lambda v: (-severity_order.get(v, -1), v))
    else:
        severities_sorted = sorted(severities)
    impacts_sorted = sorted(impacts, key=lambda v: (impact_order.get(v, len(impact_order)), v))
    counts = {}
    for sev in severities_sorted:
        counts[sev] = dict.fromkeys(impacts_sorted, 0)
    for t in task_list:
        sev = t.get("severity") or "Unspecified"
        imp = t.get("impact") or "Unspecified"
        counts.setdefault(sev, dict.fromkeys(impacts_sorted, 0))
        counts[sev].setdefault(imp, 0)
        counts[sev][imp] += 1
    return {
        "severity_labels": severities_sorted,
        "impact_labels": impacts_sorted,
        "severity_ranks": {k: severity_order.get(k, 0) for k in severities_sorted},
        "impact_ranks": {k: impact_order.get(k, 0) for k in impacts_sorted},
        "counts": counts,
    }
