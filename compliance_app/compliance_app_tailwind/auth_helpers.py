"""Authentication/session helpers shared across routes and blueprints."""

from flask import redirect, session, url_for

ACCESS_DENIED = "Access denied"


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


def login_required(route_function):
    """Redirect to login if no session user is present."""
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper


def company_admin_required(route_function):
    """Allow only company_admin role; redirect to login otherwise."""
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None or user["role"] != "company_admin":
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper


def admin_required(route_function):
    """Allow only admin role; redirect or 403 otherwise."""
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            return ACCESS_DENIED, 403
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper
