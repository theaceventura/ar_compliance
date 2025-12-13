from flask import Blueprint, render_template


ui_bp = Blueprint("ui", __name__, template_folder="templates", static_folder="static")


@ui_bp.route("/ui")
def ui_index():
    return render_template("index.html")
