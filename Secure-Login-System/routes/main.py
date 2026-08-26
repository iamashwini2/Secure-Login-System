from flask import Blueprint, render_template, session, redirect, url_for

from models.user import db, User


# ============================================================
# MAIN BLUEPRINT
# ============================================================

main_bp = Blueprint(
    "main",
    __name__
)


# ============================================================
# HOME PAGE
# Endpoint: main.index
# URL: /
# ============================================================

@main_bp.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# DASHBOARD
# Endpoint: main.dashboard
# URL: /dashboard
# ============================================================

@main_bp.route("/dashboard")
def dashboard():

    # User must be logged in
    if "user_id" not in session:

        return redirect(
            url_for("auth.login")
        )

    # Get logged-in user's ID
    user_id = session.get("user_id")

    # Fetch user from database
    user = db.session.get(
        User,
        user_id
    )

    # If user no longer exists,
    # clear the session and return to login
    if user is None:

        session.clear()

        return redirect(
            url_for("auth.login")
        )

    return render_template(
        "dashboard.html",
        user=user
    )