from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from sqlalchemy import or_

import bcrypt
import re

from models.user import User, db
from models.two_factor import TwoFactorAuth


auth_bp = Blueprint("auth", __name__)


# ============================================================
# VALIDATION FUNCTIONS
# ============================================================

def validate_username(username):
    """
    Username requirements:
    - 3 to 50 characters
    - letters, numbers and underscore only
    """

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9_]{3,50}",
            username
        )
    )


def validate_email(email):
    """
    Basic email validation.
    """

    return bool(
        re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        )
    )


def validate_password(password):
    """
    Password requirements:
    - minimum 8 characters
    - uppercase letter
    - lowercase letter
    - number
    - special character
    """

    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"\d", password):
        return False

    if not re.search(r"[^\w\s]", password):
        return False

    return True


# ============================================================
# REGISTER
# ============================================================

@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # Required fields
        # ----------------------------------------------------

        if not username or not email or not password:

            flash(
                "All fields are required.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Username validation
        # ----------------------------------------------------

        if not validate_username(username):

            flash(
                "Username must contain only letters, numbers, and underscores, and be 3-50 characters long.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Email validation
        # ----------------------------------------------------

        if not validate_email(email):

            flash(
                "Please enter a valid email address.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Password validation
        # ----------------------------------------------------

        if not validate_password(password):

            flash(
                "Password must contain at least 8 characters, including uppercase, lowercase, number, and special character.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Check existing user
        # ----------------------------------------------------

        existing_user = db.session.execute(
            db.select(User).where(
                or_(
                    User.username == username,
                    User.email == email
                )
            )
        ).scalar_one_or_none()

        if existing_user:

            flash(
                "Username or email already exists.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # ----------------------------------------------------
        # Hash password using bcrypt
        # ----------------------------------------------------

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        # ----------------------------------------------------
        # Create user
        # ----------------------------------------------------

        user = User(
            username=username,
            email=email,
            password_hash=password_hash
        )

        db.session.add(user)
        db.session.commit()

        flash(
            "Registration successful. Please log in.",
            "success"
        )

        return redirect(
            url_for("auth.login")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # Basic validation
        # ----------------------------------------------------

        if not username or not password:

            flash(
                "Username and password are required.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # ----------------------------------------------------
        # Find user
        # ----------------------------------------------------

        user = db.session.execute(
            db.select(User).where(
                User.username == username
            )
        ).scalar_one_or_none()

        # ----------------------------------------------------
        # Verify password
        # ----------------------------------------------------

        if user and bcrypt.checkpw(
            password.encode("utf-8"),
            user.password_hash.encode("utf-8")
        ):

            # ------------------------------------------------
            # Clear old session
            # Prevent session fixation
            # ------------------------------------------------

            session.clear()

            # ------------------------------------------------
            # Create authenticated session
            # ------------------------------------------------

            session["user_id"] = user.id
            session["username"] = user.username

            # ------------------------------------------------
            # Check whether 2FA is enabled
            # ------------------------------------------------

            two_factor = db.session.execute(
                db.select(TwoFactorAuth).where(
                    TwoFactorAuth.user_id == user.id
                )
            ).scalar_one_or_none()

            # ------------------------------------------------
            # 2FA ENABLED
            # ------------------------------------------------

            if two_factor and two_factor.enabled:

                # User has authenticated with password,
                # but has NOT completed 2FA yet.

                session["two_factor_verified"] = False

                return redirect(
                    url_for("two_factor.verify")
                )

            # ------------------------------------------------
            # 2FA NOT ENABLED
            # ------------------------------------------------

            session["two_factor_verified"] = True

            return redirect(
                url_for("main.dashboard")
            )

        # ----------------------------------------------------
        # Invalid login
        # ----------------------------------------------------

        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template(
        "login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@auth_bp.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("auth.login")
    )