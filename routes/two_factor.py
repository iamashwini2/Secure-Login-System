from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import io
import base64
import pyotp
import qrcode

from models.user import User, db
from models.two_factor import TwoFactorAuth


two_factor_bp = Blueprint(
    "two_factor",
    __name__,
    url_prefix="/2fa"
)


# ============================================================
# HELPER — CHECK LOGIN
# ============================================================

def is_logged_in():
    """
    Check whether the user is authenticated.
    """

    return "user_id" in session


# ============================================================
# 2FA SETUP
# ============================================================

@two_factor_bp.route("/setup", methods=["GET", "POST"])
def setup():

    # --------------------------------------------------------
    # Require login
    # --------------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("auth.login")
        )

    user_id = session.get("user_id")

    # --------------------------------------------------------
    # Get user
    # --------------------------------------------------------

    user = db.session.get(
        User,
        user_id
    )

    if not user:

        session.clear()

        flash(
            "User account could not be found.",
            "danger"
        )

        return redirect(
            url_for("auth.login")
        )

    # --------------------------------------------------------
    # Check existing 2FA
    # --------------------------------------------------------

    two_factor = db.session.execute(
        db.select(TwoFactorAuth).where(
            TwoFactorAuth.user_id == user.id
        )
    ).scalar_one_or_none()

    # --------------------------------------------------------
    # If already enabled
    # --------------------------------------------------------

    if two_factor and two_factor.enabled:

        session["two_factor_enabled"] = True

        flash(
            "Two-factor authentication is already enabled.",
            "success"
        )

        return redirect(
            url_for("main.dashboard")
        )

    # --------------------------------------------------------
    # Generate secret if needed
    # --------------------------------------------------------

    if not two_factor:

        secret = pyotp.random_base32()

        two_factor = TwoFactorAuth(
            user_id=user.id,
            secret=secret,
            enabled=False
        )

        db.session.add(two_factor)

        db.session.commit()

    else:

        secret = two_factor.secret

    # --------------------------------------------------------
    # Create TOTP provisioning URI
    # --------------------------------------------------------

    totp = pyotp.TOTP(secret)

    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="SecureAuth"
    )

    # --------------------------------------------------------
    # Generate QR code
    # --------------------------------------------------------

    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4
    )

    qr.add_data(
        provisioning_uri
    )

    qr.make(
        fit=True
    )

    qr_image = qr.make_image(
        fill_color="black",
        back_color="white"
    )

    # --------------------------------------------------------
    # Convert QR image to Base64
    # --------------------------------------------------------

    buffer = io.BytesIO()

    qr_image.save(
        buffer,
        format="PNG"
    )

    qr_base64 = base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")

    # --------------------------------------------------------
    # Verify setup code
    # --------------------------------------------------------

    if request.method == "POST":

        code = request.form.get(
            "code",
            ""
        ).strip()

        # Only allow six numeric digits
        if not code.isdigit() or len(code) != 6:

            flash(
                "Please enter a valid 6-digit authentication code.",
                "danger"
            )

            return render_template(
                "two_factor_setup.html",
                qr_code=qr_base64,
                secret=secret
            )

        # ----------------------------------------------------
        # Verify TOTP
        # ----------------------------------------------------

        if totp.verify(code):

            two_factor.enabled = True

            db.session.commit()

            # ------------------------------------------------
            # Update session
            # ------------------------------------------------

            session["two_factor_enabled"] = True
            session["two_factor_verified"] = True

            flash(
                "Two-factor authentication enabled successfully.",
                "success"
            )

            return redirect(
                url_for("main.dashboard")
            )

        flash(
            "Invalid authentication code. Please try again.",
            "danger"
        )

    # --------------------------------------------------------
    # Render setup page
    # --------------------------------------------------------

    return render_template(
        "two_factor_setup.html",
        qr_code=qr_base64,
        secret=secret
    )


# ============================================================
# 2FA VERIFY
# ============================================================

@two_factor_bp.route("/verify", methods=["GET", "POST"])
def verify():

    # --------------------------------------------------------
    # Require login
    # --------------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("auth.login")
        )

    user_id = session.get(
        "user_id"
    )

    # --------------------------------------------------------
    # Get 2FA record
    # --------------------------------------------------------

    two_factor = db.session.execute(
        db.select(TwoFactorAuth).where(
            TwoFactorAuth.user_id == user_id
        )
    ).scalar_one_or_none()

    # --------------------------------------------------------
    # No 2FA configured
    # --------------------------------------------------------

    if not two_factor:

        session["two_factor_enabled"] = False
        session["two_factor_verified"] = True

        return redirect(
            url_for("main.dashboard")
        )

    # --------------------------------------------------------
    # 2FA not enabled
    # --------------------------------------------------------

    if not two_factor.enabled:

        session["two_factor_enabled"] = False
        session["two_factor_verified"] = True

        return redirect(
            url_for("two_factor.setup")
        )

    # --------------------------------------------------------
    # Already verified
    # --------------------------------------------------------

    if session.get(
        "two_factor_verified",
        False
    ):

        return redirect(
            url_for("main.dashboard")
        )

    # --------------------------------------------------------
    # POST — Verify code
    # --------------------------------------------------------

    if request.method == "POST":

        code = request.form.get(
            "code",
            ""
        ).strip()

        # ----------------------------------------------------
        # Validate code format
        # ----------------------------------------------------

        if not code.isdigit() or len(code) != 6:

            flash(
                "Please enter a valid 6-digit authentication code.",
                "danger"
            )

            return render_template(
                "two_factor_verify.html"
            )

        # ----------------------------------------------------
        # Verify code
        # ----------------------------------------------------

        totp = pyotp.TOTP(
            two_factor.secret
        )

        if totp.verify(code):

            # ------------------------------------------------
            # Successful verification
            # ------------------------------------------------

            session["two_factor_verified"] = True
            session["two_factor_enabled"] = True

            flash(
                "Identity verified successfully.",
                "success"
            )

            return redirect(
                url_for("main.dashboard")
            )

        # ----------------------------------------------------
        # Invalid code
        # ----------------------------------------------------

        flash(
            "Invalid authentication code.",
            "danger"
        )

    # --------------------------------------------------------
    # Render verification page
    # --------------------------------------------------------

    return render_template(
        "two_factor_verify.html"
    )


# ============================================================
# DISABLE 2FA
# ============================================================

@two_factor_bp.route("/disable", methods=["POST"])
def disable():

    # --------------------------------------------------------
    # Require login
    # --------------------------------------------------------

    if not is_logged_in():

        return redirect(
            url_for("auth.login")
        )

    user_id = session.get(
        "user_id"
    )

    # --------------------------------------------------------
    # Find 2FA record
    # --------------------------------------------------------

    two_factor = db.session.execute(
        db.select(TwoFactorAuth).where(
            TwoFactorAuth.user_id == user_id
        )
    ).scalar_one_or_none()

    if two_factor:

        db.session.delete(
            two_factor
        )

        db.session.commit()

    # --------------------------------------------------------
    # Update session
    # --------------------------------------------------------

    session["two_factor_enabled"] = False
    session["two_factor_verified"] = True

    flash(
        "Two-factor authentication has been disabled.",
        "success"
    )

    return redirect(
        url_for("main.dashboard")
    )