import pyotp

from models.user import db, User
from models.two_factor import TwoFactorAuth


# ============================================================
# HELPERS
# ============================================================

def register_user(
    client,
    username="twofactoruser",
    email="twofactor@example.com",
    password="SecurePass123!"
):

    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password
        },
        follow_redirects=True
    )


def login_user(
    client,
    username="twofactoruser",
    password="SecurePass123!"
):

    return client.post(
        "/login",
        data={
            "username": username,
            "password": password
        },
        follow_redirects=True
    )


# ============================================================
# SETUP TEST
# ============================================================

def test_2fa_setup_requires_login(client):

    response = client.get(
        "/2fa/setup",
        follow_redirects=False
    )

    assert response.status_code == 302

    assert "/login" in response.headers["Location"]


# ============================================================
# SETUP PAGE
# ============================================================

def test_2fa_setup_page(client):

    register_user(client)

    login_user(client)

    response = client.get(
        "/2fa/setup"
    )

    assert response.status_code == 200

    assert b"Enable" in response.data

    assert b"Two" in response.data


# ============================================================
# SECRET GENERATION
# ============================================================

def test_2fa_secret_created(client, app):

    register_user(client)

    login_user(client)

    client.get(
        "/2fa/setup"
    )

    with app.app_context():

        user = db.session.execute(
            db.select(User).where(
                User.username == "twofactoruser"
            )
        ).scalar_one()

        two_factor = db.session.execute(
            db.select(TwoFactorAuth).where(
                TwoFactorAuth.user_id == user.id
            )
        ).scalar_one_or_none()

        assert two_factor is not None

        assert two_factor.secret

        assert len(two_factor.secret) >= 16

        assert two_factor.enabled is False


# ============================================================
# VALID 2FA CODE
# ============================================================

def test_2fa_setup_valid_code(client, app):

    register_user(client)

    login_user(client)

    client.get(
        "/2fa/setup"
    )

    with app.app_context():

        user = db.session.execute(
            db.select(User).where(
                User.username == "twofactoruser"
            )
        ).scalar_one()

        two_factor = db.session.execute(
            db.select(TwoFactorAuth).where(
                TwoFactorAuth.user_id == user.id
            )
        ).scalar_one()

        code = pyotp.TOTP(
            two_factor.secret
        ).now()

    response = client.post(
        "/2fa/setup",
        data={
            "code": code
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    assert (
        b"enabled successfully" in response.data
        or b"Security Dashboard" in response.data
    )

    with app.app_context():

        two_factor = db.session.execute(
            db.select(TwoFactorAuth).where(
                TwoFactorAuth.user_id == user.id
            )
        ).scalar_one()

        assert two_factor.enabled is True


# ============================================================
# INVALID CODE
# ============================================================

def test_2fa_invalid_code(client, app):

    register_user(client)

    login_user(client)

    client.get(
        "/2fa/setup"
    )

    response = client.post(
        "/2fa/setup",
        data={
            "code": "000000"
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    assert (
        b"Invalid authentication code" in response.data
    )


# ============================================================
# VERIFY REQUIRES LOGIN
# ============================================================

def test_2fa_verify_requires_login(client):

    response = client.get(
        "/2fa/verify",
        follow_redirects=False
    )

    assert response.status_code == 302

    assert "/login" in response.headers["Location"]


# ============================================================
# VERIFY PAGE
# ============================================================

def test_2fa_verify_page(client, app):

    register_user(client)

    login_user(client)

    client.get(
        "/2fa/setup"
    )

    with app.app_context():

        user = db.session.execute(
            db.select(User).where(
                User.username == "twofactoruser"
            )
        ).scalar_one()

        two_factor = db.session.execute(
            db.select(TwoFactorAuth).where(
                TwoFactorAuth.user_id == user.id
            )
        ).scalar_one()

        two_factor.enabled = True

        db.session.commit()

    # Clear verification state
    with client.session_transaction() as session:

        session["two_factor_verified"] = False

    response = client.get(
        "/2fa/verify"
    )

    assert response.status_code == 200

    assert b"Verify" in response.data

    assert b"Identity" in response.data


# ============================================================
# VALID VERIFY CODE
# ============================================================

def test_2fa_verify_valid_code(client, app):

    register_user(client)

    login_user(client)

    client.get(
        "/2fa/setup"
    )

    with app.app_context():

        user = db.session.execute(
            db.select(User).where(
                User.username == "twofactoruser"
            )
        ).scalar_one()

        two_factor = db.session.execute(
            db.select(TwoFactorAuth).where(
                TwoFactorAuth.user_id == user.id
            )
        ).scalar_one()

        two_factor.enabled = True

        db.session.commit()

        code = pyotp.TOTP(
            two_factor.secret
        ).now()

    with client.session_transaction() as session:

        session["two_factor_verified"] = False

    response = client.post(
        "/2fa/verify",
        data={
            "code": code
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    with client.session_transaction() as session:

        assert session.get(
            "two_factor_verified"
        ) is True


# ============================================================
# INVALID VERIFY CODE
# ============================================================

def test_2fa_verify_invalid_code(client, app):

    register_user(client)

    login_user(client)

    client.get(
        "/2fa/setup"
    )

    with app.app_context():

        user = db.session.execute(
            db.select(User).where(
                User.username == "twofactoruser"
            )
        ).scalar_one()

        two_factor = db.session.execute(
            db.select(TwoFactorAuth).where(
                TwoFactorAuth.user_id == user.id
            )
        ).scalar_one()

        two_factor.enabled = True

        db.session.commit()

    with client.session_transaction() as session:

        session["two_factor_verified"] = False

    response = client.post(
        "/2fa/verify",
        data={
            "code": "123456"
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    assert (
        b"Invalid authentication code" in response.data
    )

    with client.session_transaction() as session:

        assert session.get(
            "two_factor_verified"
        ) is not True

# ============================================================
# DISABLE 2FA
# ============================================================

def test_2fa_disable(client, app):

    register_user(client)

    login_user(client)

    client.get(
        "/2fa/setup"
    )

    # Enable 2FA
    with app.app_context():

        user = db.session.execute(
            db.select(User).where(
                User.username == "twofactoruser"
            )
        ).scalar_one()

        user_id = user.id

        two_factor = db.session.execute(
            db.select(TwoFactorAuth).where(
                TwoFactorAuth.user_id == user_id
            )
        ).scalar_one()

        two_factor.enabled = True

        db.session.commit()

    # Disable 2FA
    response = client.post(
        "/2fa/disable",
        follow_redirects=True
    )

    assert response.status_code == 200

    # Verify that 2FA record was deleted
    with app.app_context():

        two_factor = db.session.execute(
            db.select(TwoFactorAuth).where(
                TwoFactorAuth.user_id == user_id
            )
        ).scalar_one_or_none()

        assert two_factor is None