from models.user import db


# ============================================================
# CSRF PROTECTION
# ============================================================

def test_csrf_protection(client, app):

    # Enable CSRF specifically for this test
    app.config["WTF_CSRF_ENABLED"] = True

    response = client.post(
        "/login",
        data={
            "username": "testuser",
            "password": "SecurePass123!"
        }
    )

    # Request without CSRF token must be rejected
    assert response.status_code == 400


# ============================================================
# SECURITY HEADERS
# ============================================================

def test_security_headers(client):

    response = client.get("/login")

    assert response.headers.get(
        "X-Content-Type-Options"
    ) == "nosniff"

    assert response.headers.get(
        "X-Frame-Options"
    ) == "DENY"

    assert response.headers.get(
        "Referrer-Policy"
    ) == "strict-origin-when-cross-origin"

    assert (
        response.headers.get(
            "Content-Security-Policy"
        ) is not None
    )


# ============================================================
# SQL INJECTION
# ============================================================

def test_sql_injection_login_rejected(client):

    response = client.post(
        "/login",
        data={
            "username": "' OR '1'='1",
            "password": "' OR '1'='1"
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    assert (
        b"Invalid username or password"
        in response.data
    )


def test_sql_injection_username_rejected(client):

    response = client.post(
        "/register",
        data={
            "username": "' OR '1'='1",
            "email": "attacker@example.com",
            "password": "SecurePass123!"
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    assert (
        b"Username must contain"
        in response.data
    )


# ============================================================
# SESSION COOKIE SECURITY
# ============================================================

def test_session_cookie_security(client):

    # Force Flask to create a session cookie
    with client.session_transaction() as session:

        session["test"] = True

    response = client.get("/login")

    cookies = response.headers.getlist("Set-Cookie")

    assert cookies

    cookie_header = " ".join(cookies)

    assert "HttpOnly" in cookie_header

    assert "SameSite=Lax" in cookie_header