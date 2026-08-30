from models.user import db, User


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def register_user(
    client,
    username="testuser",
    email="test@example.com",
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
    username="testuser",
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
# REGISTRATION TESTS
# ============================================================

def test_registration_success(client):

    response = register_user(client)

    assert response.status_code == 200

    assert b"Registration successful" in response.data


def test_duplicate_username_rejected(client):

    register_user(client)

    response = register_user(client)

    assert b"already exists" in response.data


def test_weak_password_rejected(client):

    response = register_user(
        client,
        password="password"
    )

    assert b"Password must contain" in response.data


def test_invalid_username_rejected(client):

    response = register_user(
        client,
        username="ab"
    )

    assert b"Username must contain" in response.data


def test_invalid_email_rejected(client):

    response = register_user(
        client,
        email="not-an-email"
    )

    assert b"valid email" in response.data


# ============================================================
# PASSWORD SECURITY TESTS
# ============================================================

def test_password_is_hashed(client, app):

    register_user(client)

    with app.app_context():

        user = db.session.execute(
            db.select(User).where(
                User.username == "testuser"
            )
        ).scalar_one()

        # Password must NOT be stored as plaintext
        assert user.password_hash != "SecurePass123!"

        # bcrypt hashes normally start with $2
        assert user.password_hash.startswith("$2")


# ============================================================
# LOGIN TESTS
# ============================================================

def test_login_success(client):

    register_user(client)

    response = login_user(client)

    assert response.status_code == 200

    assert b"Welcome, testuser" in response.data


def test_wrong_password_rejected(client):

    register_user(client)

    response = login_user(
        client,
        password="WrongPassword123!"
    )

    assert b"Invalid username or password" in response.data


def test_nonexistent_user_rejected(client):

    response = login_user(
        client,
        username="doesnotexist"
    )

    assert b"Invalid username or password" in response.data


# ============================================================
# SESSION / AUTHORIZATION TESTS
# ============================================================

def test_dashboard_requires_login(client):

    response = client.get(
        "/dashboard",
        follow_redirects=False
    )

    assert response.status_code == 302

    assert "/login" in response.headers["Location"]


def test_login_creates_session(client):

    register_user(client)

    login_user(client)

    with client.session_transaction() as session:

        assert "user_id" in session

        assert "username" in session

        assert session["username"] == "testuser"


def test_logout(client):

    register_user(client)

    login_user(client)

    response = client.get(
        "/logout",
        follow_redirects=True
    )

    assert response.status_code == 200

    assert b"logged out" in response.data


def test_dashboard_blocked_after_logout(client):

    register_user(client)

    login_user(client)

    client.get("/logout")

    response = client.get(
        "/dashboard",
        follow_redirects=False
    )

    assert response.status_code == 302

    assert "/login" in response.headers["Location"]