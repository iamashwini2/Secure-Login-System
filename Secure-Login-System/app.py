from flask import Flask

from config import Config

from models.user import db

# Import models so SQLAlchemy registers their tables
from models.two_factor import TwoFactorAuth

from extensions import csrf, limiter


def create_app(config_class=Config):

    app = Flask(__name__)

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    app.config.from_object(config_class)

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    db.init_app(app)

    # --------------------------------------------------------
    # Security extensions
    # --------------------------------------------------------

    csrf.init_app(app)
    limiter.init_app(app)

    # --------------------------------------------------------
    # Security Headers
    # --------------------------------------------------------

    @app.after_request
    def add_security_headers(response):

        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Enable browser XSS protection for older browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Control information sent in the Referer header
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Restrict browser capabilities
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:;"
        )

        # HTTPS security
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        return response

    # --------------------------------------------------------
    # Register routes
    # --------------------------------------------------------

    from routes.auth import auth_bp
    from routes.main import main_bp
    from routes.two_factor import two_factor_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(two_factor_bp)

    # --------------------------------------------------------
    # Create database tables
    # --------------------------------------------------------

    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        debug=True
    )