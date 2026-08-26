from datetime import datetime, timezone

from models.user import db


class TwoFactorAuth(db.Model):

    __tablename__ = "two_factor_auth"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        unique=True
    )

    secret = db.Column(
        db.String(32),
        nullable=False
    )

    enabled = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "two_factor",
            uselist=False,
            cascade="all, delete-orphan"
        )
    )