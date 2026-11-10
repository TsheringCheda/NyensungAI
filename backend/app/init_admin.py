from getpass import getpass

from sqlalchemy.orm import Session

from app.database import Base, engine, SessionLocal

from app.models.user import User
from app.models.revoked_token import RevokedToken
from app.models.audit_log import AuditLog

from app.services.security import hash_password


def initialize_admin():

    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()

    try:

        email = input(
            "Administrator email: "
        ).strip().lower()

        username = input(
            "Administrator username: "
        ).strip()

        password = getpass(
            "Administrator password: "
        )

        confirm = getpass(
            "Confirm password: "
        )

        if password != confirm:
            print("Passwords do not match.")
            return

        if len(password) < 12:
            print("Password must contain at least 12 characters.")
            return

        if not username or len(username) > 100:
            print("Invalid username.")
            return

        existing = db.query(User).filter(
            (User.email == email) |
            (User.username == username)
        ).first()

        if existing:
            print("User already exists.")
            return

        admin = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role="admin",
            is_active=True
        )

        db.add(admin)
        db.commit()

        print("\nAdministrator created successfully!")

    finally:
        db.close()


if __name__ == "__main__":
    initialize_admin()