
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings


connect_args = {}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}


engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
)


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


Base = declarative_base()


def migrate_security_event_columns():
    """
    Add missing telemetry columns to an existing SQLite database.

    Existing rows and existing columns are preserved.
    Safe to execute repeatedly.
    """

    if engine.dialect.name != "sqlite":
        return

    new_columns = {
        "process_name": "VARCHAR(255)",
        "process_id": "INTEGER",
        "local_ip": "VARCHAR(45)",
        "local_port": "INTEGER",
        "remote_ip": "VARCHAR(45)",
        "remote_port": "INTEGER",
        "protocol": "VARCHAR(10)",

        "windows_event_id": "INTEGER",
        "windows_record_id": "INTEGER",
        "windows_channel": "VARCHAR(255)",
        "windows_status": "VARCHAR(50)",
        "windows_sub_status": "VARCHAR(50)",
        "windows_logon_type": "INTEGER",
        "windows_event_timestamp": "DATETIME",
    }

    with engine.begin() as connection:
        inspector = inspect(connection)

        if "security_events" not in inspector.get_table_names():
            return

        existing_columns = {
            column["name"]
            for column in inspector.get_columns("security_events")
        }

        for column_name, column_type in new_columns.items():
            if column_name in existing_columns:
                continue

            statement = text(
                f'ALTER TABLE security_events '
                f'ADD COLUMN "{column_name}" {column_type}'
            )

            connection.execute(statement)
            print(
                f"[DATABASE MIGRATION] Added column: {column_name}"
            )


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
