"""Shared fixtures for the backend suite.

These exist because app.py became an application factory. Previously it built
the app at import time and ran db.create_all() + seed_admin() inside a
module-level app context, so importing it opened a real database connection
and no test could exercise a request without a live PostgreSQL.
"""

import pytest

pytest.importorskip(
    "flask_sqlalchemy",
    reason="backend dependencies not installed — run: pip install -r backend/requirements.txt",
)


@pytest.fixture
def app():
    """A real app with an in-memory SQLite database and the schema created.

    init_db=False skips the production create_all()/seed_admin() path; the
    schema is created here against SQLite instead, so tests are isolated and
    need no external service.
    """
    from app import create_app
    from models.user import db

    application = create_app(
        {
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "TESTING": True,
        },
        init_db=False,
    )
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
