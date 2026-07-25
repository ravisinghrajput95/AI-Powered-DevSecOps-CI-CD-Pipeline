"""WSGI entry point (``gunicorn wsgi:app``).

The app is constructed here rather than at import time in app.py, so
importing app.py has no side effects and does not require a database.
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
