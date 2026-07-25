"""Backend smoke tests.

Replaces a literal `assert True`, which passed unconditionally and verified
nothing — a green CI check that cannot fail is worse than no check, because
it looks like coverage.

Scope is deliberately narrow: these import route modules and models
directly and assert on structure. They do NOT import app.py, because it
runs `db.create_all()` and `seed_admin()` at module import time inside a
`with app.app_context()` block, so importing it opens a real database
connection. Testing request handling properly needs an application factory
(`create_app()`); that refactor is the right fix rather than standing up a
database per test run.

What these DO catch, all of which are real failure modes here:
  - a route module that fails to import (bad syntax, missing dependency)
  - a blueprint renamed or removed, silently unregistering its routes
  - a model losing a column the API serialises
  - the intentional-vulnerability surface disappearing by accident

That last one matters for a deliberately vulnerable app: if someone
"fixes" the SQL injection in products.search, the security pipeline stops
producing the findings the demo depends on, and nothing else in CI notices.
"""
import importlib

import pytest

# These tests exercise real backend modules, so they need the backend's own
# dependencies. CI installs them (see backend-ci.yaml's "Install
# dependencies" step); a bare local checkout may not have them. Skip loudly
# with an actionable message rather than failing with a raw
# ModuleNotFoundError that looks like a broken test.
pytest.importorskip(
    "flask_sqlalchemy",
    reason="backend dependencies not installed — run: pip install -r backend/requirements.txt",
)

ROUTE_MODULES = [
    ("routes.auth", "auth_bp"),
    ("routes.products", "products_bp"),
    ("routes.cart", "cart_bp"),
    ("routes.orders", "orders_bp"),
    ("routes.reviews", "reviews_bp"),
    ("routes.admin", "admin_bp"),
    ("routes.profile", "profile_bp"),
    ("routes.vulnerable", "vuln_bp"),
    ("routes.metrics", "metrics_bp"),
]


@pytest.mark.parametrize("module_name,blueprint_name", ROUTE_MODULES)
def test_route_module_imports_and_exposes_blueprint(module_name, blueprint_name):
    """Every route module imports cleanly and exposes its blueprint.

    app.py registers all nine by name; a rename breaks startup with an
    ImportError that no other test would surface.
    """
    module = importlib.import_module(module_name)
    blueprint = getattr(module, blueprint_name, None)
    assert blueprint is not None, f"{module_name} does not define {blueprint_name}"
    assert blueprint.name, f"{blueprint_name} has no name"


def test_all_models_import_and_define_tablenames():
    """Models import and declare the table names the schema creates."""
    expected = {
        "models.user": ("User", "users"),
        "models.product": ("Product", "products"),
        "models.cart": ("CartItem", "cart_items"),
        "models.order": ("Order", "orders"),
        "models.review": ("Review", "reviews"),
    }
    for module_name, (cls_name, table) in expected.items():
        module = importlib.import_module(module_name)
        cls = getattr(module, cls_name, None)
        assert cls is not None, f"{module_name} does not define {cls_name}"
        assert cls.__tablename__ == table


def test_user_to_dict_hides_sensitive_fields_by_default():
    """to_dict() must not leak password_hash or api_key unless asked.

    The exposure behind include_sensitive=True is one of the planted
    vulnerabilities, but it must stay behind that flag — an accidental
    default flip would leak credentials on every /api/auth/me response.
    """
    from models.user import User

    user = User(
        username="alice",
        email="alice@example.com",
        password_hash="pbkdf2:sha256:fake",
        full_name="Alice",
        role="customer",
        api_key="sk_live_fake",
    )
    safe = user.to_dict()
    assert "password_hash" not in safe
    assert "api_key" not in safe

    sensitive = user.to_dict(include_sensitive=True)
    assert sensitive["password_hash"] == "pbkdf2:sha256:fake"
    assert sensitive["api_key"] == "sk_live_fake"


def test_intentional_sql_injection_surface_still_present():
    """The SQLi demo route must keep building raw SQL by interpolation.

    README documents products.search as the SQL injection example and the
    security pipeline reports it every run. If someone parameterises this
    query the app gets safer and the demo silently loses a finding, so this
    asserts the vulnerability is still present on purpose.
    """
    import inspect

    from routes import products

    source = inspect.getsource(products.search_products)
    assert "text(sql)" in source, "raw SQL execution removed from search_products"
    assert "{search_term}" in source, "search term no longer interpolated into SQL"
