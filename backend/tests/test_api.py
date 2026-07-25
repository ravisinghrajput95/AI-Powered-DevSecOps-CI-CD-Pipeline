"""Request-level tests, enabled by the application factory.

These assert on real HTTP behaviour through Flask's test client — the thing
backend/tests could not do while app.py connected to a database at import.

Scope is the error contracts fixed on 2026-07-25 plus the intentional
vulnerabilities that must not regress. The planted flaws are asserted as
PRESENT: this is a deliberately vulnerable app, so "someone fixed it" is a
regression that silently removes findings the security pipeline depends on.
"""


def test_health_and_index(client):
    assert client.get("/health").get_json()["status"] == "healthy"
    assert client.get("/").get_json()["name"] == "CloudCart API"


def test_config_endpoint_still_leaks_secrets(client):
    """VULN (intentional): /api/config exposes live credentials."""
    body = client.get("/api/config").get_json()
    for key in ("secret_key", "jwt_secret", "aws_access_key", "admin_password"):
        assert (
            key in body
        ), f"/api/config no longer exposes {key} — planted vuln removed"


class TestCartErrorContracts:
    """Every one of these returned HTTP 500 before 2026-07-25."""

    def test_clear_cart_unauthenticated_returns_401_not_500(self, client):
        # Previously: int(None) -> TypeError -> 500, while every sibling
        # route returned a clean 401.
        assert client.post("/api/cart/clear").status_code == 401

    def test_get_cart_unauthenticated_returns_401(self, client):
        assert client.get("/api/cart/").status_code == 401

    def test_non_numeric_user_id_returns_400_not_500(self, client):
        # Previously: int("abc") -> ValueError -> 500.
        assert client.get("/api/cart/?user_id=abc").status_code == 400

    def test_add_to_cart_rejects_non_integer_quantity(self, client):
        # Previously: existing.quantity += "many" -> TypeError -> 500.
        r = client.post(
            "/api/cart/add",
            json={"product_id": 1, "quantity": "many"},
            headers={"X-User-Id": "1"},
        )
        assert r.status_code == 400

    def test_add_to_cart_rejects_negative_quantity(self, client):
        r = client.post(
            "/api/cart/add",
            json={"product_id": 1, "quantity": -5},
            headers={"X-User-Id": "1"},
        )
        assert r.status_code == 400


class TestAuthErrorContracts:
    def test_register_requires_fields(self, client):
        assert client.post("/api/auth/register", json={}).status_code == 400

    def test_duplicate_username_and_email_both_return_409(self, client):
        first = {"username": "alice", "email": "alice@example.com", "password": "pw"}
        assert client.post("/api/auth/register", json=first).status_code == 201

        # Duplicate username already returned 409.
        dup_user = dict(first, email="other@example.com")
        assert client.post("/api/auth/register", json=dup_user).status_code == 409

        # Duplicate email raised IntegrityError -> 500 before the fix, even
        # though email is UNIQUE in the schema. Two near-identical conflicts
        # must not produce different status codes.
        dup_email = dict(first, username="bob")
        assert client.post("/api/auth/register", json=dup_email).status_code == 409

    def test_login_rejects_bad_credentials(self, client):
        r = client.post("/api/auth/login", json={"username": "nobody", "password": "x"})
        assert r.status_code == 401


def test_cart_idor_is_still_present(client):
    """VULN (intentional): identity is taken from an unauthenticated header.

    The 2026-07-25 fix hardened the CRASH (malformed input) without touching
    the trust model — a caller can still act as any user id. If this starts
    returning 401 the IDOR demo has been silently removed.
    """
    r = client.get("/api/cart/", headers={"X-User-Id": "42"})
    assert r.status_code == 200, "cart no longer accepts an unauthenticated X-User-Id"
