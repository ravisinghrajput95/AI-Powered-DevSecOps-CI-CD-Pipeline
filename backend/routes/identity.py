"""Shared caller-identity resolution.

Four blueprints each rolled their own version of "who is calling", and they
disagreed about which sources count:

    auth.py     session | ?user_id
    orders.py   session | ?user_id          (list)
    orders.py   session | body.user_id      (checkout)
    cart.py     session | ?user_id | X-User-Id
    reviews.py  session | body.user_id

The frontend sends `X-User-Id` on **every** request (see
frontend/src/api/client.js), so it was honoured by cart.py alone and
silently ignored by the other three — a request that worked against the
cart failed against orders for no reason visible in either codebase.

Each also called int() on the raw value with no guard, so a missing or
non-numeric id raised TypeError/ValueError and returned HTTP 500 for what
are ordinary client errors.

IMPORTANT — the trust model here is intentionally broken and stays that
way. Accepting an unauthenticated ?user_id= or X-User-Id lets any caller
act as any user; that IDOR is one of CloudCart's planted vulnerabilities
and the security pipeline reports it every run. This module unifies *where
identity is read from* and stops malformed input crashing the process. It
deliberately does NOT add authentication.
"""

from flask import jsonify, request, session


def raw_user_id(json_body=None):
    """Return the caller's claimed user id as a raw string, or None.

    Sources are checked in a fixed order — session first, then the
    unauthenticated ones. `json_body` is accepted because two routes
    (orders checkout, review creation) take the id from the request body;
    passing the already-parsed body avoids re-reading it.
    """
    candidates = [
        session.get("user_id"),
        request.args.get("user_id"),
        request.headers.get("X-User-Id"),
    ]
    if json_body:
        candidates.append(json_body.get("user_id"))
    for value in candidates:
        if value not in (None, ""):
            return value
    return None


def resolve_user_id(json_body=None):
    """Return (user_id:int|None, error_response|None).

    401 when no identity was supplied, 400 when one was supplied but is not
    an integer. Both were HTTP 500 before this existed.
    """
    value = raw_user_id(json_body)
    if value is None:
        return None, (jsonify({"error": "Not authenticated"}), 401)
    try:
        return int(value), None
    except (TypeError, ValueError):
        return None, (jsonify({"error": "Invalid user id"}), 400)
