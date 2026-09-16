import uuid

from app.agents.http_client import AuthenticatedSession
from app.agents.login import pick_best_session


def test_none_or_empty_sessions_returns_none():
    assert pick_best_session(None) is None
    assert pick_best_session({}) is None


def test_bearer_token_session_preferred_over_cookie_only():
    cred_a, cred_b = uuid.uuid4(), uuid.uuid4()
    cookie_session = AuthenticatedSession(credential_set_id=cred_a, cookies={"sid": "abc"})
    bearer_session = AuthenticatedSession(credential_set_id=cred_b, bearer_token="jwt.xyz")
    # Insertion order deliberately puts the "worse" one first — a naive
    # next(iter(...)) would have picked cookie_session.
    sessions = {cred_a: cookie_session, cred_b: bearer_session}

    assert pick_best_session(sessions) is bearer_session


def test_session_with_more_cookies_preferred_over_flaky_single_cookie():
    cred_a, cred_b = uuid.uuid4(), uuid.uuid4()
    # A stray cookie left over from a macro replay that didn't actually
    # reach an authenticated state (see MacroPlayer.replay's docstring).
    flaky_session = AuthenticatedSession(credential_set_id=cred_a, cookies={"_ga": "leftover"})
    real_session = AuthenticatedSession(
        credential_set_id=cred_b, cookies={"sid": "abc", "csrf": "tok", "remember": "1"}
    )
    sessions = {cred_a: flaky_session, cred_b: real_session}

    assert pick_best_session(sessions) is real_session


def test_ties_resolve_to_first_inserted_same_as_before():
    cred_a, cred_b = uuid.uuid4(), uuid.uuid4()
    first = AuthenticatedSession(credential_set_id=cred_a, cookies={"sid": "abc"})
    second = AuthenticatedSession(credential_set_id=cred_b, cookies={"sid": "def"})
    sessions = {cred_a: first, cred_b: second}

    assert pick_best_session(sessions) is first
