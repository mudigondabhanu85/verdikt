import uuid

from app.agents.http_client import AuthenticatedSession
from app.agents.matrix import build_matrix


def test_matrix_is_cross_product_of_endpoints_and_identities():
    admin_id = uuid.uuid4()
    user_id = uuid.uuid4()
    sessions = {
        admin_id: AuthenticatedSession(credential_set_id=admin_id, bearer_token="admin-token"),
        user_id: AuthenticatedSession(credential_set_id=user_id, cookies={"sid": "user-sid"}),
    }
    labels = {admin_id: "Admin", user_id: "User A"}

    entries = build_matrix(["http://x/a", "http://x/b"], sessions, labels)

    assert len(entries) == 2 * 3  # 2 endpoints x (unauthenticated + 2 credential sets)
    identity_labels = {e.identity.label for e in entries}
    assert identity_labels == {"unauthenticated", "Admin", "User A"}

    unauth_entries = [e for e in entries if e.identity.label == "unauthenticated"]
    assert all(e.identity.session is None for e in unauth_entries)
    assert all(e.identity.credential_set_id is None for e in unauth_entries)


def test_matrix_with_no_sessions_is_unauthenticated_only():
    entries = build_matrix(["http://x/a"], {}, {})
    assert len(entries) == 1
    assert entries[0].identity.label == "unauthenticated"


def test_matrix_falls_back_to_id_string_for_unknown_label():
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token="t")}
    entries = build_matrix(["http://x/a"], sessions, {})
    labeled = [e for e in entries if e.identity.credential_set_id == cred_id]
    assert labeled[0].identity.label == str(cred_id)
