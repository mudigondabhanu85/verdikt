import uuid
from dataclasses import dataclass

from app.agents.http_client import AuthenticatedSession


@dataclass(frozen=True)
class Identity:
    """One row of the §5 privilege matrix: either the unauthenticated
    baseline (session=None) or a logged-in CredentialSet."""

    label: str
    credential_set_id: uuid.UUID | None
    session: AuthenticatedSession | None


@dataclass(frozen=True)
class MatrixEntry:
    endpoint: str
    identity: Identity


def build_identities(
    sessions: dict[uuid.UUID, AuthenticatedSession],
    credential_labels: dict[uuid.UUID, str],
) -> list[Identity]:
    """The unauthenticated baseline plus every credential set that has an
    established session — the identity axis of the §5 privilege matrix.
    """
    identities: list[Identity] = [Identity(label="unauthenticated", credential_set_id=None, session=None)]
    for credential_set_id, session in sessions.items():
        label = credential_labels.get(credential_set_id, str(credential_set_id))
        identities.append(
            Identity(label=label, credential_set_id=credential_set_id, session=session)
        )
    return identities


def build_matrix(
    endpoints: list[str],
    sessions: dict[uuid.UUID, AuthenticatedSession],
    credential_labels: dict[uuid.UUID, str],
) -> list[MatrixEntry]:
    """Cross product of discovered endpoints x available identities — the
    input the Access-Control agent walks to build its horizontal/vertical
    comparisons.
    """
    identities = build_identities(sessions, credential_labels)
    return [
        MatrixEntry(endpoint=endpoint, identity=identity)
        for endpoint in endpoints
        for identity in identities
    ]
