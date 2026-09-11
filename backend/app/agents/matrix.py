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
    # Analyst-set (CredentialSet.privilege_rank), None for the
    # unauthenticated baseline and for any credential the analyst never
    # ranked. Higher means more privileged. Only used by
    # app.agents.access_control's role-vs-role vertical escalation
    # check, which only compares identities that both have a rank set.
    privilege_rank: int | None = None


@dataclass(frozen=True)
class MatrixEntry:
    endpoint: str
    identity: Identity


def build_identities(
    sessions: dict[uuid.UUID, AuthenticatedSession],
    credential_labels: dict[uuid.UUID, str],
    credential_ranks: dict[uuid.UUID, int | None] | None = None,
) -> list[Identity]:
    """The unauthenticated baseline plus every credential set that has an
    established session — the identity axis of the §5 privilege matrix.
    """
    ranks = credential_ranks or {}
    identities: list[Identity] = [Identity(label="unauthenticated", credential_set_id=None, session=None)]
    for credential_set_id, session in sessions.items():
        label = credential_labels.get(credential_set_id, str(credential_set_id))
        identities.append(
            Identity(
                label=label,
                credential_set_id=credential_set_id,
                session=session,
                privilege_rank=ranks.get(credential_set_id),
            )
        )
    return identities


def build_matrix(
    endpoints: list[str],
    sessions: dict[uuid.UUID, AuthenticatedSession],
    credential_labels: dict[uuid.UUID, str],
    credential_ranks: dict[uuid.UUID, int | None] | None = None,
) -> list[MatrixEntry]:
    """Cross product of discovered endpoints x available identities — the
    input the Access-Control agent walks to build its horizontal/vertical
    comparisons.
    """
    identities = build_identities(sessions, credential_labels, credential_ranks)
    return [
        MatrixEntry(endpoint=endpoint, identity=identity)
        for endpoint in endpoints
        for identity in identities
    ]
