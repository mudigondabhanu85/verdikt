import pytest

from app.network_policy import apply_ruleset


class _FakeExecResult:
    def __init__(self, exit_code: int, output: bytes = b""):
        self.exit_code = exit_code
        self.output = output


class _FakeContainer:
    """Records every command it was asked to exec_run, in order — lets a
    test assert the actual iptables call sequence reached the container,
    not just that build_ruleset() produced the right strings."""

    def __init__(self, *, fail_on: str | None = None):
        self.calls: list[list[str]] = []
        self._fail_on = fail_on

    def exec_run(self, argv: list[str]):
        self.calls.append(argv)
        if self._fail_on is not None and self._fail_on in argv:
            return _FakeExecResult(1, b"iptables: bad rule (does a matching rule exist in that chain?)")
        return _FakeExecResult(0)


def test_apply_ruleset_runs_every_rule_against_the_container():
    container = _FakeContainer()
    apply_ruleset(container, [{"ip": "10.0.0.5", "port": 80, "protocol": "tcp"}], deny_ips=["172.20.0.3"])

    assert len(container.calls) > 0
    assert container.calls[-1] == ["iptables", "-P", "OUTPUT", "DROP"]
    assert ["iptables", "-A", "OUTPUT", "-d", "10.0.0.5", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"] in (
        container.calls
    )


def test_apply_ruleset_raises_loudly_on_the_first_failed_rule():
    """A partially-applied ruleset has unpredictable scope — this must
    fail hard (so the caller tears the container down) rather than
    silently continuing with some rules missing."""
    container = _FakeContainer(fail_on="169.254.169.254")

    with pytest.raises(RuntimeError, match="network policy rule failed"):
        apply_ruleset(container, [], deny_ips=[])
