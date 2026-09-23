from app.network_policy import build_ruleset


def test_default_deny_policy_is_the_last_rule():
    """Order matters: the default-deny OUTPUT policy must be applied
    last, or it would block the very setup commands applying the rest
    of the ruleset."""
    rules = build_ruleset([], deny_ips=[])
    assert rules[-1] == "iptables -P OUTPUT DROP"


def test_allow_listed_target_gets_an_explicit_accept_rule():
    rules = build_ruleset([{"ip": "10.0.0.5", "port": 80, "protocol": "tcp"}], deny_ips=[])
    assert "iptables -A OUTPUT -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT" in rules


def test_null_port_allows_every_port_on_that_host():
    """Mirrors app.agents.scope.is_in_scope's own null-port semantics on
    the main backend — a ScopeEntry with no port set matches any port,
    not a narrower {80, 443} default of this service's own invention."""
    rules = build_ruleset([{"ip": "10.0.0.5", "port": None, "protocol": "tcp"}], deny_ips=[])
    assert "iptables -A OUTPUT -d 10.0.0.5 -p tcp -j ACCEPT" in rules
    assert not any("--dport" in r and "10.0.0.5" in r for r in rules)


def test_cloud_metadata_endpoint_is_always_denied():
    rules = build_ruleset([], deny_ips=[])
    assert "iptables -A OUTPUT -d 169.254.169.254 -j DROP" in rules


def test_peer_service_deny_ips_are_blocked_even_if_never_allow_listed():
    rules = build_ruleset([], deny_ips=["172.20.0.3"])
    assert "iptables -A OUTPUT -d 172.20.0.3 -j DROP" in rules


def test_deny_rules_precede_the_default_deny_policy():
    rules = build_ruleset([{"ip": "10.0.0.5", "port": 80}], deny_ips=["172.20.0.3"])
    deny_index = rules.index("iptables -A OUTPUT -d 172.20.0.3 -j DROP")
    policy_index = rules.index("iptables -P OUTPUT DROP")
    assert deny_index < policy_index


def test_dns_stays_open_for_tool_convenience():
    rules = build_ruleset([], deny_ips=[])
    assert "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT" in rules
