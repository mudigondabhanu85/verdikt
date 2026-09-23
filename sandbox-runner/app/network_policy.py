"""Real, network-layer scope enforcement for a sandbox session's egress.

Why this exists instead of an HTTP(S) proxy allow-list: HTTP_PROXY/
HTTPS_PROXY env vars only constrain tools that honor them, and only
cover HTTP(S) traffic — nmap's SYN scans, raw `nc`, and some sqlmap
request modes bypass a proxy entirely. A pentest session's whole point
is running exactly those tools, so enforcement has to happen at the
point where packets actually leave the container's own network
namespace, not in application code above it.

Mechanism: the calling container is created with NET_ADMIN capability
(and nothing else privileged — see docker_manager.py). Immediately after
it starts, before any exec() the caller will run, this module applies a
default-deny OUTPUT chain via `docker exec` (which runs inside that
container's own netns) with one explicit ACCEPT rule per allow-listed
(ip, port, protocol) tuple the main Verdikt backend already resolved
from the target Version's ScopeEntry rows. DNS stays open (UDP/53) for
tool convenience — this grants no network access on its own, since
every actual destination IP beyond a DNS answer is still blocked unless
separately allow-listed. This is a real, load-bearing TOCTOU tradeoff:
rules are bound to the IP resolved once, at session-create time — if a
target's DNS record changes mid-session, the sandbox loses connectivity
to it rather than gaining connectivity to whatever the new IP maps to.
That's the safe direction for a security tool to fail in, so it's
accepted rather than solved here.
"""

# Cloud metadata endpoint — same concern already guarded against in
# app.agents.ssrf_callback on the main backend; explicitly denied here
# too regardless of what's on the allow-list, since a sandboxed pentest
# tool reaching this from inside a real cloud deployment would leak
# instance credentials.
_CLOUD_METADATA_IP = "169.254.169.254"


def build_ruleset(allow_list: list[dict], *, deny_ips: list[str]) -> list[str]:
    """Returns an ordered list of iptables commands (each a list of argv
    tokens joined by the caller) to apply, in order, inside the session
    container's own network namespace. Order matters: explicit denies
    must be inserted before the allow rules they're meant to override,
    and the default-deny policy must be set last so it never blocks the
    setup commands applying the rest of this ruleset.
    """
    rules: list[str] = [
        # Loopback and established/related traffic (so a rule ACCEPTing
        # an outbound connection doesn't also require a second explicit
        # rule for its own return traffic).
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        # DNS — cosmetic convenience only (nmap/sqlmap/etc. doing their
        # own lookups); grants no reachability beyond resolving names,
        # since answers still have to match an allow-listed IP below.
        "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
    ]

    for ip in [_CLOUD_METADATA_IP, *deny_ips]:
        rules.append(f"iptables -A OUTPUT -d {ip} -j DROP")

    for entry in allow_list:
        proto = entry.get("protocol", "tcp")
        port = entry.get("port")
        # None port -> no --dport restriction at all (every port on this
        # host is in scope) — mirrors app.agents.scope.is_in_scope's own
        # null-port semantics on the main backend exactly, not a
        # narrower default of this service's own invention.
        dport_clause = f" --dport {port}" if port is not None else ""
        rules.append(f"iptables -A OUTPUT -d {entry['ip']} -p {proto}{dport_clause} -j ACCEPT")

    # Default-deny last — everything above is evaluated first for any
    # packet, so this only ever catches what nothing else already
    # accepted or explicitly dropped.
    rules.append("iptables -P OUTPUT DROP")
    return rules


def apply_ruleset(container, allow_list: list[dict], *, deny_ips: list[str]) -> None:
    """Applies build_ruleset()'s commands to `container` (a docker-py
    Container object) via exec_run, one at a time, so a failure on any
    single rule is immediately attributable rather than lost inside one
    giant shell one-liner. Raises RuntimeError on the first failure —
    session creation must fail loudly and the container must be torn
    down by the caller rather than left running with a partial (and
    therefore unpredictable) ruleset.
    """
    for rule in build_ruleset(allow_list, deny_ips=deny_ips):
        result = container.exec_run(rule.split(" "))
        if result.exit_code != 0:
            raise RuntimeError(
                f"network policy rule failed (exit {result.exit_code}): {rule!r} -> "
                f"{result.output.decode(errors='replace')}"
            )
