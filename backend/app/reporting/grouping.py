"""Groups findings by (check_id, title) for report rendering (§8). A
scan commonly confirms the same vulnerability class across dozens of
endpoints (e.g. a missing security header checked on every crawled
page) — rendering each as its own full flat section produced reports
hundreds of pages long with near-duplicate content (a real 291-finding
scan produced a 629-page PDF). Real data confirms plain_language_summary
and remediation are always identical across instances of the same
check_id within one scan run, so one shared block plus a per-instance
list (endpoint, steps_to_reproduce, evidence) loses no information.
"""

from dataclasses import dataclass, field

from app.models.finding import Finding

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Deduping the shared narrative fixed the 629-page complaint's main
# cause, but a check confirmed across dozens/hundreds of endpoints still
# repeated a full evidence block (request/response text + screenshot)
# per instance — still enough on its own to produce an unwieldy report.
# Full evidence for a representative handful plus a compact endpoint
# list for the rest keeps every instance accounted for without
# re-embedding near-identical proof over and over.
_MAX_DETAILED_INSTANCES = 5


@dataclass
class FindingGroup:
    check_id: str
    title: str
    severity: str
    instances: list[Finding] = field(default_factory=list)

    @property
    def shared(self) -> Finding:
        """Any instance's shared fields (summary/remediation/CWE/OWASP
        category) are identical within a group — the first one stands
        in for all of them."""
        return self.instances[0]

    @property
    def detailed_instances(self) -> list[Finding]:
        """The instances to render with full evidence (steps, request/
        response, screenshot)."""
        return self.instances[:_MAX_DETAILED_INSTANCES]

    @property
    def summary_only_instances(self) -> list[Finding]:
        """The rest — listed by endpoint only, no repeated evidence."""
        return self.instances[_MAX_DETAILED_INSTANCES:]


def group_findings(findings: list[Finding]) -> list[FindingGroup]:
    groups: dict[tuple[str, str], FindingGroup] = {}
    for finding in findings:
        key = (finding.check_id, finding.title)
        group = groups.get(key)
        if group is None:
            group = FindingGroup(check_id=finding.check_id, title=finding.title, severity=finding.severity)
            groups[key] = group
        group.instances.append(finding)
        if SEVERITY_ORDER.get(finding.severity, 99) < SEVERITY_ORDER.get(group.severity, 99):
            group.severity = finding.severity

    return sorted(groups.values(), key=lambda g: SEVERITY_ORDER.get(g.severity, 99))
