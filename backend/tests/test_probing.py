from urllib.parse import parse_qs, urlsplit

from app.agents.probing import BASELINE_VALUE, ProbeTarget, build_request, form_probe_targets
from app.agents.recon import FormField, FormInfo


def test_get_request_includes_other_fields_alongside_the_tested_one():
    """Real, live-found bug against DVWA: a multi-field GET form (SQL
    Injection's "id" + "Submit") needs every companion field present for
    the target's own server-side logic to run at all — DVWA's low.php
    gates its query behind `isset($_GET['Submit'])`. Omitting
    other_fields for GET (while the POST branch already included them)
    silently degraded every such probe into fetching the untouched
    "enter a value" placeholder page instead of ever submitting the
    form — no error, no visible symptom beyond a quietly-empty finding
    list for every GET form with more than one field.
    """
    target = ProbeTarget(
        url="http://site.test/vulnerabilities/sqli/",
        method="GET",
        param_name="id",
        other_fields={"Submit": "verdikt1"},
    )
    url, body, content_type = build_request(target, "1' OR '1'='1")

    assert body is None
    assert content_type is None
    query = parse_qs(urlsplit(url).query)
    assert query["id"] == ["1' OR '1'='1"]
    assert query["Submit"] == ["verdikt1"]


def test_get_request_with_no_other_fields_still_works():
    target = ProbeTarget(url="http://site.test/vulnerabilities/xss_r/", method="GET", param_name="name")
    url, body, content_type = build_request(target, "<script>")

    assert body is None
    assert content_type is None
    query = parse_qs(urlsplit(url).query)
    assert query["name"] == ["<script>"]
    assert list(query.keys()) == ["name"]


def test_form_probe_targets_never_gives_two_fields_the_same_value():
    """Real, live-found bug against DVWA: giving every companion field
    the exact same literal BASELINE_VALUE let a same-form equality gate
    (a password-change form's "new" vs. "confirm" field, DVWA's own CSRF
    page being exactly this shape) be satisfied by the very first
    *baseline* fetch alone — before any actual attack payload was even
    tried — silently changing the real admin password to "verdikt1" as
    a side effect of routine SQLi/XSS probing. Each companion field must
    get a distinct value so no two fields on the same form can ever be
    coincidentally equal.
    """
    form = FormInfo(
        action_url="http://site.test/vulnerabilities/csrf/",
        method="GET",
        fields=[
            FormField(name="password_new", type="text"),
            FormField(name="password_conf", type="text"),
            FormField(name="Change", type="submit"),
        ],
    )
    targets = form_probe_targets([form])

    for target in targets:
        values = list(target.other_fields.values())
        assert len(values) == len(set(values)), target.other_fields
        # And no other field's baseline value may equal what the tested
        # field itself gets set to during the baseline fetch.
        assert BASELINE_VALUE not in values


def test_form_probe_targets_carries_submit_button_as_an_other_field():
    form = FormInfo(
        action_url="http://site.test/vulnerabilities/sqli/",
        method="GET",
        fields=[
            FormField(name="id", type="text"),
            FormField(name="Submit", type="submit"),
        ],
    )
    targets = form_probe_targets([form])

    assert len(targets) == 1
    assert targets[0].param_name == "id"
    assert targets[0].other_fields == {"Submit": "verdikt1_Submit"}
