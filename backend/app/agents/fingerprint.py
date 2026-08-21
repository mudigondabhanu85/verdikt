"""Deterministic tech-stack fingerprinting ("smart scan", §10). Runs
after recon over the pages recon already fetched — zero extra requests.
Purely signal-matching against known headers/cookies/HTML markers/error
signatures; never guesses beyond what's actually observed, and multiple
signals commonly fire together for the same target (e.g. nginx serving
a React SPA backed by a Django API). Used to (a) show the detected stack
in reports and (b) let a handful of narrowly-scoped, well-justified
probes skip themselves when they categorically can't apply — see
app.agents.injection's SSTI gating for the one such case built so far.
"""

import re
from dataclasses import dataclass, field

import httpx

_COOKIE_LANGUAGE_HINTS = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "PHP (Laravel)",
    "csrftoken": "Python (Django)",
    "connect.sid": "Node.js (Express)",
}

# (pattern, TechStackFingerprint attribute name, value to record)
_HTML_MARKERS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"ng-version="), "frontend_frameworks", "Angular"),
    (re.compile(r"__NEXT_DATA__|/_next/static/"), "frontend_frameworks", "Next.js (React)"),
    (re.compile(r"data-reactroot|react-dom"), "frontend_frameworks", "React"),
    (re.compile(r"__NUXT__"), "frontend_frameworks", "Nuxt (Vue)"),
    (re.compile(r"\bng-app\b|angular\.js"), "frontend_frameworks", "AngularJS"),
    (re.compile(r"wp-content/|wp-includes/"), "cms", "WordPress"),
    (re.compile(r"Drupal\.settings|/sites/default/files/"), "cms", "Drupal"),
    (re.compile(r"/media/jui/|Joomla!"), "cms", "Joomla"),
    (re.compile(r"csrfmiddlewaretoken"), "backend_languages", "Python (Django)"),
]

_ERROR_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python"),
    (re.compile(r"at java\.[\w.]+\("), "Java"),
    (re.compile(r"Microsoft\.AspNet|System\.Web\."), "ASP.NET"),
    (re.compile(r"Fatal error:.*on line \d+|Warning:.*in .*\.php"), "PHP"),
    (re.compile(r"Cannot GET /|at Layer\.handle"), "Node.js (Express)"),
]


def _looks_html(response: httpx.Response) -> bool:
    return "html" in response.headers.get("content-type", "").lower()


@dataclass
class TechStackFingerprint:
    server_software: set[str] = field(default_factory=set)
    backend_languages: set[str] = field(default_factory=set)
    frontend_frameworks: set[str] = field(default_factory=set)
    cms: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "server_software": sorted(self.server_software),
            "backend_languages": sorted(self.backend_languages),
            "frontend_frameworks": sorted(self.frontend_frameworks),
            "cms": sorted(self.cms),
        }

    @property
    def is_empty(self) -> bool:
        return not (
            self.server_software or self.backend_languages or self.frontend_frameworks or self.cms
        )


class FingerprintAgent:
    def run(self, responses: dict[str, httpx.Response]) -> TechStackFingerprint:
        fingerprint = TechStackFingerprint()
        for response in responses.values():
            self._from_headers(response, fingerprint)
            self._from_cookies(response, fingerprint)
            if _looks_html(response):
                self._from_html(response.text, fingerprint)
            if response.status_code >= 500:
                self._from_error_body(response.text, fingerprint)
        return fingerprint

    def _from_headers(self, response: httpx.Response, fp: TechStackFingerprint) -> None:
        server = response.headers.get("server")
        if server:
            fp.server_software.add(server.split("/")[0].strip())
        powered_by = response.headers.get("x-powered-by")
        if powered_by:
            fp.backend_languages.add(powered_by.strip())

    def _from_cookies(self, response: httpx.Response, fp: TechStackFingerprint) -> None:
        for raw in response.headers.get_list("set-cookie"):
            name = raw.split("=", 1)[0].strip().lower()
            hint = _COOKIE_LANGUAGE_HINTS.get(name)
            if hint:
                fp.backend_languages.add(hint)

    def _from_html(self, text: str, fp: TechStackFingerprint) -> None:
        for pattern, attr, value in _HTML_MARKERS:
            if pattern.search(text):
                getattr(fp, attr).add(value)

    def _from_error_body(self, text: str, fp: TechStackFingerprint) -> None:
        for pattern, language in _ERROR_SIGNATURES:
            if pattern.search(text):
                fp.backend_languages.add(language)
