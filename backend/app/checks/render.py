from collections import defaultdict


def render_check_template(template: str, url: str, extra: dict) -> str:
    """Fills a catalog template's {url}/{extra-key} placeholders. Missing
    keys render empty rather than raising — catalog templates only
    reference a subset of possible extra fields per check."""
    context = defaultdict(str, url=url, **extra)
    return template.format_map(context)
