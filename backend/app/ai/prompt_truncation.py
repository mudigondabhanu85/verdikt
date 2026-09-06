DEFAULT_TRUNCATE = 2000


def truncate_pair_for_prompt(a: str, b: str, limit: int = DEFAULT_TRUNCATE) -> tuple[str, str]:
    """Truncates a pair of response bodies (baseline/probe, or identity-A/
    identity-B) to `limit` characters each for an LLM prompt — centered on
    where they first diverge, not just the first `limit` characters of
    each. A real, live-found bug (app.agents.injection): a blind head
    truncation silently hid an injected marker for DVWA's own Command
    Injection page, whose distinguishing output comes after ~3200
    characters of an unrelated page header/sidebar — the deterministic
    Python check correctly saw the marker in the full, untruncated
    response, but the LLM triage step never did (its prompt only got the
    first 2000 characters) and rejected an otherwise correctly-detected,
    genuinely exploitable finding. Centering the truncation on the first
    point of divergence, rather than the start of the response, keeps
    this working regardless of how much boilerplate precedes the actual
    signal on any given page — used anywhere a triage/validation prompt
    compares two response bodies against each other (injection's
    baseline/probe, access control's identity-A/identity-B).
    """
    if len(a) <= limit and len(b) <= limit:
        return a, b

    min_len = min(len(a), len(b))
    diverge_at = min_len
    for i in range(min_len):
        if a[i] != b[i]:
            diverge_at = i
            break

    half = limit // 2
    start = max(0, diverge_at - half)

    def _window(text: str) -> str:
        end = min(len(text), start + limit)
        window_start = max(0, end - limit)
        prefix = "...[truncated]...\n" if window_start > 0 else ""
        suffix = "\n...[truncated]..." if end < len(text) else ""
        return prefix + text[window_start:end] + suffix

    return _window(a), _window(b)
