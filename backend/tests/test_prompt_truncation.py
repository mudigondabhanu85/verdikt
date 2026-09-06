from app.ai.prompt_truncation import truncate_pair_for_prompt


def test_short_pair_passes_through_unchanged():
    a, b = truncate_pair_for_prompt("hello", "hello world")
    assert a == "hello"
    assert b == "hello world"


def test_divergence_far_past_the_limit_is_not_dropped():
    # A real, live-found bug: a blind head truncation hid a marker that
    # only appeared after ~3200 characters of identical page boilerplate
    # (DVWA's own Command Injection page) — the LLM prompt never saw it.
    shared_prefix = "x" * 3000
    baseline = shared_prefix + "no marker here"
    probe = shared_prefix + "MARKER_verdikt123 appeared here"

    _, probe_trunc = truncate_pair_for_prompt(baseline, probe, limit=500)

    assert "MARKER_verdikt123" in probe_trunc


def test_window_is_centered_on_first_divergence_for_both_sides():
    shared_prefix = "a" * 5000
    baseline = shared_prefix + "BASELINE_TAIL"
    probe = shared_prefix + "PROBE_TAIL"

    baseline_trunc, probe_trunc = truncate_pair_for_prompt(baseline, probe, limit=200)

    assert "BASELINE_TAIL" in baseline_trunc
    assert "PROBE_TAIL" in probe_trunc


def test_truncated_windows_are_marked_as_such():
    shared_prefix = "z" * 5000
    baseline = shared_prefix + "b"
    probe = shared_prefix + "p"

    baseline_trunc, probe_trunc = truncate_pair_for_prompt(baseline, probe, limit=200)

    assert "truncated" in baseline_trunc
    assert "truncated" in probe_trunc


def test_identical_strings_never_index_error_on_full_length_match():
    text = "identical" * 500
    a, b = truncate_pair_for_prompt(text, text, limit=100)
    assert len(a) <= 100 + len("...[truncated]...\n") + len("\n...[truncated]...")
    assert len(b) <= 100 + len("...[truncated]...\n") + len("\n...[truncated]...")
