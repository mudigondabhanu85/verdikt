import uuid

from app.agents.macro import MacroPlayer, MacroRecorder


async def _drive_login(page, *, username="whatever-typed", password="whatever-typed"):
    await page.fill("#username", username)
    await page.fill("#password", password)
    await page.click("#submit-btn")
    await page.wait_for_load_state("networkidle")


async def test_record_captures_steps_without_credential_values(fixture_login_server):
    host, port = fixture_login_server
    base_url = f"http://{host}:{port}/"

    recorder = MacroRecorder()
    steps = await recorder.record(base_url, headless=True, drive=_drive_login)

    assert steps[0].action == "goto"
    assert steps[0].url == base_url

    fill_steps = [s for s in steps if s.action == "fill"]
    assert len(fill_steps) == 2
    assert {s.field_role for s in fill_steps} == {"username", "password"}
    # Neither the typed username nor password value is ever retained.
    assert all(s.value is None for s in fill_steps)

    click_steps = [s for s in steps if s.action == "click"]
    assert len(click_steps) == 1
    assert click_steps[0].selector  # some selector was captured


async def test_record_then_replay_produces_working_session(fixture_login_server):
    host, port = fixture_login_server
    base_url = f"http://{host}:{port}/"

    recorder = MacroRecorder()
    steps = await recorder.record(base_url, headless=True, drive=_drive_login)

    player = MacroPlayer()
    credential_set_id = uuid.uuid4()
    result = await player.replay(
        steps,
        credential_set_id=credential_set_id,
        username="expected_user",
        password="expected_pass",
        headless=True,
    )

    assert result.session is not None
    assert result.session.credential_set_id == credential_set_id
    assert result.session.cookies.get("session") == "abc123-real-session"
    assert result.cookie_count == 1
    assert result.final_status == 200
    assert result.still_shows_password_field is False


async def test_replay_still_showing_password_field_is_flagged_even_with_cookies(fixture_login_server):
    """Real, common shape a failed login takes: the page that comes back
    still sets some cookie (a CSRF token, a fresh anonymous session —
    unrelated to whether the credentials were accepted) and still shows
    the same login form. "Some cookies came back" alone would have read
    this as a successful login; still_shows_password_field is the
    corroborating signal that catches it — see MacroReplayResult's
    docstring and the real bug this closes in
    SessionManager._login_via_macro.
    """
    host, port = fixture_login_server
    base_url = f"http://{host}:{port}/"

    recorder = MacroRecorder()
    steps = await recorder.record(base_url, headless=True, drive=_drive_login)

    player = MacroPlayer()
    result = await player.replay(
        steps,
        credential_set_id=uuid.uuid4(),
        username="wrong_user",
        password="wrong_pass",
        headless=True,
    )

    assert result.cookie_count == 1  # the stray csrftoken cookie
    assert result.still_shows_password_field is True


async def test_macro_step_round_trips_through_dict():
    from app.agents.macro import MacroStep

    step = MacroStep(action="fill", selector="#password", value=None, field_role="password")
    restored = MacroStep.from_dict(step.to_dict())
    assert restored == step
