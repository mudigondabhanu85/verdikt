from app.integrations.teams_bot.commands import (
    NewProjectCommand,
    RejectedCommand,
    ScanCommand,
    StatusCommand,
    UnknownCommand,
    parse_command,
)


def test_parses_scan_command():
    assert parse_command("scan Juice Shop") == ScanCommand(project_name="Juice Shop")


def test_scan_command_case_insensitive_and_whitespace_tolerant():
    assert parse_command("  SCAN   Juice Shop  ") == ScanCommand(project_name="Juice Shop")


def test_parses_status_command():
    assert parse_command("status Juice Shop") == StatusCommand(project_name="Juice Shop")


def test_parses_new_project_command():
    assert parse_command("new project https://example.com") == NewProjectCommand(
        url="https://example.com"
    )


def test_new_project_case_insensitive():
    assert parse_command("New Project https://example.com") == NewProjectCommand(
        url="https://example.com"
    )


def test_unknown_command_echoes_raw_text():
    result = parse_command("do a barrel roll")
    assert isinstance(result, UnknownCommand)
    assert result.raw == "do a barrel roll"


def test_empty_text_is_unknown():
    result = parse_command("")
    assert isinstance(result, UnknownCommand)


def test_rejects_password_shaped_text():
    result = parse_command("scan MyApp password=hunter2")
    assert isinstance(result, RejectedCommand)


def test_rejects_token_shaped_text():
    result = parse_command("here is my token: abc123def456")
    assert isinstance(result, RejectedCommand)


def test_rejects_api_key_shaped_text():
    result = parse_command("api_key=sk-abcdef1234567890")
    assert isinstance(result, RejectedCommand)


def test_rejects_bearer_shaped_text():
    result = parse_command("bearer: eyJhbGciOiJIUzI1NiJ9.somejwt")
    assert isinstance(result, RejectedCommand)


def test_credential_check_takes_priority_over_command_parsing():
    # Even though this otherwise looks like a valid scan command, the
    # embedded secret must win and produce a rejection, not a ScanCommand.
    result = parse_command("scan MyApp secret=abc123")
    assert isinstance(result, RejectedCommand)


def test_normal_scan_command_without_credential_words_is_not_rejected():
    # Sanity check the credential regex isn't so broad it eats normal text.
    assert parse_command("scan Password Manager Demo") == ScanCommand(
        project_name="Password Manager Demo"
    )
