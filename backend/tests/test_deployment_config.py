"""Guards against a real, silent-failure regression found via §14 live
validation against OWASP Juice Shop: uvicorn's default loop selection
picks uvloop whenever it's importable (uvicorn[standard] pulls it in),
and Playwright's async API is incompatible with uvloop — browser.launch()
hangs forever instead of raising. That permanently stalls the
clickjacking/dom_xss/prototype-pollution checks (real headless-browser
proofs) with no error, no timeout, and no visible symptom short of an
AgentJob stuck at "running" indefinitely. There's no way to catch this
with a normal application-level test (it's an event-loop implementation
detail of how the server process itself is launched), so this instead
guards the actual startup commands directly — if `--loop asyncio` is
ever dropped from these, this test should fail loudly instead of the
regression only surfacing as a silent hang in a real deployment.
"""
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_dockerfile_pins_asyncio_loop():
    dockerfile = (_REPO_ROOT / "backend" / "Dockerfile").read_text()
    cmd_lines = [line for line in dockerfile.splitlines() if line.startswith("CMD")]
    assert cmd_lines, "Dockerfile has no CMD instruction"
    assert "--loop" in cmd_lines[-1] and "asyncio" in cmd_lines[-1], (
        "Dockerfile's CMD must pin --loop asyncio — uvicorn's default loop "
        "selection silently picks uvloop, which hangs Playwright's browser.launch() "
        "forever instead of raising (see this file's module docstring)"
    )


def test_docker_compose_pins_asyncio_loop():
    compose = (_REPO_ROOT / "docker-compose.yml").read_text()
    backend_section = compose.split("frontend:")[0]
    assert "uvicorn" in backend_section
    assert "--loop" in backend_section and "asyncio" in backend_section, (
        "docker-compose.yml's backend command must pin --loop asyncio — see "
        "this file's module docstring"
    )


def test_readme_dev_instructions_pin_asyncio_loop():
    readme = (_REPO_ROOT / "README.md").read_text()
    uvicorn_lines = [line for line in readme.splitlines() if "uvicorn app.main:app" in line]
    assert uvicorn_lines, "README.md has no documented uvicorn run command"
    assert all("--loop asyncio" in line for line in uvicorn_lines), (
        "README.md's documented uvicorn command(s) must include --loop asyncio — "
        "see this file's module docstring"
    )
