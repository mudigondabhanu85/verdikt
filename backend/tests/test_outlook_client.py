import socket
import threading

import pytest

from app.integrations.outlook.client import OutlookClient, OutlookNotificationError


class _FakeSmtpServer:
    """A minimal real SMTP server speaking just enough of RFC 5321 for
    smtplib.SMTP.send_message() to complete successfully — no aiosmtpd/
    smtpd available in this environment (smtpd was removed from the
    stdlib in Python 3.12+), so this hand-rolls the handshake instead of
    mocking smtplib itself, matching this codebase's real-fixture-over-
    mock discipline (see tests/test_api_notification_configs.py's
    ThreadingHTTPServer fixtures for the same pattern applied to Slack).
    """

    def __init__(self, *, reject_auth: bool = False):
        self._reject_auth = reject_auth
        self.received_messages: list[bytes] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.host, self.port = self._sock.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._stop = False

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            try:
                self._handle(conn)
            except OSError:
                pass
            finally:
                conn.close()

    def _handle(self, conn: socket.socket) -> None:
        rfile = conn.makefile("rb")
        conn.sendall(b"220 fake-smtp ready\r\n")
        in_data = False
        data_buf = b""
        while True:
            line = rfile.readline()
            if not line:
                return
            if in_data:
                if line == b".\r\n":
                    in_data = False
                    self.received_messages.append(data_buf)
                    conn.sendall(b"250 OK\r\n")
                    continue
                data_buf += line
                continue

            upper = line.upper()
            if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
                conn.sendall(b"250-fake-smtp\r\n250 AUTH LOGIN PLAIN\r\n")
            elif upper.startswith(b"AUTH"):
                if self._reject_auth:
                    conn.sendall(b"535 Authentication failed\r\n")
                else:
                    conn.sendall(b"235 Authentication successful\r\n")
            elif upper.startswith(b"MAIL FROM"):
                conn.sendall(b"250 OK\r\n")
            elif upper.startswith(b"RCPT TO"):
                conn.sendall(b"250 OK\r\n")
            elif upper.startswith(b"DATA"):
                conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data = True
                data_buf = b""
            elif upper.startswith(b"QUIT"):
                conn.sendall(b"221 Bye\r\n")
                return
            else:
                conn.sendall(b"500 unrecognized\r\n")


@pytest.fixture
def fake_smtp():
    server = _FakeSmtpServer()
    server.start()
    yield server
    server.stop()


async def test_outlook_client_sends_a_real_message_over_smtp(fake_smtp):
    client = OutlookClient(
        smtp_host=fake_smtp.host,
        smtp_port=fake_smtp.port,
        smtp_username="verdikt@example.com",
        smtp_password="app-password",
        from_address="verdikt@example.com",
        to_address="analyst@example.com",
        use_tls=False,
    )
    await client.send_message("5 findings confirmed", subject="Scan complete")

    assert len(fake_smtp.received_messages) == 1
    body = fake_smtp.received_messages[0]
    assert b"Scan complete" in body
    assert b"5 findings confirmed" in body


async def test_outlook_client_raises_on_auth_failure():
    server = _FakeSmtpServer(reject_auth=True)
    server.start()
    try:
        client = OutlookClient(
            smtp_host=server.host,
            smtp_port=server.port,
            smtp_username="verdikt@example.com",
            smtp_password="wrong-password",
            from_address="verdikt@example.com",
            to_address="analyst@example.com",
            use_tls=False,
        )
        with pytest.raises(OutlookNotificationError):
            await client.send_message("hi")
    finally:
        server.stop()


async def test_outlook_client_raises_on_unreachable_host():
    client = OutlookClient(
        smtp_host="127.0.0.1",
        smtp_port=1,
        smtp_username="x",
        smtp_password="x",
        from_address="a@example.com",
        to_address="b@example.com",
        use_tls=False,
        timeout=1.0,
    )
    with pytest.raises(OutlookNotificationError):
        await client.send_message("hi")
