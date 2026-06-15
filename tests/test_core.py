"""
Tests for the SMTP server core.
"""
import base64
import socket
import ssl
import threading
from unittest.mock import MagicMock, patch

import pytest

from mailoney.config import RateLimitConfig, TlsConfig
from mailoney.core import DEFAULT_CONN_TIMEOUT, SMTPHoneypot, _format_banner
from mailoney.rate_limiter import RateLimiter
from mailoney.tls import build_server_context, ensure_tls_material
from tests.conftest import read_jsonl


def _honeypot(tmp_path, **kwargs):
    kwargs.setdefault("rate_limiter", None)
    kwargs.setdefault("bind_ip", "127.0.0.1")
    kwargs.setdefault("bind_port", 8025)
    kwargs.setdefault("server_name", "test.example.com")
    kwargs.setdefault("log_file", str(tmp_path / "log" / "log.json"))
    kwargs.setdefault("mail_dir", str(tmp_path / "log" / "mails"))
    return SMTPHoneypot(
        **kwargs,
    )


def _recv_until(sock: socket.socket, needle: bytes, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while needle not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _run_session(honeypot: SMTPHoneypot, client_script) -> None:
    server_sock, client_sock = socket.socketpair()
    handler = threading.Thread(
        target=honeypot._handle_client,
        args=(server_sock, ("203.0.113.7", 54321)),
    )
    handler.start()
    try:
        client_script(client_sock)
    finally:
        client_sock.close()
    handler.join(timeout=5)
    assert not handler.is_alive(), "handler thread did not exit"


def _tls_context(tmp_path):
    tls_config = TlsConfig(
        cert_file=str(tmp_path / "log" / "tls" / "server.crt"),
        key_file=str(tmp_path / "log" / "tls" / "server.key"),
    )
    material = ensure_tls_material(tls_config, "test.example.com")
    assert material is not None
    return build_server_context(material), material


def _client_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


@pytest.fixture
def smtp_honeypot(tmp_path):
    return _honeypot(tmp_path)


def test_smtp_honeypot_init(smtp_honeypot):
    assert smtp_honeypot.bind_ip == "127.0.0.1"
    assert smtp_honeypot.bind_port == 8025
    assert smtp_honeypot.server_name == "test.example.com"
    assert "test.example.com" in smtp_honeypot.ehlo_response
    assert "STARTTLS" not in smtp_honeypot.ehlo_response
    assert smtp_honeypot.socket is None


def test_banner_is_centered_without_indentation():
    banner = _format_banner("2.2.0")
    lines = banner.splitlines()

    assert len(lines) == 3
    assert lines[0] == lines[2]
    assert set(lines[0]) == {"*"}
    assert not banner.startswith("\n")
    assert all(not line.startswith(" ") for line in lines)
    assert lines[1].startswith("*")
    assert lines[1].endswith("*")
    assert len({len(line) for line in lines}) == 1


@patch("socket.create_server")
def test_smtp_honeypot_start(mock_create_server, smtp_honeypot):
    mock_socket_instance = MagicMock()
    mock_create_server.return_value = mock_socket_instance

    call_count = [0]

    def accept_connections_mock():
        call_count[0] += 1

    original_method = smtp_honeypot._accept_connections
    smtp_honeypot._accept_connections = accept_connections_mock
    try:
        smtp_honeypot.start()
        mock_create_server.assert_called_once()
        args, kwargs = mock_create_server.call_args
        assert args[0] == ("127.0.0.1", 8025)
        assert kwargs["backlog"] == 100
        assert call_count[0] == 1
    finally:
        smtp_honeypot._accept_connections = original_method


def test_conn_timeout_defaults(smtp_honeypot):
    assert smtp_honeypot.conn_timeout == DEFAULT_CONN_TIMEOUT
    assert SMTPHoneypot(conn_timeout=5).conn_timeout == 5


def test_idle_connection_times_out(tmp_path):
    honeypot = _honeypot(tmp_path, conn_timeout=1)

    def script(client_sock):
        banner = client_sock.recv(1024)
        assert banner.startswith(b"220 ")
        tail = _recv_until(client_sock, b"421", timeout=3)
        assert b"421" in tail

    _run_session(honeypot, script)
    events = read_jsonl(tmp_path / "log" / "log.json")
    assert events[0]["event.type"] == "session"
    assert "timed out" in events[0]["errors"][0]


def test_pipelined_mail_session_writes_flat_mail_event(tmp_path):
    honeypot = _honeypot(tmp_path)

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(
            b"EHLO sender.example\r\n"
            b"MAIL FROM:<alice@example.test>\r\n"
            b"RCPT TO:<bob@example.test>\r\n"
            b"DATA\r\n"
        )
        assert b"354" in _recv_until(client_sock, b"354")
        client_sock.sendall(
            b"Subject: Hello\r\n"
            b"From: Alice <alice@example.test>\r\n"
            b"To: Bob <bob@example.test>\r\n"
            b"\r\n"
            b"Body text\r\n"
            b".\r\n"
            b"QUIT\r\n"
        )
        assert b"221" in _recv_until(client_sock, b"221")

    _run_session(honeypot, script)

    events = read_jsonl(tmp_path / "log" / "log.json")
    assert len(events) == 1
    event = events[0]
    assert event["event.type"] == "mail"
    assert event["src_ip"] == "203.0.113.7"
    assert event["src_port"] == 54321
    assert event["dest_port"] > 0
    assert event["mail.envelope_from"] == "alice@example.test"
    assert event["mail.envelope_to"] == ["bob@example.test"]
    assert event["mail.header_from"] == "Alice <alice@example.test>"
    assert event["mail.header_to"] == "Bob <bob@example.test>"
    assert event["mail.subject"] == "Hello"
    assert event["mail.sending_mailserver"] == "sender.example"
    assert event["mail.truncated"] is False
    assert event["attachment.count"] == 0
    assert "attachment.files" not in event
    assert event["tls.used"] is False
    assert "Body text" not in event["smtp_input"]
    assert "MAIL FROM:<alice@example.test>" in event["smtp_input"]
    assert (tmp_path / "log" / "mails" / event["mail.eml_file"]).exists()


def test_auth_plain_splits_username_and_password(tmp_path):
    honeypot = _honeypot(tmp_path)
    token = base64.b64encode(b"\x00user@example.test\x00SecretPass").decode("ascii")

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(f"EHLO client\r\nAUTH PLAIN {token}\r\nQUIT\r\n".encode())
        assert b"221" in _recv_until(client_sock, b"221")

    _run_session(honeypot, script)
    events = read_jsonl(tmp_path / "log" / "log.json")
    auth_event = next(event for event in events if event["event.type"] == "auth")

    assert auth_event["auth.method"] == "plain"
    assert auth_event["auth.raw"] == token
    assert auth_event["auth.username"] == "user@example.test"
    assert auth_event["auth.password"] == "SecretPass"
    assert "auth.decode_error" not in auth_event
    assert any(event["event.type"] == "session" for event in events)


def test_auth_login_splits_username_and_password(tmp_path):
    honeypot = _honeypot(tmp_path)
    username = base64.b64encode(b"login-user").decode("ascii")
    password = base64.b64encode(b"login-pass").decode("ascii")

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(b"EHLO client\r\nAUTH LOGIN\r\n")
        assert b"VXNlcm5hbWU6" in _recv_until(client_sock, b"VXNlcm5hbWU6")
        client_sock.sendall(f"{username}\r\n".encode())
        assert b"UGFzc3dvcmQ6" in _recv_until(client_sock, b"UGFzc3dvcmQ6")
        client_sock.sendall(f"{password}\r\nQUIT\r\n".encode())
        assert b"221" in _recv_until(client_sock, b"221")

    _run_session(honeypot, script)
    events = read_jsonl(tmp_path / "log" / "log.json")
    auth_event = next(event for event in events if event["event.type"] == "auth")

    assert auth_event["auth.method"] == "login"
    assert auth_event["auth.username"] == "login-user"
    assert auth_event["auth.password"] == "login-pass"
    assert "auth.decode_error" not in auth_event


def test_starttls_upgrades_session_and_logs_tls_fields(tmp_path):
    server_context, material = _tls_context(tmp_path)
    honeypot = _honeypot(
        tmp_path,
        advertise_starttls=True,
        tls_context=server_context,
        tls_cert_file=material.cert_file,
    )

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(b"EHLO plain-client\r\n")
        ehlo = _recv_until(client_sock, b"250 8BITMIME")
        assert b"250-STARTTLS" in ehlo
        client_sock.sendall(b"STARTTLS\r\n")
        assert b"220" in _recv_until(client_sock, b"220")

        tls_sock = _client_tls_context().wrap_socket(
            client_sock,
            server_hostname="test.example.com",
        )
        tls_sock.sendall(b"EHLO secure-client\r\n")
        secure_ehlo = _recv_until(tls_sock, b"250 8BITMIME")
        assert b"250-STARTTLS" not in secure_ehlo
        tls_sock.sendall(
            b"MAIL FROM:<alice@example.test>\r\n"
            b"RCPT TO:<bob@example.test>\r\n"
            b"DATA\r\n"
        )
        assert b"354" in _recv_until(tls_sock, b"354")
        tls_sock.sendall(b"Subject: TLS\r\n\r\nBody\r\n.\r\nQUIT\r\n")
        assert b"221" in _recv_until(tls_sock, b"221")

    _run_session(honeypot, script)

    events = read_jsonl(tmp_path / "log" / "log.json")
    event = next(item for item in events if item["event.type"] == "mail")
    assert event["tls.used"] is True
    assert event["tls.server_name"] == "test.example.com"
    assert event["tls.cert_file"] == material.cert_file
    assert event["tls.version"].startswith("TLS")
    assert event["mail.sending_mailserver"] == "secure-client"
    assert "STARTTLS" in event["smtp_input"]


def test_implicit_tls_session_logs_tls_fields(tmp_path):
    server_context, material = _tls_context(tmp_path)
    honeypot = _honeypot(
        tmp_path,
        bind_port=8465,
        listener_name="smtps",
        implicit_tls=True,
        tls_context=server_context,
        tls_cert_file=material.cert_file,
        max_connections=0,
    )
    server_sock, client_sock = socket.socketpair()
    handler = threading.Thread(
        target=honeypot._handle_client_with_slot_release,
        args=(server_sock, ("203.0.113.8", 54322)),
    )
    handler.start()
    try:
        tls_sock = _client_tls_context().wrap_socket(
            client_sock,
            server_hostname="test.example.com",
        )
        assert tls_sock.recv(1024).startswith(b"220 ")
        tls_sock.sendall(b"EHLO tls-client\r\nQUIT\r\n")
        assert b"221" in _recv_until(tls_sock, b"221")
        tls_sock.close()
    finally:
        client_sock.close()
    handler.join(timeout=5)
    assert not handler.is_alive(), "handler thread did not exit"

    events = read_jsonl(tmp_path / "log" / "log.json")
    event = events[0]
    assert event["event.type"] == "session"
    assert event["listener.name"] == "smtps"
    assert event["listener.tls_mode"] == "implicit"
    assert event["tls.used"] is True
    assert event["tls.server_name"] == "test.example.com"


def test_implicit_tls_plain_client_is_closed_without_thread_exception(tmp_path):
    server_context, material = _tls_context(tmp_path)
    honeypot = _honeypot(
        tmp_path,
        bind_port=8465,
        listener_name="smtps",
        implicit_tls=True,
        tls_context=server_context,
        tls_cert_file=material.cert_file,
        conn_timeout=0.2,
        max_connections=0,
    )
    server_sock, client_sock = socket.socketpair()
    handler = threading.Thread(
        target=honeypot._handle_client_with_slot_release,
        args=(server_sock, ("203.0.113.9", 54323)),
    )
    handler.start()
    try:
        handler.join(timeout=2)
        assert not handler.is_alive(), "handler thread did not exit"
    finally:
        client_sock.close()


def test_rate_limit_blocks_and_logs_once_without_eml(tmp_path):
    config = RateLimitConfig(
        enabled=True,
        window_seconds=3600,
        block_seconds=3600,
        max_messages_per_ip=1,
        max_messages_per_sender=25,
        state_file=str(tmp_path / "log" / "rate_limit_state.json"),
    )
    limiter = RateLimiter(config)
    limiter.record_message("203.0.113.7", None)
    honeypot = _honeypot(tmp_path, rate_limiter=limiter)

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(
            b"EHLO sender.example\r\n"
            b"MAIL FROM:<alice@example.test>\r\n"
            b"RCPT TO:<bob@example.test>\r\n"
            b"DATA\r\n"
        )
        assert b"421" in _recv_until(client_sock, b"421")

    _run_session(honeypot, script)

    events = read_jsonl(tmp_path / "log" / "log.json")
    assert len(events) == 1
    event = events[0]
    assert event["event.type"] == "rate_limit_block"
    assert event["rate_limit.scope"] == "ip"
    assert event["rate_limit.key"] == "203.0.113.7"
    assert not list((tmp_path / "log" / "mails").glob("**/*.eml"))
