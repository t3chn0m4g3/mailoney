#!/usr/bin/env python3
"""
Smoke-test a running Mailoney instance.

Defaults match docker-compose.yml. Override with CLI flags or the
MAILONEY_TEST_* environment variables documented in parse_args().
"""
from __future__ import annotations

import argparse
import base64
import os
import socket
import ssl
import sys
import uuid
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Target:
    host: str
    smtp_port: int
    submission_port: int
    smtps_port: int
    timeout: float


class SMTPTestClient:
    def __init__(
        self,
        target: Target,
        port: int,
        *,
        implicit_tls: bool = False,
    ):
        self.target = target
        self.port = port
        raw_socket = socket.create_connection(
            (target.host, port),
            timeout=target.timeout,
        )
        raw_socket.settimeout(target.timeout)
        if implicit_tls:
            raw_socket = self._tls_context().wrap_socket(
                raw_socket,
                server_hostname=target.host,
            )
            raw_socket.settimeout(target.timeout)
        self.sock = raw_socket
        self.file = self.sock.makefile("rb")

    @staticmethod
    def _tls_context() -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def close(self) -> None:
        try:
            self.file.close()
        finally:
            self.sock.close()

    def read_response(self, expected_code: Optional[int] = None) -> tuple[int, list[str]]:
        lines = []
        while True:
            raw_line = self.file.readline()
            if not raw_line:
                raise AssertionError("SMTP server closed the connection")
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
                break

        code = int(lines[-1][:3])
        if expected_code is not None and code != expected_code:
            raise AssertionError(
                f"expected SMTP {expected_code}, got {code}: {lines!r}"
            )
        return code, lines

    def command(
        self,
        command: str,
        expected_code: Optional[int] = None,
    ) -> tuple[int, list[str]]:
        self.sock.sendall(command.encode("ascii") + b"\r\n")
        return self.read_response(expected_code)

    def ehlo(
        self,
        name: str,
        *,
        expect_starttls: bool = False,
        expect_no_starttls: bool = False,
    ) -> list[str]:
        _, lines = self.command(f"EHLO {name}", 250)
        has_starttls = any("STARTTLS" in line.upper() for line in lines)
        if expect_starttls and not has_starttls:
            raise AssertionError(f"STARTTLS not advertised in EHLO response: {lines!r}")
        if expect_no_starttls and has_starttls:
            raise AssertionError(f"STARTTLS still advertised after TLS: {lines!r}")
        return lines

    def starttls(self) -> None:
        self.command("STARTTLS", 220)
        tls_socket = self._tls_context().wrap_socket(
            self.sock,
            server_hostname=self.target.host,
        )
        tls_socket.settimeout(self.target.timeout)
        self.sock = tls_socket
        self.file = self.sock.makefile("rb")

    def auth_plain(self) -> None:
        token = base64.b64encode(b"\x00smoke-user\x00smoke-pass").decode("ascii")
        self.command(f"AUTH PLAIN {token}", 235)

    def auth_login(self) -> None:
        username = base64.b64encode(b"smoke-login-user").decode("ascii")
        password = base64.b64encode(b"smoke-login-pass").decode("ascii")
        self.command("AUTH LOGIN", 334)
        self.command(username, 334)
        self.command(password, 235)

    def send_mail(self, label: str) -> None:
        unique = uuid.uuid4().hex[:12]
        sender = f"sender-{unique}@example.test"
        recipient = f"recipient-{unique}@example.test"
        second_recipient = f"second-{unique}@example.test"
        self.command(f"MAIL FROM:<{sender}>", 250)
        self.command(f"RCPT TO:<{recipient}>", 250)
        self.command(f"RCPT TO:<{second_recipient}>", 250)
        self.command("DATA", 354)
        body = (
            f"Subject: Mailoney smoke test {label}\r\n"
            f"From: {sender}\r\n"
            f"To: {recipient}, {second_recipient}\r\n"
            "\r\n"
            f"Smoke test label: {label}\r\n"
            f"Message id fragment: {unique}\r\n"
            ".\r\n"
        )
        self.sock.sendall(body.encode("utf-8"))
        self.read_response(250)

    def quit(self) -> None:
        self.command("QUIT", 221)


def run_positive_case(
    target: Target,
    label: str,
    port: int,
    *,
    implicit_tls: bool = False,
    use_starttls: bool = False,
    auth: Optional[str] = None,
) -> None:
    client = SMTPTestClient(target, port, implicit_tls=implicit_tls)
    try:
        client.read_response(220)
        client.ehlo(
            f"{label}.smoke.localdomain",
            expect_starttls=use_starttls,
            expect_no_starttls=implicit_tls,
        )
        if use_starttls:
            client.starttls()
            client.ehlo(
                f"{label}.tls.smoke.localdomain",
                expect_no_starttls=True,
            )
        if auth == "plain":
            client.auth_plain()
        elif auth == "login":
            client.auth_login()
        client.send_mail(label)
        client.quit()
    finally:
        client.close()
    print(f"[PASS] {label} on {target.host}:{port}")


def run_plain_to_implicit_tls_negative_case(target: Target) -> None:
    sock = socket.create_connection(
        (target.host, target.smtps_port),
        timeout=target.timeout,
    )
    sock.settimeout(target.timeout)
    try:
        sock.sendall(b"EHLO plain-client\r\n")
        try:
            data = sock.recv(3)
        except (ConnectionResetError, socket.timeout):
            print(f"[PASS] smtps-plain-negative on {target.host}:{target.smtps_port}")
            return
        if not data:
            print(f"[PASS] smtps-plain-negative on {target.host}:{target.smtps_port}")
            return
        if data.startswith(b"220"):
            raise AssertionError("implicit TLS listener sent a cleartext SMTP banner")
        print(f"[PASS] smtps-plain-negative on {target.host}:{target.smtps_port}")
    finally:
        sock.close()


def env_value(name: str, default: str) -> str:
    return os.environ.get(name, default)


def parse_args() -> Target:
    parser = argparse.ArgumentParser(
        description="Smoke-test a running Mailoney SMTP honeypot.",
    )
    parser.add_argument(
        "--host",
        default=env_value("MAILONEY_TEST_HOST", "127.0.0.1"),
        help="target host (env: MAILONEY_TEST_HOST, default: 127.0.0.1)",
    )
    parser.add_argument(
        "--smtp-port",
        type=int,
        default=int(env_value("MAILONEY_TEST_SMTP_PORT", "25")),
        help="SMTP port (env: MAILONEY_TEST_SMTP_PORT, default: 25)",
    )
    parser.add_argument(
        "--submission-port",
        type=int,
        default=int(env_value("MAILONEY_TEST_SUBMISSION_PORT", "587")),
        help="Submission port (env: MAILONEY_TEST_SUBMISSION_PORT, default: 587)",
    )
    parser.add_argument(
        "--smtps-port",
        type=int,
        default=int(env_value("MAILONEY_TEST_SMTPS_PORT", "465")),
        help="implicit TLS SMTPS port (env: MAILONEY_TEST_SMTPS_PORT, default: 465)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(env_value("MAILONEY_TEST_TIMEOUT", "5")),
        help="socket timeout in seconds (env: MAILONEY_TEST_TIMEOUT, default: 5)",
    )
    args = parser.parse_args()
    return Target(
        host=args.host,
        smtp_port=args.smtp_port,
        submission_port=args.submission_port,
        smtps_port=args.smtps_port,
        timeout=args.timeout,
    )


def main() -> int:
    target = parse_args()
    cases = [
        ("smtp-plain", target.smtp_port, False, False, "plain"),
        ("smtp-starttls", target.smtp_port, False, True, "login"),
        ("submission-plain", target.submission_port, False, False, None),
        ("submission-starttls", target.submission_port, False, True, "plain"),
        ("smtps-implicit", target.smtps_port, True, False, "login"),
    ]
    for label, port, implicit_tls, use_starttls, auth in cases:
        run_positive_case(
            target,
            label,
            port,
            implicit_tls=implicit_tls,
            use_starttls=use_starttls,
            auth=auth,
        )
    run_plain_to_implicit_tls_negative_case(target)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
