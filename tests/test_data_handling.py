"""
Tests for DATA reading and mail/attachment storage.
"""
import os
from pathlib import Path

from mailoney.core import SMTPLineReader
from mailoney import mail_storage


class FakeSocket:
    def __init__(self, *chunks: bytes):
        self.chunks = list(chunks)

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) <= size:
            return chunk
        self.chunks.insert(0, chunk[size:])
        return chunk[:size]


def test_read_data_single_chunk():
    reader = SMTPLineReader(
        FakeSocket(b"Subject: hi\r\n\r\nHello world\r\n.\r\n")
    )
    body, found = reader.read_data(1024)
    assert found is True
    assert body == b"Subject: hi\r\n\r\nHello world"


def test_read_data_terminator_split_across_boundary():
    reader = SMTPLineReader(FakeSocket(b"hello world\r\n", b".\r\n"))
    body, found = reader.read_data(1024)
    assert found is True
    assert body == b"hello world"


def test_read_data_preserves_pipelined_remainder():
    reader = SMTPLineReader(FakeSocket(b"body\r\n.\r\nQUIT\r\n"))
    body, found = reader.read_data(1024)
    assert found is True
    assert body == b"body"
    assert reader.readline() == b"QUIT"


def test_read_data_size_cap_truncates():
    reader = SMTPLineReader(FakeSocket(b"x" * 100))
    body, found = reader.read_data(10)
    assert found is False
    assert body == b"x" * 10


def test_store_mail_message_writes_eml_with_expected_layout(tmp_path):
    rel = mail_storage.store_mail_message(
        str(tmp_path),
        "192.0.2.1",
        "session-id",
        "message-id",
        b"Subject: hi\r\nFrom: a@example.test\r\nTo: b@example.test\r\n\r\nBody",
    )

    abs_path = tmp_path / rel["eml_file"]
    assert abs_path.exists()
    assert abs_path.read_bytes().startswith(b"Subject: hi")
    parts = Path(rel["eml_file"]).parts
    assert len(parts) == 4
    assert parts[1] == "192.0.2.1"
    assert parts[2] == "session-id"
    assert parts[3] == "message-id.eml"
    assert rel["subject"] == "hi"
    assert rel["header_from"] == "a@example.test"
    assert rel["header_to"] == "b@example.test"


def test_store_mail_message_preserves_ipv6_colons(tmp_path):
    rel = mail_storage.store_mail_message(
        str(tmp_path),
        "2001:db8::1",
        "session",
        "message",
        b"Subject: x\r\n\r\nx",
    )
    parts = Path(rel["eml_file"]).parts
    assert parts[1] == "2001:db8::1"
    assert (tmp_path / rel["eml_file"]).exists()


def test_store_mail_message_strips_unsafe_ip_characters(tmp_path):
    rel = mail_storage.store_mail_message(
        str(tmp_path),
        "../../../etc/passwd",
        "session",
        "message",
        b"Subject: x\r\n\r\nx",
    )
    parts = Path(rel["eml_file"]).parts
    assert ".." not in parts
    assert "etc" not in parts
    assert (tmp_path / rel["eml_file"]).exists()


def test_store_mail_message_sets_restrictive_mode(tmp_path):
    rel = mail_storage.store_mail_message(
        str(tmp_path), "10.0.0.1", "session", "message", b"Subject: x\r\n\r\nx"
    )
    mode = os.stat(tmp_path / rel["eml_file"]).st_mode & 0o777
    assert mode == 0o640


def test_store_mail_message_extracts_attachments(tmp_path):
    raw = (
        b"From: a@example.test\r\n"
        b"To: b@example.test\r\n"
        b"Subject: with attachment\r\n"
        b"Content-Type: multipart/mixed; boundary=frontier\r\n"
        b"\r\n"
        b"--frontier\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Body\r\n"
        b"--frontier\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Disposition: attachment; filename=\"note.txt\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"aGVsbG8=\r\n"
        b"--frontier--\r\n"
    )

    rel = mail_storage.store_mail_message(
        str(tmp_path), "192.0.2.1", "session", "message", raw
    )

    assert len(rel["attachments"]) == 1
    attachment = rel["attachments"][0]
    assert attachment["filename"] == "note.txt"
    assert attachment["content_type"] == "text/plain"
    assert attachment["size"] == 5
    assert (tmp_path / attachment["path"]).read_bytes() == b"hello"


def test_store_mail_message_can_skip_eml_write(tmp_path):
    rel = mail_storage.store_mail_message(
        str(tmp_path),
        "192.0.2.1",
        "session-id",
        "message-id",
        b"Subject: hi\r\nFrom: a@example.test\r\nTo: b@example.test\r\n\r\nBody",
        save_mail_body=False,
        save_attachments=False,
    )

    assert "eml_file" not in rel
    assert "eml_size" not in rel
    assert rel["subject"] == "hi"
    assert rel["header_from"] == "a@example.test"
    assert rel["header_to"] == "b@example.test"
    assert not list(tmp_path.glob("**/*.eml"))


def test_store_mail_message_can_skip_attachment_write(tmp_path):
    raw = (
        b"Subject: with attachment\r\n"
        b"Content-Type: multipart/mixed; boundary=frontier\r\n"
        b"\r\n"
        b"--frontier\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Body\r\n"
        b"--frontier\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Disposition: attachment; filename=\"note.txt\"\r\n"
        b"\r\n"
        b"hello\r\n"
        b"--frontier--\r\n"
    )

    rel = mail_storage.store_mail_message(
        str(tmp_path),
        "192.0.2.1",
        "session-id",
        "message-id",
        raw,
        save_attachments=False,
    )

    assert rel["attachments"] == []
    assert (tmp_path / rel["eml_file"]).exists()
    assert not list(tmp_path.glob("**/attachments/*"))
