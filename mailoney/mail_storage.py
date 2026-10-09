"""
Filesystem storage for captured SMTP messages and attachments.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _safe_ip_segment(src_ip: str) -> str:
    cleaned = "".join(c for c in src_ip if c.isalnum() or c in ".:%_-")
    return cleaned or "unknown"


def _safe_filename(name: str, fallback: str = "attachment.bin") -> str:
    name = Path(name or fallback).name
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .")
    return name or fallback


def _today_segment() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _decode_header_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _payload_bytes(part) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is not None:
        return payload
    raw_payload = part.get_payload()
    if isinstance(raw_payload, str):
        charset = part.get_content_charset() or "utf-8"
        return raw_payload.encode(charset, errors="replace")
    if raw_payload is None:
        return b""
    return bytes(raw_payload)


def _unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    counter = 2
    while True:
        candidate = directory / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def _write_restricted(path: Path, data: bytes) -> None:
    existed = path.exists()
    with path.open("wb") as f:
        f.write(data)
    if not existed:
        os.chmod(path, 0o640)


def store_mail_message(
    mail_dir: str,
    src_ip: str,
    session_id: str,
    message_id: str,
    raw_message: bytes,
    extract_attachments: Optional[bool] = None,
    save_mail_body: bool = True,
    save_attachments: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Parse a full RFC 5322 message and optionally persist it as ``.eml`` and
    extract attachments.

    Returns metadata ready to be mapped into flat ``mail.*`` and
    ``attachment.*`` JSON fields by the caller.
    """
    if save_attachments is None:
        save_attachments = extract_attachments if extract_attachments is not None else True

    root = Path(mail_dir)
    rel_dir = Path(_today_segment()) / _safe_ip_segment(src_ip) / session_id
    abs_dir = root / rel_dir

    msg = BytesParser(policy=policy.default).parsebytes(raw_message)
    attachments: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {
        "header_from": _decode_header_value(msg.get("From")),
        "header_to": _decode_header_value(msg.get("To")),
        "subject": _decode_header_value(msg.get("Subject")),
        "attachments": attachments,
    }

    if save_mail_body:
        abs_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        eml_name = _safe_filename(f"{message_id}.eml", "message.eml")
        rel_eml = rel_dir / eml_name
        abs_eml = root / rel_eml
        _write_restricted(abs_eml, raw_message)
        metadata["eml_file"] = str(rel_eml)
        metadata["eml_size"] = len(raw_message)
        logger.info("Stored mail body (%s bytes) at %s", len(raw_message), rel_eml)

    if save_attachments:
        attachment_dir = abs_dir / "attachments"
        rel_attachment_dir = rel_dir / "attachments"

        for index, part in enumerate(msg.walk(), start=1):
            if part.is_multipart():
                continue

            filename = part.get_filename()
            disposition = part.get_content_disposition()
            if disposition != "attachment" and not filename:
                continue

            original_filename = _decode_header_value(filename) if filename else None
            safe_name = _safe_filename(
                original_filename or f"attachment-{index}.bin",
                f"attachment-{index}.bin",
            )
            safe_name = f"{message_id}-{index}-{safe_name}"
            attachment_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
            abs_attachment = _unique_path(attachment_dir, safe_name)

            data = _payload_bytes(part)
            _write_restricted(abs_attachment, data)

            rel_attachment = rel_attachment_dir / abs_attachment.name
            attachments.append(
                {
                    "filename": original_filename or abs_attachment.name,
                    "path": str(rel_attachment),
                    "content_type": part.get_content_type(),
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )

    return metadata
