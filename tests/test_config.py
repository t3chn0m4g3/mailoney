"""
Tests for configuration loading.
"""
import pytest

from mailoney.config import Settings, configure_logging, get_settings


def test_default_settings(tmp_path):
    settings = get_settings(str(tmp_path / "missing.toml"))

    assert settings.server.server_name == "mail01.localdomain"
    assert [listener.port for listener in settings.server.listeners] == [25, 587, 465]
    assert settings.server.listeners[0].starttls is True
    assert settings.server.listeners[2].implicit_tls is True
    assert settings.logging.log_file == "log/log.json"
    assert settings.storage.mail_dir == "log/mails"
    assert settings.storage.save_mail_bodies is True
    assert settings.storage.save_attachments is True
    assert settings.tls.enabled is True
    assert settings.tls.cert_file == "log/tls/server.crt"
    assert settings.rate_limit.enabled is True


def test_legacy_single_listener_toml_is_translated(tmp_path):
    config_file = tmp_path / "mailoney.toml"
    config_file.write_text(
        """
[server]
bind_ip = "127.0.0.1"
bind_port = 2525
max_connections = 5

[logging]
log_file = "out/log.json"

[storage]
extract_attachments = false

[rate_limit]
max_messages_per_sender = 3
""",
        encoding="utf-8",
    )

    settings = get_settings(str(config_file))

    assert len(settings.server.listeners) == 1
    assert settings.server.listeners[0].bind_ip == "127.0.0.1"
    assert settings.server.listeners[0].port == 2525
    assert settings.server.max_connections == 5
    assert settings.logging.log_file == "out/log.json"
    assert settings.storage.save_attachments is False
    assert settings.rate_limit.max_messages_per_sender == 3


def test_explicit_listener_settings(tmp_path):
    config_file = tmp_path / "mailoney.toml"
    config_file.write_text(
        """
[server]
server_name = "mx1.test"

[[server.listeners]]
name = "smtp-alt"
bind_ip = "127.0.0.1"
port = 2525
starttls = false
implicit_tls = false
""",
        encoding="utf-8",
    )

    settings = get_settings(str(config_file))

    assert settings.server.server_name == "mx1.test"
    assert len(settings.server.listeners) == 1
    assert settings.server.listeners[0].name == "smtp-alt"
    assert settings.server.listeners[0].port == 2525
    assert settings.server.listeners[0].starttls is False


def test_env_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("MAILONEY_BIND_IP", "127.0.0.2")
    monkeypatch.setenv("MAILONEY_BIND_PORT", "2526")
    monkeypatch.setenv("MAILONEY_LOG_FILE", "env/log.json")
    monkeypatch.setenv("MAILONEY_SAVE_MAIL_BODIES", "false")
    monkeypatch.setenv("MAILONEY_SAVE_ATTACHMENTS", "false")
    monkeypatch.setenv("MAILONEY_TLS_CERT_FILE", "env/server.crt")
    monkeypatch.setenv("MAILONEY_RATE_LIMIT_ENABLED", "no")

    settings = get_settings(str(tmp_path / "missing.toml"))

    assert len(settings.server.listeners) == 1
    assert settings.server.listeners[0].bind_ip == "127.0.0.2"
    assert settings.server.listeners[0].port == 2526
    assert settings.logging.log_file == "env/log.json"
    assert settings.storage.save_mail_bodies is False
    assert settings.storage.save_attachments is False
    assert settings.tls.cert_file == "env/server.crt"
    assert settings.rate_limit.enabled is False


def test_configure_logging():
    configure_logging("DEBUG")
    configure_logging("INFO")

    with pytest.raises(ValueError):
        configure_logging("NOT_A_LEVEL")


def test_settings_validation():
    settings = Settings.model_validate(
        {"server": {"listeners": [{"bind_ip": "127.0.0.1", "port": "2525"}]}}
    )
    assert settings.server.listeners[0].port == 2525
