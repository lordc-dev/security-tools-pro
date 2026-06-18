import pytest
from pathlib import Path
from unittest.mock import patch

import core.config as config_mod
from core.config import (
    get_sonarqube_credentials,
    is_sonarqube_available,
    SONARQUBE_UNAVAILABLE_MSG,
)


@pytest.fixture
def mock_env_file(tmp_path):
    """Create a temporary .env file and patch the config module to use it."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "SONARQUBE_URL=https://sonar.example.com:9000\n"
        "SONARQUBE_TOKEN=squ_abcdef123456\n"
    )
    with patch.object(config_mod, "_ENV_FILE", env_file):
        yield env_file


@pytest.fixture
def mock_empty_env(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("")
    with patch.object(config_mod, "_ENV_FILE", env_file):
        yield env_file


@pytest.fixture
def mock_missing_env(tmp_path):
    env_file = tmp_path / ".nonexistent.env"
    with patch.object(config_mod, "_ENV_FILE", env_file):
        yield env_file


class TestGetSonarqubeCredentials:
    def test_returns_url_and_token(self, mock_env_file):
        url, token = get_sonarqube_credentials()
        assert url == "https://sonar.example.com:9000"
        assert token == "squ_abcdef123456"

    def test_strips_trailing_slash(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "SONARQUBE_URL=https://sonar.example.com:9000/\n"
            "SONARQUBE_TOKEN=squ_token\n"
        )
        with patch.object(config_mod, "_ENV_FILE", env_file):
            url, token = get_sonarqube_credentials()
        assert url == "https://sonar.example.com:9000"
        assert not url.endswith("/")

    def test_empty_env_returns_empty(self, mock_empty_env):
        url, token = get_sonarqube_credentials()
        assert url == ""
        assert token == ""

    def test_missing_env_returns_empty(self, mock_missing_env):
        url, token = get_sonarqube_credentials()
        assert url == ""
        assert token == ""

    def test_only_url_set(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SONARQUBE_URL=https://sonar.example.com\n")
        with patch.object(config_mod, "_ENV_FILE", env_file):
            url, token = get_sonarqube_credentials()
        assert url == "https://sonar.example.com"
        assert token == ""

    def test_only_token_set(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SONARQUBE_TOKEN=squ_onlytoken\n")
        with patch.object(config_mod, "_ENV_FILE", env_file):
            url, token = get_sonarqube_credentials()
        assert url == ""
        assert token == "squ_onlytoken"


class TestIsSonarqubeAvailable:
    def test_available_when_both_set(self, mock_env_file):
        assert is_sonarqube_available() is True

    def test_unavailable_when_empty(self, mock_empty_env):
        assert is_sonarqube_available() is False

    def test_unavailable_when_missing(self, mock_missing_env):
        assert is_sonarqube_available() is False

    def test_unavailable_when_only_url(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SONARQUBE_URL=https://sonar.example.com\n")
        with patch.object(config_mod, "_ENV_FILE", env_file):
            assert is_sonarqube_available() is False

    def test_unavailable_when_only_token(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SONARQUBE_TOKEN=squ_token\n")
        with patch.object(config_mod, "_ENV_FILE", env_file):
            assert is_sonarqube_available() is False


class TestSonarqubeUnavailableMsg:
    def test_message_contains_url_hint(self):
        assert "SONARQUBE_URL" in SONARQUBE_UNAVAILABLE_MSG

    def test_message_contains_token_hint(self):
        assert "SONARQUBE_TOKEN" in SONARQUBE_UNAVAILABLE_MSG

    def test_message_mentions_env_file(self):
        assert ".env" in SONARQUBE_UNAVAILABLE_MSG