from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv, dotenv_values

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_ENV_FILE)


def get_sonarqube_credentials() -> tuple[str, str]:
    vals = dotenv_values(_ENV_FILE)
    url = vals.get("SONARQUBE_URL", "").rstrip("/")
    token = vals.get("SONARQUBE_TOKEN", "")
    return url, token


def is_sonarqube_available() -> bool:
    url, token = get_sonarqube_credentials()
    return bool(url and token)


SONARQUBE_UNAVAILABLE_MSG = (
    "SonarQube not configured. Set credentials in .env file:\n"
    "  SONARQUBE_URL=https://sonar.example.com\n"
    "  SONARQUBE_TOKEN=squ_xxxx"
)