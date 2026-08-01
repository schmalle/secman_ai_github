from secscan.findings import Finding
from secscan.redact import redact_secrets


def test_redacts_aws_access_key_id():
    text = "Hardcoded credential: AKIAABCDEFGHIJKLMNOP found in config.py"
    out = redact_secrets(text)
    assert "AKIAABCDEFGHIJKLMNOP" not in out
    assert "REDACTED" in out


def test_redacts_github_token():
    text = "Leaked PAT: ghp_1234567890abcdefghijklmnopqrstuvwxyz in CI logs"
    out = redact_secrets(text)
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in out


def test_redacts_private_key_block():
    text = (
        "Found key material:\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaQdgWXneZTMh8=\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    out = redact_secrets(text)
    assert "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaQdgWXneZTMh8=" not in out
    assert "BEGIN RSA PRIVATE KEY" not in out


def test_redacts_labelled_password_assignment():
    text = 'db config: password="Sup3rSecretValue123"'
    out = redact_secrets(text)
    assert "Sup3rSecretValue123" not in out


def test_leaves_ordinary_prose_untouched():
    text = "This endpoint concatenates user input directly into a SQL query, enabling SQL injection."
    assert redact_secrets(text) == text


def test_finding_description_is_redacted_on_construction():
    finding = Finding(
        severity="critical",
        title="Hardcoded AWS key",
        description="Found AKIAABCDEFGHIJKLMNOP hardcoded in settings.py line 12.",
        file_path="settings.py",
        recommendation="Rotate the key: password=Sup3rSecretRotateMe",
    )
    assert "AKIAABCDEFGHIJKLMNOP" not in finding.description
    assert "Sup3rSecretRotateMe" not in finding.recommendation


def test_empty_and_none_safe():
    assert redact_secrets("") == ""
