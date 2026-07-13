import pytest

from secscan.secman_client import SecmanPushError, login, push_vulnerability


class _FakeResponse:
    def __init__(self, status_code, json_body=None, headers=None):
        self.status_code = status_code
        self._json_body = json_body or {}
        self.headers = headers or {}

    def json(self):
        return self._json_body

    @property
    def text(self):
        import json
        return json.dumps(self._json_body)


def test_login_extracts_token_from_set_cookie(monkeypatch):
    def fake_post(url, json, timeout):
        assert url == "https://secman.example.com/api/auth/login"
        assert json == {"username": "vulnbot", "password": "pw"}
        return _FakeResponse(200, {"id": 1, "username": "vulnbot"}, headers={
            "Set-Cookie": "secman_auth=abc.def.ghi; Path=/; HttpOnly; Secure; SameSite=Lax"
        })

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    token = login("https://secman.example.com", "vulnbot", "pw")
    assert token == "abc.def.ghi"


def test_login_401_raises_secman_push_error(monkeypatch):
    def fake_post(url, json, timeout):
        return _FakeResponse(401, {"error": "Invalid credentials"})

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    with pytest.raises(SecmanPushError, match="401|Invalid credentials"):
        login("https://secman.example.com", "vulnbot", "wrongpw")


def test_login_no_cookie_raises_secman_push_error(monkeypatch):
    def fake_post(url, json, timeout):
        return _FakeResponse(200, {"id": 1}, headers={})

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    with pytest.raises(SecmanPushError, match="token"):
        login("https://secman.example.com", "vulnbot", "pw")


def test_push_vulnerability_sends_bearer_and_body(monkeypatch):
    captured = {}

    def fake_post(url, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _FakeResponse(200, {
            "success": True, "message": "ok", "assetId": 1, "assetName": "octo/repo",
            "assetCreated": True, "vulnerabilityId": "SECSCAN:CWE-89:abc123", "id": 5,
            "operation": "CREATED",
        })

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    result = push_vulnerability(
        "https://secman.example.com", "abc.def.ghi",
        hostname="octo/repo", cve="SECSCAN:CWE-89:abc123", criticality="HIGH", days_open=3,
    )

    assert captured["url"] == "https://secman.example.com/api/vulnerabilities/cli-add"
    assert captured["json"] == {
        "hostname": "octo/repo", "cve": "SECSCAN:CWE-89:abc123",
        "criticality": "HIGH", "daysOpen": 3,
    }
    assert captured["headers"] == {"Authorization": "Bearer abc.def.ghi"}
    assert result["operation"] == "CREATED"


def test_push_vulnerability_400_raises_without_retrying_forever(monkeypatch):
    def fake_post(url, json, headers, timeout):
        return _FakeResponse(400, {"error": "Criticality must be CRITICAL, HIGH, MEDIUM, or LOW"})

    import secscan.secman_client as client
    monkeypatch.setattr(client.requests, "post", fake_post)

    with pytest.raises(SecmanPushError, match="400"):
        push_vulnerability(
            "https://secman.example.com", "tok",
            hostname="octo/repo", cve="bad", criticality="NOPE", days_open=0,
        )
