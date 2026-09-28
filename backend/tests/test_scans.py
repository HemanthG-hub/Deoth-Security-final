import json

from fastapi.testclient import TestClient

import lib.db as database
from server import app


def test_static_python_findings_have_line_evidence():
    from routers.scans import analyze_code

    code = 'password = "local-secret-123"\nsubprocess.run("grep " + user_input, shell=True)\n'
    result = analyze_code(code, "python", "sample.py")
    titles_by_line = {(finding.title, finding.line) for finding in result.vulnerabilities}
    assert ("Hardcoded secret", 1) in titles_by_line
    assert ("Command injection surface", 2) in titles_by_line
    assert result.security_score in range(101)
    assert result.risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_dependency_manifest_flags_known_vulnerable_version():
    from routers.scans import analyze_code

    result = analyze_code("requests==2.30.0\n", "auto", "requirements.txt")
    finding = next(item for item in result.vulnerabilities if "CVE-2023-32681" in item.title)
    assert finding.line == 1
    assert finding.cwe == "CWE-1104"


def test_javascript_sql_injection_and_xss_are_mapped_to_lines():
    from routers.scans import analyze_code

    code = 'const query = "SELECT * FROM products WHERE name = \'" + req.query.q;\nres.send(req.query.q);\n'
    result = analyze_code(code, "javascript", "app.js")
    assert any(item.title == "SQL injection" and item.line == 1 for item in result.vulnerabilities)
    assert any(item.title == "Cross-site scripting" and item.line == 2 for item in result.vulnerabilities)


def test_auth_validation_crypto_and_file_rules():
    from routers.scans import analyze_code

    code = (
        "debug = True\n"
        "user_id = request.args['id']\n"
        "open('/srv/' + request.args['file']).read()\n"
        "hashlib.md5(password)\n"
    )
    titles = {finding.title for finding in analyze_code(code, "python", "app.py").vulnerabilities}
    assert "Insecure authentication configuration" in titles
    assert "Missing input validation" in titles
    assert "Path traversal" in titles
    assert "Weak cryptography" in titles


def test_iot_firmware_security_rules():
    from routers.scans import analyze_code

    code = (
        'const char* WIFI_PASSWORD = "device-secret";\n'
        'const char* MQTT_BROKER = "mqtt://broker.local";\n'
        "client.setServer(MQTT_BROKER, 1883);\n"
        "ArduinoOTA.begin();\n"
    )
    titles = {finding.title for finding in analyze_code(code, "arduino", "firmware.ino").vulnerabilities}
    assert "Hardcoded secret" in titles
    assert "Unencrypted IoT communication" in titles
    assert "Insecure firmware configuration" in titles


def test_manifest_scoring_and_mock_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "scans.sqlite3")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    database.initialize_db()
    with TestClient(app) as client:
        response = client.post(
            "/api/scans",
            json={"code": json.dumps({"dependencies": {"lodash": "4.17.20"}}), "file_name": "package.json"},
        )
        assert response.status_code == 200, response.text
        scan = response.json()
        assert scan["ai_mode"] == "MOCK_AI"
        assert scan["vulnerabilities"][0]["line"] == 1
        assert client.get("/api/scans").json()[0]["id"] == scan["id"]
        assert client.get(f"/api/scans/{scan['id']}").json()["source_code"].startswith("{")


def test_pdf_report_download(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "reports.sqlite3")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    database.initialize_db()
    with TestClient(app) as client:
        created = client.post("/api/scans", json={"code": "print('safe')", "language": "python"})
        assert created.status_code == 200, created.text
        report = client.get(f"/api/scans/{created.json()['id']}/report.pdf")
        assert report.status_code == 200
        assert report.headers["content-type"].startswith("application/pdf")
        assert report.content.startswith(b"%PDF")
