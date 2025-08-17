import pytest
from app.main import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_security_headers(client):
    rv = client.get("/")
    assert rv.headers.get("X-Frame-Options") == "DENY"
    assert rv.headers.get("X-Content-Type-Options") == "nosniff"
    assert rv.headers.get("Referrer-Policy") == "no-referrer"
    assert "default-src" in rv.headers.get("Content-Security-Policy", "")
    assert "Strict-Transport-Security" in rv.headers