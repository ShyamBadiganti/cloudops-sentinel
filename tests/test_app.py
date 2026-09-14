import pytest
from unittest.mock import patch
from app import create_app
@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
@patch("app.routes.main.get_ec2_instances", return_value=[])
@patch("app.routes.main.get_s3_buckets", return_value=[])
@patch("app.routes.main.get_iam_users", return_value=[])
@patch("app.routes.main.get_cloudwatch_metrics", return_value=[])
@patch("app.routes.main.run_security_scan", return_value=[])
def test_homepage(
    mock_security,
    mock_cloudwatch,
    mock_iam,
    mock_s3,
    mock_ec2,
    client
):
    response = client.get("/")
    assert response.status_code == 200
def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
