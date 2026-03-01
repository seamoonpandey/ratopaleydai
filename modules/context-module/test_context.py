"""
tests for the context module fastapi app.
uses httpx async client with fastapi testclient pattern.
mocks heavy dependencies (ai classifier, probe injector, char fuzzer).
"""

import sys
import os
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

# add module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from app import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "context-module"
    assert "ai_model_loaded" in data


@pytest.mark.anyio
async def test_analyze_empty_params():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": [],
        })
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_analyze_missing_url():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "params": ["q"],
        })
    assert resp.status_code == 422


@pytest.mark.anyio
@patch("app.inject_probes", new_callable=AsyncMock)
@patch("app.fuzz_chars", new_callable=AsyncMock)
@patch("app.analyze_reflection")
@patch("app.get_primary_context")
@patch("app.get_dom_context")
async def test_analyze_param_no_reflection(
    mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """when probe is not reflected, param gets default context"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>hello</html>", "status_code": 200}
    }
    mock_reflection.return_value = []  # no reflection found

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert "q" in data
    assert data["q"]["reflects_in"] == "none"


@pytest.mark.anyio
@patch("app.inject_probes", new_callable=AsyncMock)
@patch("app.fuzz_chars", new_callable=AsyncMock)
@patch("app.analyze_reflection")
@patch("app.get_primary_context")
@patch("app.get_dom_context")
@patch("app.classifier")
async def test_analyze_param_with_reflection(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """when probe is reflected and AI is confident, use AI context"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>rsp123</html>", "status_code": 200}
    }
    mock_reflection.return_value = [
        {"position": "html_text", "context_snippet": "<p>rsp123</p>"}
    ]
    mock_primary.return_value = "html_text"
    mock_dom.return_value = "html_text"
    mock_classifier.classify.return_value = {
        "context_type": "html_text",
        "confidence": 0.95,
    }
    mock_fuzz.return_value = ["<", ">", "'", '"']

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["q"]["reflects_in"] == "html_text"
    assert data["q"]["context_confidence"] >= 0.8
    assert len(data["q"]["allowed_chars"]) > 0
