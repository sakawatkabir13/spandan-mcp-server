import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from spandan_mcp.server import CONTRACT, Settings, create_app

PRIVATE = Ed25519PrivateKey.generate()
PUBLIC = (
    PRIVATE.public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)


def token(*, role="patient", tools=None, audience="spandan-mcp", action_id=None):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        dict(
            sub=str(uuid4()),
            ver=0,
            role=role,
            tools=tools or ["help"],
            aud=audience,
            iss="spandan",
            exp=now + timedelta(seconds=90),
            iat=now,
            jti=str(uuid4()),
            contract=CONTRACT["version"],
            conversation_id=str(uuid4()),
            fingerprint="a" * 64,
            action_id=action_id,
        ),
        PRIVATE,
        algorithm="EdDSA",
    )


def application(handler=None):
    return create_app(
        Settings(
            env="development",
            api_base_url="http://spandan/internal",
            service_token="s" * 40,
            public_key=PUBLIC,
            allowed_hosts="mcp",
        ),
        http_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://spandan"
        ),
    )


def test_pinned_contract_integrity():
    encoded = json.dumps(CONTRACT["tools"], sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(encoded.encode()).hexdigest() == CONTRACT["sha256"]
    forbidden = ("medical_records", "prescriptions", "password", "shell", "sql", "browse")
    assert not any(word in tool["name"] for tool in CONTRACT["tools"] for word in forbidden)


@pytest.mark.parametrize("scheme,secure", [("http", False), ("https", True)])
def test_production_requires_mutual_tls(scheme, secure):
    with pytest.raises(ValueError):
        Settings(api_base_url=f"{scheme}://spandan/internal", service_token="s" * 40, public_key=PUBLIC)


async def test_unauthenticated_wrong_audience_and_old_protocol():
    app = application()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://mcp") as client:
        assert (await client.get("/health/ready")).status_code == 200
        assert (await client.post("/mcp", headers={"MCP-Protocol-Version": "2026-07-28"})).status_code == 401
        assert (
            await client.post(
                "/mcp",
                headers={
                    "MCP-Protocol-Version": "2026-07-28",
                    "Authorization": "Bearer " + token(audience="spandan-chat-api"),
                },
            )
        ).status_code == 401
        assert (
            await client.post(
                "/mcp", headers={"MCP-Protocol-Version": "2025-06-18", "Authorization": "Bearer " + token()}
            )
        ).status_code == 400


async def test_stateless_discovery_schema_and_token_exchange():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("/exchange"):
            assert request.headers["X-MCP-Service-Token"] == "s" * 40
            return httpx.Response(
                200, json={"contract_version": CONTRACT["version"], "access_token": "distinct-api-token"}
            )
        assert request.headers["Authorization"] == "Bearer distinct-api-token"
        return httpx.Response(
            200, json={"contract_version": CONTRACT["version"], "success": True, "data": {"items": []}}
        )

    app = application(handler)
    async with app.app.router.lifespan_context(app.app):

        async def call_one():
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), headers={"Authorization": "Bearer " + token()}
            ) as http:
                async with Client(
                    streamable_http_client("http://mcp/mcp", http_client=http, terminate_on_close=False),
                    mode="2026-07-28",
                    cache=None,
                ) as client:
                    assert [x.name for x in (await client.list_tools()).tools] == ["help"]
                    invalid = await client.call_tool("help", {"unknown": True})
                    assert invalid.is_error
                    assert (await client.call_tool("help", {})).structured_content["success"]

        await asyncio.gather(call_one(), call_one())
    assert len(requests) == 4


async def test_execution_requires_exact_action_grant():
    app = application(lambda _: pytest.fail("No callback is allowed for a mismatched grant"))
    async with app.app.router.lifespan_context(app.app):
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            headers={
                "Authorization": "Bearer " + token(tools=["execute_confirmed_action"], action_id=str(uuid4()))
            },
        ) as http:
            async with Client(
                streamable_http_client("http://mcp/mcp", http_client=http, terminate_on_close=False),
                mode="2026-07-28",
                cache=None,
            ) as client:
                result = await client.call_tool("execute_confirmed_action", {"action_id": str(uuid4())})
                assert result.is_error
