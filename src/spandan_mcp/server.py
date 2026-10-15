import contextvars
import json
import ssl
from pathlib import Path
from urllib.parse import urlparse

import httpx
import jwt
from jsonschema import Draft202012Validator, FormatChecker
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent, Tool
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

CONTRACT = json.loads(Path(__file__).with_name("contract.json").read_text())
VERSION = CONTRACT["version"]
CATALOG = {tool["name"]: tool for tool in CONTRACT["tools"]}
IDENTITY = contextvars.ContextVar("mcp_identity")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MCP_", env_file=".env", extra="ignore")
    env: str = "production"
    api_base_url: str
    service_token: str
    public_key: str
    allowed_hosts: str = "localhost,127.0.0.1"
    tls_ca: str = ""
    tls_cert: str = ""
    tls_key: str = ""

    @model_validator(mode="after")
    def secure_configuration(self):
        target = urlparse(self.api_base_url)
        if not target.hostname or target.username or target.password or target.query or target.fragment:
            raise ValueError("Configure a fixed Spandan tool API URL")
        if len(self.service_token) < 32:
            raise ValueError("A private service token of at least 32 characters is required")
        if self.env == "production" and (
            target.scheme != "https" or not all((self.tls_ca, self.tls_cert, self.tls_key))
        ):
            raise ValueError("Production API calls require HTTPS and mutual TLS credentials")
        return self


def result(data=None, *, error=None):
    payload = {"contract_version": VERSION, "success": error is None}
    payload["error" if error else "data"] = error if error else data
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, separators=(",", ":")))],
        structuredContent=payload,
        isError=error is not None,
    )


class SpandanServer(MCPServer):
    def __init__(self, settings, http_factory=None):
        super().__init__(name="Spandan tools", version="0.1.0")
        self.spandan_settings = settings
        self.http_factory = http_factory

    async def list_tools(self):
        claims, _ = IDENTITY.get()
        return [
            Tool(
                name=tool["name"],
                description=tool["description"],
                inputSchema=tool["inputSchema"],
                _meta={"contract_version": VERSION, "contract_sha256": CONTRACT["sha256"]},
            )
            for tool in CATALOG.values()
            if tool["name"] in claims["tools"] and claims["role"] in tool["roles"]
        ]

    async def call_tool(self, name, arguments, context=None):
        claims, subject_token = IDENTITY.get()
        tool = CATALOG.get(name)
        if not tool or name not in claims["tools"] or claims["role"] not in tool["roles"]:
            return result(
                error={"code": "FORBIDDEN", "message": "This tool is not permitted.", "status_code": 403}
            )
        if list(
            Draft202012Validator(tool["inputSchema"], format_checker=FormatChecker()).iter_errors(arguments)
        ):
            return result(
                error={
                    "code": "VALIDATION_ERROR",
                    "message": "Tool arguments do not match the contract.",
                    "status_code": 422,
                }
            )
        if name == "execute_confirmed_action" and claims.get("action_id") != arguments["action_id"]:
            return result(
                error={
                    "code": "CONFIRMATION_REQUIRED",
                    "message": "An exact confirmed-action grant is required.",
                    "status_code": 403,
                }
            )
        settings = self.spandan_settings
        tls = ssl.create_default_context(cafile=settings.tls_ca or None)
        if settings.tls_cert and settings.tls_key:
            tls.load_cert_chain(settings.tls_cert, settings.tls_key)
        factory = self.http_factory or (
            lambda: httpx.AsyncClient(verify=tls, timeout=25, follow_redirects=False, trust_env=False)
        )
        try:
            async with factory() as client:
                service_headers = {"X-MCP-Service-Token": settings.service_token}
                exchange = await client.post(
                    settings.api_base_url + "/exchange",
                    headers=service_headers,
                    json={"subject_token": subject_token, "tool_name": name, "contract_version": VERSION},
                )
                if exchange.status_code != 200:
                    return self._api_error(exchange)
                token_data = exchange.json()
                if token_data.get("contract_version") != VERSION:
                    return result(
                        error={
                            "code": "MCP_CONTRACT_MISMATCH",
                            "message": "Incompatible tool API.",
                            "status_code": 503,
                        }
                    )
                response = await client.post(
                    settings.api_base_url + "/call/" + name,
                    headers={**service_headers, "Authorization": "Bearer " + token_data["access_token"]},
                    json={"arguments": arguments, "contract_version": VERSION},
                )
                if response.status_code != 200:
                    return self._api_error(response)
                payload = response.json()
                if payload.get("contract_version") != VERSION or not payload.get("success"):
                    return result(
                        error={
                            "code": "MCP_CONTRACT_MISMATCH",
                            "message": "Incompatible tool response.",
                            "status_code": 503,
                        }
                    )
                return result(payload["data"])
        except Exception:
            return result(
                error={
                    "code": "TOOL_UNAVAILABLE",
                    "message": "Spandan could not confirm the operation. Check its status before retrying.",
                    "status_code": 503,
                }
            )

    def _api_error(self, response):
        try:
            error = response.json()["error"]
            return result(
                error={
                    "code": error["code"],
                    "message": error["message"],
                    "status_code": response.status_code,
                }
            )
        except Exception:
            return result(
                error={
                    "code": "TOOL_UNAVAILABLE",
                    "message": "The Spandan API could not complete this request.",
                    "status_code": 503,
                }
            )


class AuthenticatedApp:
    def __init__(self, app, settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] in {"/health/live", "/health/ready"}:
            return await JSONResponse({"status": "ok", "contract_version": VERSION})(scope, receive, send)
        headers = Headers(scope=scope)
        if headers.get("mcp-protocol-version") != "2026-07-28":
            return await JSONResponse({"error": "Protocol 2026-07-28 is required"}, status_code=400)(
                scope, receive, send
            )
        try:
            bearer = headers.get("authorization", "")
            if not bearer.startswith("Bearer "):
                raise ValueError()
            token = bearer[7:]
            claims = jwt.decode(
                token,
                self.settings.public_key.replace("\\n", "\n"),
                algorithms=["EdDSA"],
                audience="spandan-mcp",
                issuer="spandan",
                options={
                    "require": [
                        "sub",
                        "ver",
                        "role",
                        "exp",
                        "iat",
                        "aud",
                        "iss",
                        "jti",
                        "contract",
                        "tools",
                        "conversation_id",
                        "fingerprint",
                    ]
                },
            )
            if claims["contract"] != VERSION or not isinstance(claims["tools"], list):
                raise ValueError()
        except Exception:
            return await JSONResponse({"error": "Invalid or expired MCP authorization"}, status_code=401)(
                scope, receive, send
            )
        context_token = IDENTITY.set((claims, token))
        try:
            return await self.app(scope, receive, send)
        finally:
            IDENTITY.reset(context_token)


def create_app(settings=None, http_factory=None):
    settings = settings or Settings()
    server = SpandanServer(settings, http_factory=http_factory)
    hosts = [host.strip() for host in settings.allowed_hosts.split(",") if host.strip()]
    app = server.streamable_http_app(
        json_response=True,
        stateless_http=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[value for h in hosts for value in (h, h + ":*")], allowed_origins=[]
        ),
    )
    return AuthenticatedApp(app, settings)


def app_factory():
    return create_app()
