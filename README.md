# Spandan MCP Server

Independent, stateless appointment operations for Spandan using the official Python MCP SDK **2.3.0**, protocol **2026-07-28**, and Streamable HTTP. This service has no database or model credentials and does not import the Spandan backend.

The FastAPI chat host discovers role-scoped tools, obtains short-lived delegated grants, and connects through private mutual TLS. For every call this service exchanges the grant for a separate API audience, then calls the restricted Spandan API. Only Spandan's confirmation handler can obtain an exact-action execution grant. No clinical records, arbitrary URLs, SQL, or shell tools are exposed.

## Local setup

```sh
uv sync --frozen --extra dev
cp .env.example .env
# Set the trusted public verification key, service credential and private API URL.
uv run uvicorn spandan_mcp.server:app_factory --factory --port 8001
uv run pytest -q
```

`MCP_ENV=development` permits local HTTP callbacks. Production requires a private HTTPS API URL, trusted CA and client certificate/key. Set `MCP_ALLOWED_HOSTS` to the private service address and any explicitly configured internal DNS names. This is a first-party private integration, not an anonymous public MCP endpoint.

## Deployment

Build `docker build -t spandan-mcp-server:v0.1.0 .`, create a private `/etc/spandan-mcp/env` file from the example, and mount its TLS material at `/run/tls`. Run:

```sh
docker run -d --name spandan-mcp --restart unless-stopped --init \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --cap-drop ALL --security-opt no-new-privileges \
  --env-file /etc/spandan-mcp/env \
  -v /etc/spandan-mcp/tls:/run/tls:ro \
  -p 127.0.0.1:18800:8001 spandan-mcp-server:v0.1.0
```

Terminate private mutual TLS in a reverse proxy, forwarding `/mcp` to `127.0.0.1:18800`. Require a trusted client certificate, restrict ingress to the application instance, disable buffering and allow 90-second responses. Health endpoints are `/health/live` and `/health/ready`; readiness confirms the process and contract, while a signed `tools/list` call verifies downstream compatibility. No session affinity or shared process memory is needed; all conversation and action state belongs to Spandan's PostgreSQL database.

`src/spandan_mcp/contract.json` pins `spandan-tools-v1` and its SHA-256 tool catalog. Update it together with a compatible application release; incompatible versions fail closed. Independent CI checks authentication, protocol negotiation, schema validation, exact-action grants, token exchange and concurrent stateless requests. Semantic version tags publish GitHub releases after CI passes.
