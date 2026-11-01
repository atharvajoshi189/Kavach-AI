# AegisMesh 2.0 — Secure MCP Server Infrastructure

## 1. Overview and Architecture

The Model Context Protocol (MCP) server in AegisMesh 2.0 provides a secure, process-isolated, authenticated, policy-governed, and tamper-evident tool execution layer for autonomous security agents and clients.

Authentication is strictly isolated at the transport layer via standard HTTP Authorization headers (`Authorization: Bearer <JWT>`), ensuring tool arguments, parameter schemas, and LLM context windows remain free of credentials.

```
                    ┌───────────────────────────┐
                    │  MCP Client (e.g. Agent)  │
                    └─────────────┬─────────────┘
                                  │ Streamable HTTP (127.0.0.1:8001/mcp)
                                  │ Header: Authorization: Bearer <JWT>
                                  ▼
                    ┌───────────────────────────┐
                    │      AegisMesh MCP        │
                    │   Streamable HTTP App     │
                    └─────────────┬─────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Transport Auth  │    │  Policy Gateway  │    │  Tamper-Evident  │
│  - HTTP Header   │    │  - OPA Engine    │    │  Audit Logging   │
│  - JWT Signature │    │  - Aegis Rego    │    │  - SHA-256 Chain │
│  - Redis Blacklist│   │  - Fail-Closed   │    │  - Fail-Closed   │
│  - DB User State │    │                  │    │  - No Credential │
└──────────────────┘    └──────────────────┘    └──────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
                    ┌───────────────────────────┐
                    │   Verified Tool Registry  │
                    │      (extra="forbid")     │
                    │    (No auth in schemas)   │
                    └─────────────┬─────────────┘
                                  │
         ┌──────────────┬─────────┴────────┬──────────────┐
         ▼              ▼                  ▼              ▼
   system_health   agent tools      campaign tools  incident tools
    (Diagnostics) (list/get_agent) (list/get_camp) (list/get_inc)
```

### Key Architectural Tenets:
1. **Process Isolation**: The MCP server operates as an independent ASGI service (`app.mcp.server`) decoupled from the primary FastAPI application (`app.main`).
2. **Streamable HTTP Transport**: Implements the official Model Context Protocol Streamable HTTP transport standard over `http://127.0.0.1:8001/mcp`.
3. **Transport-Level Authentication**: Bearer tokens are transmitted exclusively in the HTTP `Authorization` header. Tool schemas expose strictly functional domain arguments.
4. **Fail-Closed Security**: Every tool invocation enforces caller authentication, OPA policy evaluation, and persistent audit log insertion. Any failure across these checkpoints aborts tool execution.
5. **Strict Schema Validation**: Tool schemas explicitly disallow unknown parameters (`extra="forbid"`), preventing prompt injection and signature smuggling.
6. **Read-Only Invariant**: All initial tools are strictly observational and informational. No mutating or offensive tools exist.

---

## 2. Dependencies and Technology Stack

- **Python SDK**: Official `mcp` SDK (`>=2.3.0,<3.0.0`)
- **Transport**: Streamable HTTP (`mcp.client.streamable_http`, `mcp.server.mcpserver`)
- **Authentication Stack**:
  - `mcp.server.auth.middleware.bearer_auth.BearerAuthBackend`
  - `mcp.server.auth.middleware.auth_context.AuthContextMiddleware`
  - `starlette.middleware.authentication.AuthenticationMiddleware`
  - `AegisMeshTokenVerifier` (integrating PyJWT, Argon2id, and Redis revocation checks)
- **Authorization**: Open Policy Agent (OPA) REST API (`http://localhost:8181/v1/data/aegis`)
- **Database**: PostgreSQL with `pgvector` via SQLAlchemy 2.0 async engine
- **Audit Logging**: Sequential SHA-256 cryptographic hash chaining persisted in `audit_logs`

---

## 3. Operations & Startup

### Configuration (`backend/app/core/config.py`):
```env
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=8001
MCP_SERVER_PATH=/mcp
MCP_SERVER_NAME=aegismesh-mcp
MCP_SERVER_VERSION=2.0.0
```

### Running the MCP Server:
From the `backend/` directory:
```bash
# Using Python module runner
python -m app.mcp.server

# Or using Uvicorn directly
uvicorn app.mcp.server:app --host 127.0.0.1 --port 8001
```

The MCP endpoint will be available at:
```
http://127.0.0.1:8001/mcp
```

---

## 4. Security Enforcement Lifecycle

Every invocation follows a zero-trust lifecycle inside `mcp_security_context`:

1. **Transport Header Extraction**:
   The HTTP `Authorization: Bearer <JWT>` header is extracted directly from the ASGI/HTTP request. If missing or malformed, the request is immediately rejected.
2. **Server-Side Authentication**:
   - Signature, algorithm, and lifetime verification.
   - Redis blacklist check (`revoked_token:{jti}`) ensures revoked tokens cannot be reused.
   - Active user query in PostgreSQL loads verified `id`, `role`, and `is_active` state. Callers cannot spoof roles.
3. **OPA Policy Evaluation**:
   - Operation envelope is constructed and submitted to OPA (`/v1/data/aegis`).
   - Role permissions and capability mappings are validated.
   - If OPA denies or times out, the server fails closed.
4. **Tool Execution**:
   - The registered read-only handler executes with an active `AsyncSession`.
5. **Persistent Tamper-Evident Audit Logging**:
   - An `AuditLog` row is created with event type `MCP_TOOL_EXECUTION` and action `mcp.<tool_name>`.
   - Credentials, Authorization headers, and tokens are scrubbed from `event_data`.
   - SHA-256 hash chaining is updated and verified.
   - If audit persistence fails, tool output is aborted and rolled back (fail closed).

---

## 5. Tool Registry & Schema Catalog

Every tool is strictly read-only and requires NO authentication arguments in its schema:

### 1. `system_health`
- **Description**: Inspects backend PostgreSQL, Redis, and OPA connectivity status without disclosing secrets.
- **Capability**: `read`
- **Resource**: `system`
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {},
    "additionalProperties": false
  }
  ```

### 2. `list_agents`
- **Description**: Lists registered autonomous security agents with safe pagination and filters.
- **Capability**: `read`
- **Resource**: `agent`
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "page": { "type": "integer", "default": 1 },
      "page_size": { "type": "integer", "default": 50 },
      "environment": { "type": ["string", "null"], "default": null },
      "status": { "type": ["string", "null"], "default": null }
    },
    "additionalProperties": false
  }
  ```

### 3. `get_agent`
- **Description**: Retrieves operational details and capabilities for a specific agent by UUID.
- **Capability**: `read`
- **Resource**: `agent`
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "agent_id": { "type": "string" }
    },
    "required": ["agent_id"],
    "additionalProperties": false
  }
  ```

### 4. `list_campaigns`
- **Description**: Lists security campaigns with pagination and status/environment filters.
- **Capability**: `read`
- **Resource**: `campaign`
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "page": { "type": "integer", "default": 1 },
      "page_size": { "type": "integer", "default": 50 },
      "environment": { "type": ["string", "null"], "default": null },
      "status": { "type": ["string", "null"], "default": null }
    },
    "additionalProperties": false
  }
  ```

### 5. `get_campaign`
- **Description**: Retrieves execution details for a specific campaign by UUID.
- **Capability**: `read`
- **Resource**: `campaign`
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "campaign_id": { "type": "string" }
    },
    "required": ["campaign_id"],
    "additionalProperties": false
  }
  ```

### 6. `list_incidents`
- **Description**: Lists security incidents with pagination and severity/status filters.
- **Capability**: `read`
- **Resource**: `incident`
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "page": { "type": "integer", "default": 1 },
      "page_size": { "type": "integer", "default": 50 },
      "severity": { "type": ["string", "null"], "default": null },
      "status": { "type": ["string", "null"], "default": null }
    },
    "additionalProperties": false
  }
  ```

### 7. `get_incident`
- **Description**: Retrieves security incident findings and details by UUID.
- **Capability**: `read`
- **Resource**: `incident`
- **Input Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "incident_id": { "type": "string" }
    },
    "required": ["incident_id"],
    "additionalProperties": false
  }
  ```

---

## 6. Testing

The MCP test suite exercises the server over actual Streamable HTTP transport:
```bash
pytest -c backend/pytest.ini backend/tests/test_mcp_server.py -v
```

All 18 dedicated MCP tests cover:
- Transport initialization & tool schema discovery without credentials
- Discovery with valid credentials
- Execution with valid HTTP Authorization header
- Rejection of missing Authorization header
- Rejection of malformed Bearer tokens and invalid schemes
- Rejection of expired and revoked JWTs
- Rejection of deactivated database users
- OPA authorization denial (fail-closed)
- Audit persistence failure (fail-closed)
- Proof that no tool schema contains `auth_token`
- Proof that credentials and Authorization headers never reach audit logs or traces
- Strict extra field rejection (`extra="forbid"`)
- Database-backed domain tool execution and not-found responses
