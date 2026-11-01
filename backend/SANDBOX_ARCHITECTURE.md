# AegisMesh 2.0 — Synthetic Target Agent & Sandbox Foundation Architecture

## 1. Executive Summary & Design Overview

Step 08 establishes the first controlled, isolated, synthetic target environment for **AegisMesh 2.0**. This conceptual infrastructure represents a fictional enterprise network that future autonomous security agents (Red Team offensive agents and Blue Guardian defensive agents) can inspect, assess, and evaluate under rigorous containment.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        AegisMesh 2.0 Security Core                     │
│                                                                        │
│   FastAPI API   ◄──►   MCP Server   ◄──►   Security Gateway (OPA)     │
│   (JWT / RBAC)     (Streamable HTTP)       (Policy Enforcement)        │
└───────────────────────────────┬────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      Sandbox Isolation Boundary                        │
│                                                                        │
│  ┌────────────────────────┐         ┌───────────────────────────────┐  │
│  │  Sandbox Manager       │         │  Target Agent Service         │  │
│  │  (Multi-Tenant Bounds) │◄───────►│  (Read-Only Asset Discovery)  │  │
│  └───────────┬────────────┘         └───────────────┬───────────────┘  │
│              │                                      │                  │
│              ▼                                      ▼                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Synthetic Asset Registry                      │  │
│  │  (Fictional Enterprise Topology — RFC 5737 Documentation IPs)    │  │
│  │  - Ingress Firewalls (192.0.2.1)                                 │  │
│  │  - Web Proxies (192.0.2.10) & App Hosts (192.0.2.11)             │  │
│  │  - Relational Databases (198.51.100.10) & Caches (198.51.100.11)│  │
│  │  - Public API Gateways (203.0.113.10) & Microservices            │  │
│  │  - Simulated Vulnerabilities (Weak Ciphers, Misconfigs, Auth)    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **Simulated Execution Invariant**:
> The current sandbox foundation operates purely on synthetic, simulated infrastructure records stored in PostgreSQL. It does **NOT** provision live virtual machines, Docker containers, or execute shell commands on the host operating system. All network addresses are strictly confined to RFC 5737 reserved documentation ranges.

---

## 2. Synthetic Asset Model

Synthetic assets model realistic enterprise assets with comprehensive structural metadata, configuration parameters, and interconnection graphs without risking real infrastructure.

### Data Model (`synthetic_assets` Table)
- **`id`** (`UUID`): Unique primary key.
- **`sandbox_id`** (`UUID`, Foreign Key): Enforces multi-sandbox isolation. Cascades deletion with parent sandbox.
- **`name`** (`VARCHAR(128)`): Human-readable asset designation.
- **`asset_type`** (`VARCHAR(64)`): One of 5 initial supported categories:
  - `server`: Virtual Linux/Unix compute hosts.
  - `database`: Relational and in-memory datastores.
  - `web_application`: Front-facing client web portals and dashboards.
  - `api`: API gateways and microservice HTTP endpoints.
  - `network_device`: Boundary firewalls, routers, and switches.
- **`environment`** (`VARCHAR(32)`): Always `"sandbox"` for synthetic assets.
- **`status`** (`VARCHAR(32)`): Fictional operational status (`online`, `offline`, `degraded`).
- **`hostname`** (`VARCHAR(255)`): Fictional DNS identifier (e.g., `web-srv-01.sandbox.local`).
- **`ip_address`** (`VARCHAR(45)`): Fictional IPv4 address exclusively within RFC 5737 blocks:
  - `192.0.2.0/24` (TEST-NET-1)
  - `198.51.100.0/24` (TEST-NET-2)
  - `203.0.113.0/24` (TEST-NET-3)
- **`os_metadata`** (`JSONB`): Operating system name, version, kernel version, and architecture.
- **`service_metadata`** (`JSONB`): Listening ports, transport protocols, and simulated banner versions.
- **`configuration`** (`JSONB`): Fictional software configurations (e.g. SSL protocols, worker limits).
- **`simulated_vulnerabilities`** (`JSONB`): Structured list of fictional security findings.
- **`risk_level`** (`VARCHAR(32)`): Risk tier (`low`, `medium`, `high`, `critical`).
- **`connected_asset_ids`** (`JSONB`): Directed graph of connected synthetic asset IDs.

---

## 3. Sandbox Environment Model & Isolation Guarantees

The `sandbox_environments` table defines logical boundaries:
- **`id`** (`UUID`): Sandbox identifier.
- **`owner_id`** (`UUID`, Optional Foreign Key to `users.id`): Ownership identifier.
  - `NULL`: Platform/system demo sandbox accessible by authorized security personnel (`admin`, `security_operator`, `security_analyst`).
  - `UUID`: User-assigned sandbox accessible exclusively by the designated owner and platform administrators.
- **`name`** (`VARCHAR(128)`): Unique sandbox environment name.
- **`status`** (`VARCHAR(32)`): Lifecycle status (`active`, `archived`).
- **`isolation_mode`** (`VARCHAR(32)`): Currently `"simulated"`.
- **`configuration`** (`JSONB`): Subnet definitions, topology metadata, and boundary controls.

### Isolation & Ownership Rules Enforced:
1. **Host & Network Isolation**: Zero subprocess execution (`os.system`, `subprocess.Popen`), raw socket connections, or outbound network calls. All IPs remain static identifiers strictly within RFC 5737 blocks.
2. **Ownership & Assignment Verification**: Access to a sandbox requires genuine authorization:
   - Platform administrators (`admin`) have system-wide visibility.
   - Assigned owners can access their designated sandboxes.
   - Unauthorized users attempting to access another user's sandbox receive `403 Forbidden` (API) or an unauthorized access rejection (MCP).
   - Viewers (`viewer`) are strictly excluded from synthetic infrastructure target tools.
3. **Cross-Sandbox Boundary Protection**: Target Agent requests specify both `sandbox_id` and `asset_id`. If an asset does not belong to the requested sandbox, access is strictly rejected with a boundary violation error.
4. **Forensic Integrity & Safe Lifecycle**:
   - Destructive deletion of sandboxes is discouraged and restricted to administrators.
   - The platform enforces an **Archival Strategy** (`archive_sandbox`): transitions `status` to `"archived"`.
   - Archived sandboxes preserve all synthetic assets, service profiles, and vulnerability findings indefinitely for forensic investigation and replay.
   - Active Target Agent discovery and inspection operations are locked out on archived environments.
   - Historical `AuditLog` records maintain immutable cryptographic SHA-256 hash chains independent of sandbox lifecycle state.
5. **Foreign Key Integrity**: Assets are bound via PostgreSQL foreign keys with index coverage for high-speed isolation filtering.

---

## 4. Deterministic Demo Environment & Synthetic Findings

The Synthetic Asset Generator (`app.services.synthetic_generator`) provides idempotent seeding (`initialize_demo_sandbox`):

### Demo Enterprise Topology (10 Assets):
```
[ Edge Firewall ] (192.0.2.1)
      │
      ├──> [ Ingress Web Proxy ] (192.0.2.10) ──> [ Customer Portal ] (192.0.2.20)
      │
      └──> [ Public API Gateway ] (203.0.113.10)
                 │
                 ▼
           [ Auth Microservice API ] (203.0.113.11)
                 │
                 ▼
           [ App Server 01 ] (192.0.2.11)
                 │
                 ├──> [ PostgreSQL Primary DB ] (198.51.100.10)
                 │
                 └──> [ Redis Broker & Cache ] (198.51.100.11) ◄── [ Task Worker Host ] (192.0.2.12)
```

### Simulated Vulnerability Profiles:
Each finding includes:
- `finding_id`: Stable identifier (e.g. `SIM-CONF-002`, `SIM-DB-004`, `SIM-API-006`).
- `category`: `cryptography`, `configuration`, `access_control`, `authentication`, `patching`.
- `severity`: Standard CVSS-aligned rating (`critical`, `high`, `medium`, `low`).
- `simulated_evidence`: Structured mock proof (e.g. cipher suites, missing headers, mock debug route).
- `suggested_mitigation`: Actionable remediation guidance.
- `synthetic_status`: Status (`simulated_open`).
- `is_simulated: true`: Explicit immutable flag preventing confusion with live scanner findings.

---

## 5. Target Agent Service Responsibilities

Located in `app.services.target_agent_service`:
1. **Asset Discovery** (`discover_sandbox_assets`):
   - Returns paginated asset records within the caller's assigned sandbox.
   - Supports filtering by `asset_type`.
2. **Metadata Inspection** (`inspect_synthetic_asset`):
   - Returns comprehensive OS, service, and connection graph details.
   - Enforces sandbox boundary validation.
3. **Simulated Findings Retrieval** (`get_simulated_findings`):
   - Retrieves fictional vulnerabilities filtered optionally by `severity`.
   - Embeds explicit `is_simulated_environment: true` marker.

---

## 6. Model Context Protocol (MCP) Target Agent Tools

The MCP registry expands from 7 to 10 tools, adding 3 read-only Target Agent tools:

### Tool 8: `target_list_assets`
- **Capability**: `read`
- **Resource**: `synthetic_asset`
- **Environment**: `sandbox`
- **Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "sandbox_id": { "type": "string" },
      "asset_type": { "type": ["string", "null"], "default": null },
      "page": { "type": "integer", "default": 1 },
      "page_size": { "type": "integer", "default": 50 }
    },
    "required": ["sandbox_id"],
    "additionalProperties": false
  }
  ```

### Tool 9: `target_inspect_asset`
- **Capability**: `read`
- **Resource**: `synthetic_asset`
- **Environment**: `sandbox`
- **Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "sandbox_id": { "type": "string" },
      "asset_id": { "type": "string" }
    },
    "required": ["sandbox_id", "asset_id"],
    "additionalProperties": false
  }
  ```

### Tool 10: `target_get_simulated_findings`
- **Capability**: `read`
- **Resource**: `synthetic_asset`
- **Environment**: `sandbox`
- **Schema**:
  ```json
  {
    "type": "object",
    "properties": {
      "sandbox_id": { "type": "string" },
      "asset_id": { "type": "string" },
      "severity": { "type": ["string", "null"], "default": null }
    },
    "required": ["sandbox_id", "asset_id"],
    "additionalProperties": false
  }
  ```

---

## 7. Open Policy Agent (OPA) Integration

Rego policy `backend/policies/aegis.rego` enforces:
1. **Rule 8 (Target Agent Allow Rule — Least Privilege)**:
   Authenticated security personnel with roles `admin`, `security_operator`, or `security_analyst` are permitted `read` access to Target Agent tools strictly when `environment == "sandbox"`.
2. **Viewer Role Restriction**:
   The `viewer` role is strictly denied access to Target Agent operations (`target.*` and `mcp.target_*`) with the specific denial reason:
   `"Viewer role is not authorized to access target agent infrastructure."`
3. **Environment Restriction Guard**:
   If a Target Agent operation (`target.list_assets`, `target.inspect_asset`, `target.get_simulated_findings`, or their `mcp.` aliases) is requested with `environment != "sandbox"`, it is explicitly denied with the reason:
   `"Target Agent operations are strictly restricted to sandbox environment."`

---

## 8. Cryptographic Audit Integration

Every Target Agent tool execution follows:
```
HTTP Request ──> Transport JWT Auth ──> OPA Policy ──> Tool Execution ──> SHA-256 Audit Log
```
- Recorded under event type `MCP_TOOL_EXECUTION` and actions:
  - `mcp.target_list_assets`
  - `mcp.target_inspect_asset`
  - `mcp.target_get_simulated_findings`
- Actor ID is derived exclusively from the verified JWT user entity.
- Audit records link cryptographically using SHA-256 hash chaining:
  `event_hash = SHA256(canonical_payload + previous_hash)`
- If audit persistence fails, the tool execution aborts fail-closed.

---

## 9. Current Scope & Future Milestones

- **Current Implementation**: In-database simulated target architecture, strict multi-sandbox boundaries, deterministic synthetic asset generation, OPA policy enforcement, and 3 new MCP tools.
- **Future Milestones (Later Steps)**:
  - Red Team offensive emulation agents (Step 09+).
  - Blue Guardian defensive agents and automated remediation workflows.
  - LangGraph stateful agent orchestration.
  - Optional containerized ephemeral sandboxes (Docker-in-Docker / Firecracker microVMs).

