"""Deterministic Synthetic Asset and Vulnerability Profile Generator.

Generates realistic but entirely synthetic enterprise infrastructure models strictly using
documentation IP ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
Never generates real hostnames, real IPs, or real credentials.
"""

import logging
from typing import Any
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset

logger = logging.getLogger("aegismesh.services.generator")

# Deterministic namespace for demo sandbox assets
NAMESPACE_AEGIS_DEMO = uuid.UUID("44444444-4444-4444-4444-444444444444")
DEMO_SANDBOX_ID = uuid.uuid5(NAMESPACE_AEGIS_DEMO, "sandbox.demo-enterprise")
DEMO_SANDBOX_NAME = "demo-enterprise-sandbox"
RFC_5737_DOCUMENTATION_NETWORKS = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]


def _deterministic_uuid(name: str) -> uuid.UUID:
    """Generates a stable, reproducible UUID from a synthetic name."""
    return uuid.uuid5(NAMESPACE_AEGIS_DEMO, name)


# 10 Deterministic Synthetic Assets Definitions
DEMO_ASSET_DEFINITIONS: list[dict[str, Any]] = [
    # 1. Edge Firewall (network_device)
    {
        "key": "net-firewall-01",
        "name": "Edge Perimeter Firewall",
        "asset_type": "network_device",
        "description": "Simulated perimeter gateway managing traffic filtering between ingress networks.",
        "hostname": "firewall-edge-01.sandbox.local",
        "ip_address": "192.0.2.1",
        "os_metadata": {
            "os_name": "AegisOS-VirtualFirewall",
            "os_version": "4.2.1-sim",
            "kernel": "5.15.0-hardened",
            "architecture": "x86_64",
        },
        "service_metadata": {
            "services": [
                {"name": "ssh", "port": 22, "protocol": "tcp", "version": "OpenSSH_8.9p1_sim"},
                {"name": "https-admin", "port": 8443, "protocol": "tcp", "version": "nginx/1.22.0"},
            ]
        },
        "configuration": {
            "default_policy": "drop",
            "nat_enabled": True,
            "logging_level": "verbose",
            "zone": "dmz_boundary",
        },
        "risk_level": "medium",
        "connected_keys": ["srv-web-01", "api-gateway-01"],
        "simulated_vulnerabilities": [
            {
                "finding_id": "SIM-NET-001",
                "category": "configuration",
                "severity": "medium",
                "description": "Administrative management interface exposed on non-isolated port with default self-signed certificate.",
                "simulated_evidence": {
                    "port": 8443,
                    "tls_version": "TLSv1.2",
                    "cert_issuer": "CN=Simulated-Self-Signed-CA",
                },
                "suggested_mitigation": "Restrict admin interface to private management subnet and deploy enterprise certificate authority certificate.",
                "synthetic_status": "simulated_open",
                "is_simulated": True,
            }
        ],
    },
    # 2. Web Server 01 (server)
    {
        "key": "srv-web-01",
        "name": "Ingress Web Proxy Server",
        "asset_type": "server",
        "description": "Synthetic Linux server hosting reverse proxy and static asset delivery.",
        "hostname": "web-srv-01.sandbox.local",
        "ip_address": "192.0.2.10",
        "os_metadata": {
            "os_name": "Ubuntu",
            "os_version": "22.04 LTS (Jammy Jellyfish)",
            "kernel": "5.15.0-101-generic",
            "architecture": "x86_64",
        },
        "service_metadata": {
            "services": [
                {"name": "http", "port": 80, "protocol": "tcp", "version": "nginx/1.22.0"},
                {"name": "https", "port": 443, "protocol": "tcp", "version": "nginx/1.22.0"},
            ]
        },
        "configuration": {
            "proxy_protocol": "http",
            "upstream_keepalive": 64,
            "ssl_protocols": ["TLSv1.2", "TLSv1.3"],
        },
        "risk_level": "high",
        "connected_keys": ["app-portal-01", "api-gateway-01"],
        "simulated_vulnerabilities": [
            {
                "finding_id": "SIM-CONF-002",
                "category": "cryptography",
                "severity": "high",
                "description": "Legacy weak cipher suites (e.g. 3DES/CBC) enabled in virtual web server configuration.",
                "simulated_evidence": {
                    "enabled_ciphers": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
                    "virtual_host": "portal.sandbox.local",
                },
                "suggested_mitigation": "Deprecate CBC and 3DES cipher suites; restrict SSL configuration to modern AEAD ciphers.",
                "synthetic_status": "simulated_open",
                "is_simulated": True,
            }
        ],
    },
    # 3. Application Server 01 (server)
    {
        "key": "srv-app-01",
        "name": "Core Business Application Server",
        "asset_type": "server",
        "description": "Synthetic backend application host running domain microservices.",
        "hostname": "app-srv-01.sandbox.local",
        "ip_address": "192.0.2.11",
        "os_metadata": {
            "os_name": "Debian GNU/Linux",
            "os_version": "12 (Bookworm)",
            "kernel": "6.1.0-18-amd64",
            "architecture": "x86_64",
        },
        "service_metadata": {
            "services": [
                {"name": "fastapi-service", "port": 8000, "protocol": "tcp", "version": "uvicorn/0.30.0"},
                {"name": "metrics-agent", "port": 9100, "protocol": "tcp", "version": "prometheus-node-exporter/1.5.0"},
            ]
        },
        "configuration": {
            "environment_mode": "production-sim",
            "worker_concurrency": 4,
            "memory_limit_mb": 4096,
        },
        "risk_level": "medium",
        "connected_keys": ["api-auth-01", "db-postgres-01"],
        "simulated_vulnerabilities": [
            {
                "finding_id": "SIM-APP-003",
                "category": "patching",
                "severity": "medium",
                "description": "Simulated node exporter daemon version contains mock denial of service advisory.",
                "simulated_evidence": {
                    "package": "prometheus-node-exporter",
                    "installed_version": "1.5.0",
                    "fixed_version": "1.8.0",
                },
                "suggested_mitigation": "Upgrade package prometheus-node-exporter to version 1.8.0 or higher.",
                "synthetic_status": "simulated_open",
                "is_simulated": True,
            }
        ],
    },
    # 4. Background Worker Server 01 (server)
    {
        "key": "srv-worker-01",
        "name": "Asynchronous Task Worker Host",
        "asset_type": "server",
        "description": "Synthetic worker node executing background jobs and batch processing.",
        "hostname": "worker-srv-01.sandbox.local",
        "ip_address": "192.0.2.12",
        "os_metadata": {
            "os_name": "Rocky Linux",
            "os_version": "9.3 (Blue Onyx)",
            "kernel": "5.14.0-362.el9_3.x86_64",
            "architecture": "x86_64",
        },
        "service_metadata": {
            "services": [
                {"name": "celery-worker", "port": 0, "protocol": "internal", "version": "celery/5.4.0"},
            ]
        },
        "configuration": {
            "concurrency": 8,
            "prefetch_multiplier": 1,
            "queue_bindings": ["security_tasks", "audit_indexing"],
        },
        "risk_level": "low",
        "connected_keys": ["db-redis-01"],
        "simulated_vulnerabilities": [],
    },
    # 5. PostgreSQL Database (database)
    {
        "key": "db-postgres-01",
        "name": "Enterprise PostgreSQL Primary",
        "asset_type": "database",
        "description": "Relational data store housing transactional security records and tenant entities.",
        "hostname": "postgres-primary-01.sandbox.local",
        "ip_address": "198.51.100.10",
        "os_metadata": {
            "os_name": "Ubuntu",
            "os_version": "22.04 LTS",
            "kernel": "5.15.0-generic",
            "architecture": "x86_64",
        },
        "service_metadata": {
            "services": [
                {"name": "postgresql", "port": 5432, "protocol": "tcp", "version": "PostgreSQL 16.2 (Debian 16.2-1.pgdg120+1)"},
            ]
        },
        "configuration": {
            "max_connections": 200,
            "shared_buffers": "2GB",
            "ssl": "on",
            "password_encryption": "scram-sha-256",
        },
        "risk_level": "high",
        "connected_keys": ["srv-app-01"],
        "simulated_vulnerabilities": [
            {
                "finding_id": "SIM-DB-004",
                "category": "access_control",
                "severity": "high",
                "description": "Excessive simulated database privileges granted to service role account.",
                "simulated_evidence": {
                    "role_name": "app_backend_role",
                    "privileges": ["SUPERUSER", "CREATEROLE"],
                },
                "suggested_mitigation": "Revoke SUPERUSER and CREATEROLE grants; apply principle of least privilege using table-specific DML grants.",
                "synthetic_status": "simulated_open",
                "is_simulated": True,
            }
        ],
    },
    # 6. Redis Database (database)
    {
        "key": "db-redis-01",
        "name": "Session Cache & Message Broker",
        "asset_type": "database",
        "description": "In-memory cache and task queue broker for background worker orchestration.",
        "hostname": "redis-broker-01.sandbox.local",
        "ip_address": "198.51.100.11",
        "os_metadata": {
            "os_name": "Alpine Linux",
            "os_version": "3.19.1",
            "kernel": "6.6.14-0-virt",
            "architecture": "x86_64",
        },
        "service_metadata": {
            "services": [
                {"name": "redis", "port": 6379, "protocol": "tcp", "version": "Redis 7.2.4"},
            ]
        },
        "configuration": {
            "maxmemory": "1gb",
            "maxmemory_policy": "volatile-lru",
            "protected_mode": "yes",
        },
        "risk_level": "low",
        "connected_keys": ["srv-worker-01", "srv-app-01"],
        "simulated_vulnerabilities": [],
    },
    # 7. Customer Portal Web App (web_application)
    {
        "key": "app-portal-01",
        "name": "Customer Security Operations Portal",
        "asset_type": "web_application",
        "description": "Synthetic front-facing React/Next.js client interface for operations analysts.",
        "hostname": "portal.sandbox.local",
        "ip_address": "192.0.2.20",
        "os_metadata": {
            "framework": "Next.js",
            "runtime": "Node.js v20.11.0",
        },
        "service_metadata": {
            "services": [
                {"name": "frontend-http", "port": 3000, "protocol": "tcp", "version": "NodeJS/NextJS 14.1.0"},
            ]
        },
        "configuration": {
            "auth_flow": "oauth2_pkce",
            "cors_origin": "https://portal.sandbox.local",
        },
        "risk_level": "medium",
        "connected_keys": ["api-gateway-01"],
        "simulated_vulnerabilities": [
            {
                "finding_id": "SIM-WEB-005",
                "category": "configuration",
                "severity": "medium",
                "description": "Missing Content-Security-Policy (CSP) and Strict-Transport-Security (HSTS) simulated headers.",
                "simulated_evidence": {
                    "missing_headers": ["Content-Security-Policy", "Strict-Transport-Security"],
                },
                "suggested_mitigation": "Configure web response headers with strict CSP default-src 'self' and max-age=31536000 HSTS directives.",
                "synthetic_status": "simulated_open",
                "is_simulated": True,
            }
        ],
    },
    # 8. Admin Console Web App (web_application)
    {
        "key": "app-admin-01",
        "name": "Internal Platform Administration Console",
        "asset_type": "web_application",
        "description": "Synthetic administrative dashboard for tenant and policy management.",
        "hostname": "admin.sandbox.local",
        "ip_address": "192.0.2.21",
        "os_metadata": {
            "framework": "Vue.js",
            "runtime": "Node.js v20.11.0",
        },
        "service_metadata": {
            "services": [
                {"name": "admin-http", "port": 3001, "protocol": "tcp", "version": "NodeJS/Vite"},
            ]
        },
        "configuration": {
            "mfa_enforced": True,
            "session_timeout_seconds": 900,
        },
        "risk_level": "low",
        "connected_keys": ["srv-web-01"],
        "simulated_vulnerabilities": [],
    },
    # 9. API Gateway (api)
    {
        "key": "api-gateway-01",
        "name": "Public API Gateway & Ingress Router",
        "asset_type": "api",
        "description": "Simulated REST/gRPC API gateway mediating inbound partner and client requests.",
        "hostname": "api-gw-01.sandbox.local",
        "ip_address": "203.0.113.10",
        "os_metadata": {
            "runtime": "Kong Gateway",
            "version": "3.6.0",
        },
        "service_metadata": {
            "services": [
                {"name": "api-ingress", "port": 443, "protocol": "tcp", "version": "Kong/3.6.0"},
            ]
        },
        "configuration": {
            "rate_limit_minute": 1000,
            "jwt_verification": "enabled",
        },
        "risk_level": "critical",
        "connected_keys": ["api-auth-01"],
        "simulated_vulnerabilities": [
            {
                "finding_id": "SIM-API-006",
                "category": "authentication",
                "severity": "critical",
                "description": "Mock route bypass permitting unauthenticated access to simulated diagnostic endpoint /internal/debug.",
                "simulated_evidence": {
                    "unprotected_path": "/internal/debug",
                    "status_code": 200,
                    "response_body": "{\"mock_env\": \"sandbox\", \"debug_mode\": true}",
                },
                "suggested_mitigation": "Enforce authentication plugin globally on the gateway route hierarchy and block /internal/* on public listeners.",
                "synthetic_status": "simulated_open",
                "is_simulated": True,
            }
        ],
    },
    # 10. Identity & Token API (api)
    {
        "key": "api-auth-01",
        "name": "Identity & Token Microservice API",
        "asset_type": "api",
        "description": "Internal authentication and credential verification microservice.",
        "hostname": "auth-svc-01.sandbox.local",
        "ip_address": "203.0.113.11",
        "os_metadata": {
            "runtime": "FastAPI / Python 3.12",
        },
        "service_metadata": {
            "services": [
                {"name": "auth-api", "port": 8080, "protocol": "tcp", "version": "uvicorn/0.30.0"},
            ]
        },
        "configuration": {
            "token_ttl_seconds": 1800,
            "algorithm": "RS256",
        },
        "risk_level": "low",
        "connected_keys": ["db-postgres-01"],
        "simulated_vulnerabilities": [],
    },
]


async def initialize_demo_sandbox(session: AsyncSession) -> SandboxEnvironment:
    """Idempotently initializes the demo enterprise sandbox with 10 synthetic assets.

    Guarantees:
    - Never creates duplicate sandboxes or duplicate assets on repeated calls.
    - All IP addresses belong strictly to RFC 5737 documentation blocks.
    - Zero host system execution or external network operations.
    """
    stmt = select(SandboxEnvironment).where(SandboxEnvironment.id == DEMO_SANDBOX_ID)
    result = await session.execute(stmt)
    sandbox = result.scalar_one_or_none()

    if not sandbox:
        sandbox = SandboxEnvironment(
            id=DEMO_SANDBOX_ID,
            name="demo-enterprise-sandbox",
            description="Synthetic enterprise network infrastructure for safe security operations testing.",
            status="active",
            isolation_mode="simulated",
            configuration={
                "environment_type": "enterprise_simulated",
                "network_topology": "dmz_with_internal_subnets",
                "doc_ip_subnets": ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
            },
        )
        session.add(sandbox)
        await session.flush()
        logger.info("Initialized demo SandboxEnvironment '%s' (%s)", sandbox.name, sandbox.id)

    # Precalculate UUID mappings for all keys to link relationships
    key_to_uuid: dict[str, str] = {
        item["key"]: str(_deterministic_uuid(f"asset.{item['key']}"))
        for item in DEMO_ASSET_DEFINITIONS
    }

    # Fetch existing assets for this sandbox to guarantee idempotency
    existing_stmt = select(SyntheticAsset).where(SyntheticAsset.sandbox_id == sandbox.id)
    existing_res = await session.execute(existing_stmt)
    existing_assets_by_id = {str(a.id): a for a in existing_res.scalars().all()}

    for item in DEMO_ASSET_DEFINITIONS:
        asset_uuid = _deterministic_uuid(f"asset.{item['key']}")
        asset_id_str = str(asset_uuid)

        # Resolve connected asset UUIDs from keys
        connected_uuids = [
            key_to_uuid[target_key]
            for target_key in item.get("connected_keys", [])
            if target_key in key_to_uuid
        ]

        # Bind asset_id to simulated vulnerabilities
        vulns = []
        for v in item.get("simulated_vulnerabilities", []):
            vuln_copy = v.copy()
            vuln_copy["asset_id"] = asset_id_str
            vulns.append(vuln_copy)

        if asset_id_str in existing_assets_by_id:
            # Update existing asset to ensure consistency
            existing = existing_assets_by_id[asset_id_str]
            existing.name = item["name"]
            existing.asset_type = item["asset_type"]
            existing.description = item.get("description")
            existing.hostname = item["hostname"]
            existing.ip_address = item["ip_address"]
            existing.os_metadata = item.get("os_metadata", {})
            existing.service_metadata = item.get("service_metadata", {})
            existing.configuration = item.get("configuration", {})
            existing.simulated_vulnerabilities = vulns
            existing.risk_level = item.get("risk_level", "low")
            existing.connected_asset_ids = connected_uuids
        else:
            asset = SyntheticAsset(
                id=asset_uuid,
                sandbox_id=sandbox.id,
                name=item["name"],
                asset_type=item["asset_type"],
                description=item.get("description"),
                environment="sandbox",
                status="online",
                hostname=item["hostname"],
                ip_address=item["ip_address"],
                os_metadata=item.get("os_metadata", {}),
                service_metadata=item.get("service_metadata", {}),
                configuration=item.get("configuration", {}),
                simulated_vulnerabilities=vulns,
                risk_level=item.get("risk_level", "low"),
                connected_asset_ids=connected_uuids,
            )
            session.add(asset)

    await session.commit()
    await session.refresh(sandbox)
    logger.info("Successfully seeded %d synthetic assets in sandbox '%s'", len(DEMO_ASSET_DEFINITIONS), sandbox.id)
    return sandbox
