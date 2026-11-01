# AegisMesh 2.0 — Authentication & Role-Based Access Control (RBAC)

This document describes the security architecture, authentication lifecycle, role permissions, and administrative provisioning for **AegisMesh 2.0**.

---

## 1. Security Overview

AegisMesh enforces server-side authentication and authorization across all operational endpoints:

* **Password Security**: Passwords are never stored in plaintext. They are hashed using **Argon2id** (`pwdlib[argon2]`), a memory-hard, GPU-resistant algorithm.
* **Password Complexity**: Enforces at least 8 characters, with lowercase, uppercase, numeric, and special character requirements.
* **Stateless Token Pairs**: Client sessions use signed **JWT** tokens (`HS256` or configurable asymmetric algorithms):
  - **Access Token**: Short-lived (default: 30 minutes) bearer token carrying user claims (`sub`, `role`, `type: "access"`, `jti`).
  - **Refresh Token**: Long-lived (default: 7 days) token (`type: "refresh"`) stored securely by the client for session extension.
* **Active Token Revocation**: Although JWTs are stateless, AegisMesh provides real-time revocation via **Redis**. When a user logs out or rotates a refresh token, the token's unique identifier (`jti`) is stored in a Redis blocklist for its remaining lifetime.

---

## 2. Role-Based Access Control (RBAC) Hierarchy

AegisMesh implements four hierarchical platform roles:

| Role | Hierarchy / Privilege | Permitted Operations |
| :--- | :--- | :--- |
| **`admin`** | Full Platform Control | User management, policy configuration, audit reviews, and inspecting any user's background jobs. |
| **`security_operator`** | Action Execution | Dispatching security background jobs, automated tasks, and remediation workflows. |
| **`security_analyst`** | Read & Analysis | Reviewing platform health, threat indicators, audit logs, and self-owned tasks. |
| **`viewer`** | Read-Only Minimum Privilege | Default role assigned upon public self-registration. Can view self profile and public health endpoints; blocked from job queueing. |

---

## 3. API Endpoints

### Public Endpoints
* `GET /api/v1/health`: Unauthenticated health probe for load balancers and orchestrators.
* `POST /api/v1/auth/register`: Public account creation. Strictly defaults to `viewer` role; self-assigning privileged roles is rejected.
* `POST /api/v1/auth/login`: Authenticates username/email and password. Returns access and refresh token pair.
* `POST /api/v1/auth/refresh`: Accepts valid refresh token, revokes old refresh token, and issues a fresh pair.

### Protected Endpoints
* `GET /api/v1/auth/me`: Requires valid access token. Returns authenticated caller profile.
* `POST /api/v1/auth/logout`: Requires valid access token. Revokes access token (and optional refresh token) in Redis.
* `POST /api/v1/jobs/health-check`: Requires `security_operator` or `admin` role. Rejects `viewer` callers with HTTP 403.
* `GET /api/v1/jobs/{task_id}`: Requires valid access token. Caller must be the task owner or an `admin`.

---

## 4. Secure Administrator Provisioning

To prevent unauthorized privilege escalation, **there is no public API endpoint to create an administrator**.

Administrators must be provisioned directly via the secure CLI command:

```powershell
# Navigate to the backend directory
cd backend

# Activate virtual environment
.\.venv\Scripts\activate

# Run the admin bootstrap command
python -m app.commands.create_admin --email admin@aegismesh.internal --username admin --password "YourStrongAdminPass123!"
```

If arguments are omitted, the command prompts interactively with masked password entry (`getpass`).

---

## 5. Environment Configuration

The following variables in `backend/.env` govern authentication behavior:

```env
# Cryptographic secret for signing tokens (minimum 32 characters in production)
JWT_SECRET_KEY=aegismesh-dev-secret-key-must-be-replaced-in-production-min32bytes!

# Token signing algorithm (e.g. HS256)
JWT_ALGORITHM=HS256

# Expiration windows
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Set to false to disable public self-registration
PUBLIC_REGISTRATION_ENABLED=true
```

---

## 6. Audit Trail

All authentication actions emit structured JSON audit records logged to the `aegismesh.audit` logger:
* `AUTH_REGISTER_SUCCESS` / `AUTH_REGISTER_FAILURE`
* `AUTH_LOGIN_SUCCESS` / `AUTH_LOGIN_FAILURE`
* `AUTH_LOGOUT`
* `AUTH_TOKEN_REFRESH_SUCCESS` / `AUTH_TOKEN_REFRESH_FAILURE`
* `AUTH_PERMISSION_DENIED`
* `AUTH_ADMIN_BOOTSTRAP`

Audit entries include timestamps, event types, user IDs, and client IP addresses. Credentials, hashes, and JWT tokens are sanitized and never written to audit trails.

