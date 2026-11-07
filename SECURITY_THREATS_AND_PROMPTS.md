# TrustVault – Security Threat Model, Mitigation Analysis & Security Testing Prompts

This document provides the complete **Security Threat Model (STRIDE Framework)**, **Vulnerability Mitigation Analysis**, and **Security Penetration Testing Prompts** for the **TrustVault Secure Document Sharing Platform**.

---

## 🛡️ PART 1: STRIDE Threat Model & Defense Matrix

| Threat Category | Threat Description | Attack Vector | TrustVault Security Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Impersonating valid users, session hijacking, or accessing disabled accounts. | - Session fixation<br>- Brute force logins<br>- Accessing app after account disabling | - Session regeneration upon login (`req.session.regenerate`).<br>- Password hashing using `bcryptjs` (10 salt rounds).<br>- `requireAuth` middleware checks DB account status (`ACTIVE` vs `DISABLED`) on **every single request**.<br>- Rate limiting on `/api/auth/login` (max 30 attempts per 15 min). |
| **Tampering** | Modifying document contents, metadata, or altering audit logs to erase evidence. | - Unauthorized edit requests<br>- Directly altering database records | - `requireDocumentPermission('EDIT')` server middleware checks DB active status.<br>- **Append-only Audit Log with SHA-256 HMAC Hash Chaining**: Every log event includes `previous_hash` and `event_hash`. Any modification or deletion breaks the hash chain.<br>- Audit Verification API (`/api/audit-logs/verify`) detects tampered rows. |
| **Repudiation** | User denying having uploaded, viewed, downloaded, or shared a document. | - Denying document sharing or download actions | - Mandatory audit event creation for ALL authentication, upload, view, download, edit, share, and revocation events.<br>- Logs record User ID, IP address, timestamp, action name, document ID, and result. |
| **Information Disclosure** | Unauthorized users viewing or downloading confidential documents (IDOR). | - Path traversal (`../storage/..`) - Direct object ID guessing<br>- Public static file exposure | - Private storage directory (`STORAGE_DIR`) **is not served via static middleware**.<br>- File paths use UUIDs (`uuidv4()_filename`) with path traversal sanitization in `storageService.js`.<br>- Server-side `requireDocumentPermission` enforces DB access rights on **every request**. |
| **Denial of Service** | Resource exhaustion, upload bombs, or API flooding. | - Large file uploads (100MB+)<br>- Rapid API request flooding | - `multer` limits file size to **15MB maximum** and validates file extension against allowed whitelist.<br>- `express-rate-limit` limits general API requests to **300 requests / 15 min**. |
| **Elevation of Privilege** | Normal user attempting Admin actions or unauthorized document deletion. | - Sending `role: "ADMIN"` during registration<br>- Non-owners calling DELETE endpoints | - Registration page & API **hardcode assigned role to `OWNER`** with status `ACTIVE`. **Zero invitation or role selection fields exist**.<br>- Server-side `requireRole('ADMIN')` and `requireDocumentPermission('OWNER')` reject unauthorized actions regardless of frontend payload. |

---

## 🧪 PART 2: Security Testing Prompts & Penetration Tests

You can use the following structured **Security Prompts & Verification Tests** to stress-test and audit TrustVault.

---

### 📌 Prompt 1: Registration Role Self-Selection & Invitation Bypass Test
**Objective**: Verify that a user cannot self-assign the `ADMIN` role or bypass registration using fake invitation parameters.

**Test Execution Prompt / Command**:
```bash
# Attempt to register with role="ADMIN" and fake invitationCode
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Attacker User",
    "email": "attacker@test.com",
    "password": "Password123!",
    "confirmPassword": "Password123!",
    "role": "ADMIN",
    "invitationCode": "BYPASS_ADMIN_123"
  }'
```
**Expected Outcome**:
- Registration succeeds, BUT the database stores `role: 'OWNER'` and `status: 'ACTIVE'`.
- The `role: 'ADMIN'` and `invitationCode` parameters sent in request body are **completely ignored**.

---

### 📌 Prompt 2: IDOR (Insecure Direct Object Reference) Protection Test
**Objective**: Verify that a Viewer user cannot view or download a document owned by another user without explicit active permission.

**Test Execution Prompt / Command**:
```bash
# 1. Log in as Viewer
curl -X POST http://localhost:3000/api/auth/login \
  -c viewer_cookie.txt \
  -H "Content-Type: application/json" \
  -d '{"email": "viewer@trustvault.com", "password": "Password123!"}'

# 2. Attempt to directly download an unauthorized document ID
curl -X GET http://localhost:3000/api/documents/<UNAUTHORIZED_DOC_ID>/download \
  -b viewer_cookie.txt
```
**Expected Outcome**:
- HTTP `403 Forbidden` response: `{"error": "Forbidden: You do not have permission to access this document."}`.
- An `UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT` audit failure log is generated in `audit_logs`.

---

### 📌 Prompt 3: Immediate Permission Revocation Test
**Objective**: Verify that revoking a user's permission instantly blocks all future viewing and download requests.

**Test Execution Prompt / Command**:
```bash
# 1. Owner revokes permission ID
curl -X DELETE http://localhost:3000/api/documents/<DOC_ID>/permissions/<PERM_ID> \
  -b owner_cookie.txt

# 2. Viewer attempts to view document 1 second later
curl -X GET http://localhost:3000/api/documents/<DOC_ID> \
  -b viewer_cookie.txt
```
**Expected Outcome**:
- Immediate HTTP `403 Forbidden` response.
- No cached access granted; permission status `REVOKED` in SQLite database is enforced instantly.

---

### 📌 Prompt 4: Cryptographic Audit Log Tampering Detection Test
**Objective**: Verify that modifying an existing audit record breaks the SHA-256 HMAC hash chain and is detected by the verification system.

**Test Execution Prompt / Command**:
```bash
# 1. Admin triggers audit chain verification
curl -X GET http://localhost:3000/api/audit-logs/verify \
  -b admin_cookie.txt
```
**Expected Outcome**:
- If database logs are clean: `{"valid": true, "totalLogs": N}`.
- If an attacker manually modifies a database row in `audit_logs`: `{"valid": false, "tamperedAt": {"index": X, "reason": "Event hash mismatch..."}}`.

---

### 📌 Prompt 5: Disabled Account Instant Session Invalidation Test
**Objective**: Verify that disabling a user account instantly revokes active user sessions on their next API call.

**Test Execution Prompt / Command**:
```bash
# 1. Admin disables user account
curl -X PATCH http://localhost:3000/api/admin/users/<TARGET_USER_ID>/status \
  -b admin_cookie.txt \
  -H "Content-Type: application/json" \
  -d '{"status": "DISABLED"}'

# 2. Disabled user sends request using existing active session cookie
curl -X GET http://localhost:3000/api/auth/me \
  -b target_user_cookie.txt
```
**Expected Outcome**:
- HTTP `403 Forbidden`: `{"error": "Your account has been disabled by an administrator."}`.
- The active session is destroyed server-side and `DISABLED_ACCOUNT_ACCESS_ATTEMPT` is recorded in audit logs.
