# TrustVault – Secure Document Sharing Platform

**TrustVault** is an enterprise-grade, production-ready web application designed for secure document uploading, role-based access control, document-level permissions (`READ` / `EDIT`), immediate revocation enforcement, and cryptographic tamper-evident audit logging.

---

## 🚀 Features & Architecture

### 1. Role-Based Dashboards & Access Control
TrustVault features 3 distinct, server-enforced user roles:
- **ADMIN**: System-wide dashboard with total user/document/storage metrics, User Management (promote role, enable/disable accounts), Document Oversight, Security Event Monitoring, and Audit Hash Chain Verification.
- **OWNER**: Document Management dashboard for uploading files (drag-and-drop), viewing personal documents, editing metadata, granting `READ` or `EDIT` permissions to registered users by email, and revoking permissions instantly.
- **VIEWER**: Dashboard listing shared documents with explicit permissions. View and download documents with `READ` access, edit metadata when granted `EDIT` access, and track personal access history.

### 2. Strict No-Invitation Registration
Registration allows users to sign up directly with their Full Name, Email Address, and Password:
- **NO invitation codes, tokens, or links required**.
- New registrants automatically receive the default role `OWNER` with status `ACTIVE`.
- Self-selecting `ADMIN` role during registration is strictly blocked. Only an existing Administrator can promote users.

### 3. Immediate Permission Revocation
Permission checks are executed on **every** single document view, download, or edit request on the server database:
- Revoking a user's permission blocks all future view/download/edit requests instantly.

### 4. Cryptographic Tamper-Evident Audit Logging
All critical platform events are appended to an immutable audit ledger:
- Each event includes `previous_hash` and `event_hash` calculated via SHA-256 HMAC.
- Administrators can run the **Audit Chain Integrity Verification** endpoint (`/api/audit-logs/verify`) at any time to detect any database tampering or record modifications.

---

## 🛠️ Technology Stack

- **Backend**: Node.js, Express.js REST API
- **Database**: SQLite via `better-sqlite3` (WAL mode, Foreign Keys enabled)
- **Security**: `bcryptjs`, `express-session`, `helmet`, `express-rate-limit`, `multer`
- **Frontend**: Responsive SaaS UI (HTML5, CSS3, JavaScript, Bootstrap 5, Chart.js)
- **Testing**: Node.js test runner (`node:test`) + `supertest`

---

## 💻 Local Setup & Quick Start

### 1. Prerequisites
- Node.js (v18 or higher recommended)
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/your-username/trustvault.git
cd trustvault

# Install dependencies
npm install
```

### 3. Environment Setup
Create a `.env` file in the project root:
```env
PORT=3000
NODE_ENV=development
TRUSTVAULT_SESSION_SECRET=a-long-random-secret-key-32-chars-minimum
TRUSTVAULT_AUDIT_SECRET=a-different-long-random-audit-secret-key
DATA_DIR=./data
STORAGE_DIR=./storage
```

### 4. Running the Application
```bash
# Start server
npm start
```
Open your browser and navigate to `http://localhost:3000`.

### 5. Default Pre-seeded Administrator Credentials
Upon first launch, TrustVault automatically seeds a default Administrator account:
- **Email**: `admin@trustvault.com`
- **Password**: `AdminPassword123!`

---

## 🧪 Automated Security & Functional Testing

Run the full automated test suite covering registration, auth, role protection, IDOR prevention, permission granting/revocation, and audit log verification:

```bash
npm test
```

All 21 automated subtests should execute and pass with 0 failures.

---

## 🌐 Deploying to Render

Deploying TrustVault to **Render** takes just a few simple steps.

### Step 1: Push Project to GitHub
```bash
git init
git add .
git commit -m "Initial TrustVault release"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/trustvault.git
git push -u origin main
```

### Step 2: Create Web Service on Render
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** -> **Web Service**.
3. Connect your GitHub repository `trustvault`.
4. Configure the Web Service settings:
   - **Name**: `trustvault`
   - **Environment**: `Node`
   - **Region**: Select your preferred region (e.g. Oregon, US)
   - **Branch**: `main`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Instance Type**: Starter / Free

### Step 3: Configure Environment Variables in Render
In the Render Web Service settings, go to the **Environment** tab and add the following variables:

| Key | Value |
| :--- | :--- |
| `NODE_ENV` | `production` |
| `TRUSTVAULT_SESSION_SECRET` | `generate-a-strong-random-session-secret-here` |
| `TRUSTVAULT_AUDIT_SECRET` | `generate-a-strong-random-audit-secret-here` |
| `DATA_DIR` | `/var/data` |
| `STORAGE_DIR` | `/var/storage` |

*Note: Render automatically injects the `PORT` environment variable.*

### Step 4: Configure Render Persistent Disk (For Database & File Persistence)
To ensure your SQLite database (`trustvault.db`) and uploaded document files persist across app restarts and deployments:
1. In your Render Web Service dashboard, navigate to **Disks** tab.
2. Click **Add Disk**.
3. Name: `trustvault-data`
4. Mount Path: `/var/data`
5. Size: `1 GB` (or as required)
6. Add a second Disk or sub-directory for `/var/storage`.

### Step 5: Verify Live Deployment
1. Click **Deploy Latest Commit**.
2. Once build completes, open your live Render service URL (e.g., `https://trustvault.onrender.com`).
3. Log in with `admin@trustvault.com` / `AdminPassword123!`.
4. Register a new user account, upload a document, grant/revoke permissions, and check the audit logs!

---

## 📄 API Reference Summary

### Authentication
- `POST /api/auth/register` - Create user account (Default `OWNER` role, `ACTIVE` status)
- `POST /api/auth/login` - Authenticate & establish session
- `POST /api/auth/logout` - Destroy session
- `GET /api/auth/me` - Fetch authenticated user profile

### Admin Endpoints
- `GET /api/admin/dashboard` - Platform statistics & metrics
- `GET /api/admin/users` - List & search users
- `PATCH /api/admin/users/:id/role` - Update user role (`ADMIN`, `OWNER`, `VIEWER`)
- `PATCH /api/admin/users/:id/status` - Enable or disable user account
- `GET /api/admin/documents` - Platform document oversight
- `GET /api/admin/security-events` - Security audit event log

### Documents & Permissions
- `POST /api/documents` - Upload document
- `GET /api/documents` - Search & filter accessible documents
- `GET /api/documents/:id` - View document details
- `GET /api/documents/:id/download` - Download document file
- `PATCH /api/documents/:id` - Edit document metadata (`EDIT` or `OWNER` level)
- `DELETE /api/documents/:id` - Delete document (`OWNER` level)
- `POST /api/documents/:id/permissions` - Grant `READ`/`EDIT` permission by email
- `DELETE /api/documents/:id/permissions/:permissionId` - Revoke permission immediately

### Audit Logging
- `GET /api/audit-logs` - Query audit logs with filters
- `GET /api/audit-logs/verify` - Verify cryptographic SHA-256 hash chain integrity

---

## 🛡️ License
Distributed under the ISC License. Developed for TrustVault Document Security.
