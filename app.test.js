const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

// 1. Set environment variables FIRST before requiring database or server
const testDir = path.join(__dirname, 'test_run');
if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true, force: true });
fs.mkdirSync(testDir, { recursive: true });

process.env.DATA_DIR = testDir;
process.env.STORAGE_DIR = path.join(testDir, 'storage');
process.env.TRUSTVAULT_SESSION_SECRET = 'test-session-secret-32-characters-long';
process.env.TRUSTVAULT_AUDIT_SECRET = 'test-audit-secret-key';
process.env.NODE_ENV = 'test';

const { getDatabase } = require('../config/database');
const { verifyAuditChain } = require('../services/auditService');
const app = require('../server');

const db = getDatabase();

test('TrustVault Core Automated Test Suite', async (t) => {

  let adminCookie = null;
  let ownerCookie = null;
  let viewerCookie = null;

  let ownerUserId = null;
  let viewerUserId = null;
  let disabledUserId = null;

  let uploadedDocId = null;
  let grantedPermId = null;

  await t.test('1. Registration - Allows normal registration without invitations & assigns OWNER role', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Doc Owner User',
        email: 'owner@trustvault.com',
        password: 'Password123!',
        confirmPassword: 'Password123!'
      });

    assert.equal(res.status, 201);
    assert.ok(res.body.userId);
    ownerUserId = res.body.userId;

    const userInDb = db.prepare('SELECT role, status FROM users WHERE id = ?').get(ownerUserId);
    assert.equal(userInDb.role, 'OWNER');
    assert.equal(userInDb.status, 'ACTIVE');
  });

  await t.test('2. Registration - Rejects duplicate email registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Duplicate Owner',
        email: 'owner@trustvault.com',
        password: 'Password123!',
        confirmPassword: 'Password123!'
      });

    assert.equal(res.status, 409);
    assert.match(res.body.error, /already exists/i);
  });

  await t.test('3. Registration - Register a Viewer user', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Doc Viewer User',
        email: 'viewer@trustvault.com',
        password: 'Password123!',
        confirmPassword: 'Password123!'
      });

    assert.equal(res.status, 201);
    viewerUserId = res.body.userId;
  });

  await t.test('4. Registration - Register user to be disabled', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Disabled User',
        email: 'disabled@trustvault.com',
        password: 'Password123!',
        confirmPassword: 'Password123!'
      });

    assert.equal(res.status, 201);
    disabledUserId = res.body.userId;
  });

  await t.test('5. Authentication - Login Owner User & establish session cookie', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'owner@trustvault.com',
        password: 'Password123!'
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.user.role, 'OWNER');
    assert.ok(res.headers['set-cookie']);
    ownerCookie = res.headers['set-cookie'];
  });

  await t.test('6. Authentication - Login Viewer User & establish session cookie', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'viewer@trustvault.com',
        password: 'Password123!'
      });

    assert.equal(res.status, 200);
    viewerCookie = res.headers['set-cookie'];
  });

  await t.test('7. Admin Seeding & Auth - Create and login System Administrator', async () => {
    const adminPassHash = await bcrypt.hash('AdminPassword123!', 10);
    db.prepare("INSERT INTO users (id, name, email, password_hash, role, status) VALUES ('admin-test-id', 'System Admin', 'admin@trustvault.com', ?, 'ADMIN', 'ACTIVE')").run(adminPassHash);

    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'admin@trustvault.com',
        password: 'AdminPassword123!'
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.user.role, 'ADMIN');
    adminCookie = res.headers['set-cookie'];
  });

  await t.test('8. Admin Controls - Demote viewer user role to VIEWER and disable disabled user', async () => {
    const resRole = await request(app)
      .patch(`/api/admin/users/${viewerUserId}/role`)
      .set('Cookie', adminCookie)
      .send({ role: 'VIEWER' });
    assert.equal(resRole.status, 200);

    const resStatus = await request(app)
      .patch(`/api/admin/users/${disabledUserId}/status`)
      .set('Cookie', adminCookie)
      .send({ status: 'DISABLED' });
    assert.equal(resStatus.status, 200);
  });

  await t.test('9. Security - Disabled account login is blocked', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'disabled@trustvault.com',
        password: 'Password123!'
      });

    assert.equal(res.status, 403);
    assert.match(res.body.error, /disabled/i);
  });

  await t.test('10. Document Management - Owner uploads a document', async () => {
    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .field('name', 'Confidential Q3 Financial Report.pdf')
      .field('category', 'Financial')
      .field('description', 'Q3 Balance sheet and revenue')
      .attach('file', Buffer.from('Mock PDF File Content for TrustVault Testing'), 'Financial_Report.pdf');

    assert.equal(res.status, 201);
    assert.ok(res.body.document.id);
    uploadedDocId = res.body.document.id;
  });

  await t.test('11. Document Access - Viewer user tries to access document WITHOUT permission (IDOR protection)', async () => {
    const res = await request(app)
      .get(`/api/documents/${uploadedDocId}`)
      .set('Cookie', viewerCookie);

    assert.equal(res.status, 403);
    assert.match(res.body.error, /do not have permission/i);
  });

  await t.test('12. Permission System - Owner grants READ permission to Viewer user', async () => {
    const res = await request(app)
      .post(`/api/documents/${uploadedDocId}/permissions`)
      .set('Cookie', ownerCookie)
      .send({
        userEmail: 'viewer@trustvault.com',
        permissionType: 'READ'
      });

    assert.equal(res.status, 201);
    assert.ok(res.body.permissionId);
    grantedPermId = res.body.permissionId;
  });

  await t.test('13. Document Access - Viewer can now VIEW & DOWNLOAD document with READ permission', async () => {
    const resView = await request(app)
      .get(`/api/documents/${uploadedDocId}`)
      .set('Cookie', viewerCookie);
    assert.equal(resView.status, 200);
    assert.equal(resView.body.accessLevel, 'READ');

    const resDownload = await request(app)
      .get(`/api/documents/${uploadedDocId}/download`)
      .set('Cookie', viewerCookie);
    assert.equal(resDownload.status, 200);
  });

  await t.test('14. Document Access - Viewer CANNOT EDIT document with only READ permission', async () => {
    const res = await request(app)
      .patch(`/api/documents/${uploadedDocId}`)
      .set('Cookie', viewerCookie)
      .send({ name: 'Hacked Title.pdf' });

    assert.equal(res.status, 403);
    assert.match(res.body.error, /need EDIT permission/i);
  });

  await t.test('15. Permission System - Owner updates permission to EDIT', async () => {
    const res = await request(app)
      .patch(`/api/documents/${uploadedDocId}/permissions/${grantedPermId}`)
      .set('Cookie', ownerCookie)
      .send({ permissionType: 'EDIT' });

    assert.equal(res.status, 200);
  });

  await t.test('16. Document Access - Viewer can now EDIT document metadata', async () => {
    const res = await request(app)
      .patch(`/api/documents/${uploadedDocId}`)
      .set('Cookie', viewerCookie)
      .send({ name: 'Updated Q3 Financial Report.pdf', description: 'Updated by Viewer' });

    assert.equal(res.status, 200);
  });

  await t.test('17. Immediate Revocation - Owner revokes permission; Viewer access blocked immediately', async () => {
    const resRevoke = await request(app)
      .delete(`/api/documents/${uploadedDocId}/permissions/${grantedPermId}`)
      .set('Cookie', ownerCookie);
    assert.equal(resRevoke.status, 200);

    // Immediate block on View
    const resView = await request(app)
      .get(`/api/documents/${uploadedDocId}`)
      .set('Cookie', viewerCookie);
    assert.equal(resView.status, 403);

    // Immediate block on Download
    const resDownload = await request(app)
      .get(`/api/documents/${uploadedDocId}/download`)
      .set('Cookie', viewerCookie);
    assert.equal(resDownload.status, 403);
  });

  await t.test('18. Role Restrictions - Viewer user cannot access Admin or Owner management routes', async () => {
    const resAdmin = await request(app)
      .get('/api/admin/dashboard')
      .set('Cookie', viewerCookie);
    assert.equal(resAdmin.status, 403);

    const resDelete = await request(app)
      .delete(`/api/documents/${uploadedDocId}`)
      .set('Cookie', viewerCookie);
    assert.equal(resDelete.status, 403);
  });

  await t.test('19. Audit Logging - Cryptographic Audit Hash Chain verification passes', async () => {
    const verification = verifyAuditChain(db);
    assert.equal(verification.valid, true);
    assert.ok(verification.totalLogs > 0);
  });

  await t.test('20. Clean up test database directory', async () => {
    db.close();
    if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true, force: true });
  });

});
