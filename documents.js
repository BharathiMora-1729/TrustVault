const express = require('express');
const router = express.Router();
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../config/database');
const { logEvent } = require('../services/auditService');
const { saveFile, getFilePath, deleteFile } = require('../services/storageService');
const { requireAuth } = require('../middleware/auth');
const { requireDocumentPermission } = require('../middleware/permissions');
const upload = require('../middleware/upload');

router.use(requireAuth);

/**
 * POST /api/documents
 * Upload document (Owner action).
 */
router.post('/', upload.single('file'), (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No document file uploaded.' });
    }

    const { name, description, category } = req.body;
    const documentName = (name && name.trim()) || req.file.originalname;
    const documentCategory = (category && category.trim()) || 'General';
    const documentDescription = description || '';

    const storageKey = saveFile(req.file.buffer, req.file.originalname);
    const docId = uuidv4();
    const fileType = path.extname(req.file.originalname).toLowerCase().replace('.', '') || 'bin';
    const fileSize = req.file.size;
    const ownerId = req.user.id;

    const db = getDatabase();
    const stmt = db.prepare(`
      INSERT INTO documents (id, owner_id, name, description, category, file_type, file_size, storage_key)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(docId, ownerId, documentName, documentDescription, documentCategory, fileType, fileSize, storageKey);

    logEvent(db, {
      userId: ownerId,
      documentId: docId,
      action: 'DOCUMENT_UPLOAD',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { name: documentName, category: documentCategory, fileType, fileSize }
    });

    res.status(201).json({
      message: 'Document uploaded successfully.',
      document: {
        id: docId,
        name: documentName,
        category: documentCategory,
        fileType,
        fileSize
      }
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/documents
 * Search and filter documents accessible to the current user.
 */
router.get('/', (req, res, next) => {
  try {
    const { search, category, fileType } = req.query;
    const userId = req.user.id;
    const userRole = req.user.role;
    const db = getDatabase();

    let documents = [];

    if (userRole === 'ADMIN') {
      let query = `
        SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at, d.updated_at,
               u.name as owner_name, u.email as owner_email, 'OWNER' as access_level
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        WHERE 1=1
      `;
      const params = [];
      if (search) {
        query += ' AND (LOWER(d.name) LIKE ? OR LOWER(d.description) LIKE ?)';
        params.push(`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`);
      }
      if (category) {
        query += ' AND d.category = ?';
        params.push(category);
      }
      if (fileType) {
        query += ' AND d.file_type = ?';
        params.push(fileType.toLowerCase());
      }
      query += ' ORDER BY d.created_at DESC';
      documents = db.prepare(query).all(...params);
    } else {
      let query = `
        SELECT DISTINCT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at, d.updated_at,
               u.name as owner_name, u.email as owner_email,
               CASE
                 WHEN d.owner_id = ? THEN 'OWNER'
                 ELSE dp.permission_type
               END as access_level
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        LEFT JOIN document_permissions dp ON d.id = dp.document_id AND dp.user_id = ? AND dp.status = 'ACTIVE'
        WHERE (d.owner_id = ? OR (dp.user_id = ? AND dp.status = 'ACTIVE'))
      `;
      const params = [userId, userId, userId, userId];

      if (search) {
        query += ' AND (LOWER(d.name) LIKE ? OR LOWER(d.description) LIKE ?)';
        params.push(`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`);
      }
      if (category) {
        query += ' AND d.category = ?';
        params.push(category);
      }
      if (fileType) {
        query += ' AND d.file_type = ?';
        params.push(fileType.toLowerCase());
      }

      query += ' ORDER BY d.created_at DESC';
      documents = db.prepare(query).all(...params);
    }

    res.json({ documents });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/documents/:id
 */
router.get('/:id', requireDocumentPermission('READ'), (req, res, next) => {
  try {
    const db = getDatabase();
    logEvent(db, {
      userId: req.user.id,
      documentId: req.document.id,
      action: 'DOCUMENT_VIEW',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { accessLevel: req.accessLevel }
    });

    res.json({
      document: req.document,
      accessLevel: req.accessLevel
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/documents/:id/download
 */
router.get('/:id/download', requireDocumentPermission('READ'), (req, res, next) => {
  try {
    const filePath = getFilePath(req.document.storage_key);

    if (!filePath) {
      return res.status(404).json({ error: 'Storage file not found on server.' });
    }

    const db = getDatabase();
    logEvent(db, {
      userId: req.user.id,
      documentId: req.document.id,
      action: 'DOCUMENT_DOWNLOAD',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { accessLevel: req.accessLevel, name: req.document.name }
    });

    res.download(filePath, req.document.name);
  } catch (err) {
    next(err);
  }
});

/**
 * PATCH /api/documents/:id
 * Edit metadata (EDIT or OWNER level required).
 */
router.patch('/:id', requireDocumentPermission('EDIT'), (req, res, next) => {
  try {
    const { name, description, category } = req.body;
    const db = getDatabase();

    const newName = (name && name.trim()) || req.document.name;
    const newDesc = description !== undefined ? description : req.document.description;
    const newCat = (category && category.trim()) || req.document.category;

    db.prepare(`
      UPDATE documents
      SET name = ?, description = ?, category = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(newName, newDesc, newCat, req.document.id);

    logEvent(db, {
      userId: req.user.id,
      documentId: req.document.id,
      action: 'DOCUMENT_EDIT',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { oldName: req.document.name, newName, oldCategory: req.document.category, newCategory: newCat }
    });

    res.json({ message: 'Document updated successfully.' });
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/documents/:id
 * Delete document (OWNER level required).
 */
router.delete('/:id', requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const db = getDatabase();

    deleteFile(req.document.storage_key);
    db.prepare('DELETE FROM documents WHERE id = ?').run(req.document.id);

    logEvent(db, {
      userId: req.user.id,
      documentId: req.document.id,
      action: 'DOCUMENT_DELETE',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { documentName: req.document.name }
    });

    res.json({ message: 'Document deleted successfully.' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
