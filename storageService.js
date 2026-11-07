const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

/**
 * Returns absolute storage directory path.
 */
function getStorageDir() {
  const storageDir = process.env.STORAGE_DIR || path.join(__dirname, '../storage');
  if (!fs.existsSync(storageDir)) {
    fs.mkdirSync(storageDir, { recursive: true });
  }
  return storageDir;
}

/**
 * Saves uploaded file buffer to private storage directory.
 * @param {Buffer} buffer
 * @param {string} originalName
 * @returns {string} storageKey
 */
function saveFile(buffer, originalName) {
  const storageDir = getStorageDir();
  const safeFilename = path.basename(originalName).replace(/[^a-zA-Z0-9._-]/g, '_');
  const storageKey = `${uuidv4()}_${safeFilename}`;
  const targetPath = path.join(storageDir, storageKey);

  fs.writeFileSync(targetPath, buffer);
  return storageKey;
}

/**
 * Resolves absolute path for a storage key with path traversal prevention.
 * @param {string} storageKey
 * @returns {string|null}
 */
function getFilePath(storageKey) {
  if (!storageKey || storageKey.includes('..') || storageKey.includes('/') || storageKey.includes('\\')) {
    return null;
  }
  const storageDir = getStorageDir();
  const filePath = path.join(storageDir, storageKey);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return filePath;
}

/**
 * Removes file from storage directory.
 * @param {string} storageKey
 * @returns {boolean}
 */
function deleteFile(storageKey) {
  const filePath = getFilePath(storageKey);
  if (filePath && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    return true;
  }
  return false;
}

module.exports = {
  getStorageDir,
  saveFile,
  getFilePath,
  deleteFile
};
