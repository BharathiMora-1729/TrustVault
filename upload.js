const multer = require('multer');
const path = require('path');

const ALLOWED_EXTENSIONS = [
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.txt', '.png', '.jpg', '.jpeg', '.zip', '.csv', '.json', '.md'
];

const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024; // 15MB

const storage = multer.memoryStorage();

function fileFilter(req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(new Error(`Invalid file type (${ext}). Allowed formats: ${ALLOWED_EXTENSIONS.join(', ')}`), false);
  }
  cb(null, true);
}

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_SIZE_BYTES
  },
  fileFilter
});

module.exports = upload;
