import { Router } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { config } from '../config/config.js';
import { db } from '../db/database.js';
import { sanitizeDatasetRows, inspectPayload } from '../services/securityEngine.js';

const router = Router();

// Configure Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, config.UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, `${uniqueSuffix}-${file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_')}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB max
});

/**
 * @route POST /api/files/upload
 * @desc Upload and perform server-side threat audit on file
 */
router.post('/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    const rawContent = fs.readFileSync(filePath, 'utf-8');
    const ext = path.extname(req.file.originalname).toLowerCase();

    let parsedRows = [];
    let isJson = false;

    if (ext === '.json') {
      try {
        const parsed = JSON.parse(rawContent);
        parsedRows = Array.isArray(parsed) ? parsed : [parsed];
        isJson = true;
      } catch (e) {
        return res.status(400).json({ error: 'Invalid JSON file structure' });
      }
    } else if (ext === '.csv' || ext === '.txt' || ext === '.log') {
      // Basic CSV line parsing
      const lines = rawContent.split(/\r?\n/).filter(Boolean);
      if (lines.length > 0) {
        const headers = lines[0].split(',').map(h => h.trim().replace(/^["']|["']$/g, ''));
        parsedRows = lines.slice(1).map((line, rIdx) => {
          const vals = line.split(',').map(v => v.trim().replace(/^["']|["']$/g, ''));
          const rowObj = { _rowId: rIdx + 1 };
          headers.forEach((h, hIdx) => {
            rowObj[h || `col_${hIdx}`] = vals[hIdx] || '';
          });
          return rowObj;
        });
      }
    }

    // Server-side audit
    let totalThreats = 0;
    const detectedThreats = [];

    parsedRows.forEach((row, idx) => {
      for (const key of Object.keys(row)) {
        const val = String(row[key]);
        const audit = inspectPayload(val);
        if (audit.threatType !== 'NORMAL' || audit.riskScore >= 40) {
          totalThreats++;
          if (detectedThreats.length < 15) {
            detectedThreats.push({
              row: idx + 1,
              field: key,
              type: audit.threatType,
              risk: audit.riskScore,
              sample: val.slice(0, 80)
            });
          }
        }
      }
    });

    const fileRecord = {
      id: `file-${Date.now()}`,
      originalName: req.file.originalname,
      serverFileName: req.file.filename,
      sizeBytes: req.file.size,
      mimeType: req.file.mimetype,
      uploadedAt: new Date().toISOString(),
      rowCount: parsedRows.length,
      threatsDetectedCount: totalThreats,
      isCleaned: false,
      sampleThreats: detectedThreats
    };

    db.insert('uploadedFiles', fileRecord);

    res.json({
      success: true,
      file: fileRecord,
      sampleRows: parsedRows.slice(0, 10),
      detectedThreats
    });
  } catch (err) {
    res.status(500).json({ error: 'File upload processing failed: ' + err.message });
  }
});

/**
 * @route POST /api/files/sanitize
 * @desc Sanitize dataset rows directly on server and generate download artifact
 */
router.post('/sanitize', (req, res) => {
  try {
    const { rows, filename = 'sanitized_dataset.json' } = req.body;

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({ error: 'Valid rows array is required for sanitization' });
    }

    const { cleanedRows, stats } = sanitizeDatasetRows(rows);

    const outFileName = `sanitized-${Date.now()}-${filename.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
    const outPath = path.join(config.UPLOAD_DIR, outFileName);

    fs.writeFileSync(outPath, JSON.stringify(cleanedRows, null, 2), 'utf-8');

    const cleanRecord = {
      id: `file-clean-${Date.now()}`,
      originalName: filename,
      serverFileName: outFileName,
      sizeBytes: fs.statSync(outPath).size,
      rowCount: cleanedRows.length,
      isCleaned: true,
      stats,
      downloadUrl: `/api/files/download/${outFileName}`,
      createdAt: new Date().toISOString()
    };

    db.insert('uploadedFiles', cleanRecord);

    res.json({
      success: true,
      stats,
      cleanedSample: cleanedRows.slice(0, 15),
      file: cleanRecord
    });
  } catch (err) {
    res.status(500).json({ error: 'Sanitization process failed: ' + err.message });
  }
});

/**
 * @route GET /api/files/download/:filename
 * @desc Download sanitized or uploaded file
 */
router.get('/download/:filename', (req, res) => {
  const { filename } = req.params;
  const safeFilename = path.basename(filename);
  const filePath = path.join(config.UPLOAD_DIR, safeFilename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found on server storage' });
  }

  res.download(filePath, safeFilename);
});

/**
 * @route GET /api/files/list
 * @desc List all files in server repository
 */
router.get('/list', (req, res) => {
  res.json(db.get('uploadedFiles'));
});

export default router;
