const express = require('express');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;
const upload = multer();

app.use(cors());
app.use(express.json());

const allowedTypes = [
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/gif',
  'text/csv',
  'application/json',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
];

// ✅ Middleware to protect admin routes
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token. Please login as admin.' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid token. Please login again.' });
  }
};

// ✅ Admin login route
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ✅ Admin register route
app.post('/api/admin/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  try {
    // Check if username already exists
    const existing = await pool.query('SELECT id FROM admin_users WHERE username = $1', [username]);
    if (existing.rows.length > 0)
      return res.status(409).json({ error: 'Username already exists' });

    const password_hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)',
      [username, password_hash]
    );
    res.json({ message: 'Admin registered successfully' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ✅ Upload API (user)
app.post('/api/upload', upload.single('file'), async (req, res) => {
  const file = req.file;
  const uploadedBy = req.body.user || 'anonymous';

  if (!file) return res.status(400).send('No file uploaded');
  if (!allowedTypes.includes(file.mimetype)) {
    return res.status(400).json({ error: 'File type not allowed' });
  }

  try {
    await pool.query(
      'INSERT INTO files (name, mimetype, data, uploaded_by) VALUES ($1, $2, $3, $4)',
      [file.originalname, file.mimetype, file.buffer, uploadedBy]
    );
    res.json({ message: 'File uploaded successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Upload failed');
  }
});

// Public: list files
app.get('/api/files', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, mimetype, uploaded_by, uploaded_at FROM files ORDER BY uploaded_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).send('Failed to fetch files');
  }
});

// Public: download file
app.get('/api/file/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM files WHERE id = $1', [id]);
    const file = result.rows[0];
    if (!file) return res.status(404).send('File not found');

    res.setHeader('Content-Disposition', `inline; filename="${file.name}"`);
    res.setHeader('Content-Type', file.mimetype);
    res.send(file.data);
  } catch (err) {
    res.status(500).send('Download failed');
  }
});

// Root
app.get('/', (req, res) => res.send('🎉 File Upload Backend with Admin Login'));

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
