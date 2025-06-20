const express = require('express');
const cors = require('cors');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'secretkey';

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'thuvienso',
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  next();
}

app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed]);
  res.sendStatus(201);
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
  if (!rows.length || !(await bcrypt.compare(password, rows[0].password))) return res.sendStatus(401);
  const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, SECRET);
  res.json({ token });
});

app.get('/api/categories', async (req, res) => {
  const [rows] = await db.query('SELECT * FROM categories');
  res.json(rows);
});

app.post('/api/categories', authMiddleware, adminMiddleware, async (req, res) => {
  const { name } = req.body;
  await db.query('INSERT INTO categories (name) VALUES (?)', [name]);
  res.sendStatus(201);
});

app.post('/api/documents', authMiddleware, adminMiddleware, upload.single('file'), async (req, res) => {
  const { title, category_id } = req.body;
  const file_path = req.file.path;
  await db.query('INSERT INTO documents (title, file_path, category_id, uploaded_by) VALUES (?, ?, ?, ?)', [title, file_path, category_id, req.user.id]);
  res.sendStatus(201);
});

app.get('/api/documents', async (req, res) => {
  const [rows] = await db.query('SELECT d.*, c.name AS category FROM documents d LEFT JOIN categories c ON d.category_id = c.id');
  res.json(rows);
});

app.get('/api/documents/:id', async (req, res) => {
  const [rows] = await db.query('SELECT * FROM documents WHERE id = ?', [req.params.id]);
  if (!rows.length) return res.sendStatus(404);
  res.json(rows[0]);
});

app.patch('/api/documents/:id/view', async (req, res) => {
  await db.query('UPDATE documents SET views = views + 1 WHERE id = ?', [req.params.id]);
  res.sendStatus(200);
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
