const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const port = 10000;

app.use(express.json()); //  Fix: Parse JSON bodies

const SECRET_KEY = 'your-secret-key'; // Replace with a strong secret in production

// MySQL connection
const db = mysql.createConnection({
  host: 'mysql-hirwa.alwaysdata.net',
  user: 'hirwa',
  password: 'kayirangwa/2003', // Add your password if any
  database: 'hirwa_api'
});

db.connect(err => {
  if (err) {
    console.error('DB connection failed:', err);
    return;
  }
  console.log('Connected to MySQL');
});

// ================= AUTH ==================
// Signup Route
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required' });

  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('INSERT INTO user (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
    if (err) return res.status(500).json({ error: 'User already exists or DB error' });
    res.json({ message: 'User created successfully' });
  });
});

// Login Route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required' });

  db.query('SELECT * FROM user WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0)
      return res.status(401).json({ error: 'Invalid credentials' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

// ================= MIDDLEWARE ==================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) return res.status(401).json({ error: 'Token missing' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ================== CRUD APIs (Protected) ==================

// GET all products
app.get('/products', authenticateToken, (req, res) => {
  db.query('SELECT * FROM product', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

// GET product by ID
app.get('/products/:id', authenticateToken, (req, res) => {
  db.query('SELECT * FROM product WHERE productId = ?', [req.params.id], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json(result[0]);
  });
});

// POST new product
app.post('/products', authenticateToken, (req, res) => {
  const { productName, description, quantity, price } = req.body;
  const createAt = new Date();

  const query = 'INSERT INTO product (productName, description, quantity, price, createAt) VALUES (?, ?, ?, ?, ?)';
  db.query(query, [productName, description, quantity, price, createAt], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json({ message: 'Product created', id: result.insertId });
  });
});

// PUT full update
app.put('/products/:id', authenticateToken, (req, res) => {
  const { productName, description, quantity, price } = req.body;

  const query = 'UPDATE product SET productName = ?, description = ?, quantity = ?, price = ? WHERE productId = ?';
  db.query(query, [productName, description, quantity, price, req.params.id], (err) => {
    if (err) return res.status(500).send(err);
    res.json({ message: 'Product fully updated' });
  });
});

// PATCH partial update
app.patch('/products/:id', authenticateToken, (req, res) => {
  const fields = Object.keys(req.body);
  const values = Object.values(req.body);
  const setClause = fields.map(field => `${field} = ?`).join(', ');

  const query = `UPDATE product SET ${setClause} WHERE productId = ?`;
  db.query(query, [...values, req.params.id], (err) => {
    if (err) return res.status(500).send(err);
    res.json({ message: 'Product partially updated' });
  });
});

// DELETE product
app.delete('/products/:id', authenticateToken, (req, res) => {
  db.query('DELETE FROM product WHERE productId = ?', [req.params.id], (err) => {
    if (err) return res.status(500).send(err);
    res.json({ message: 'Product deleted' });
  });
});

// ================== Start Server ==================
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
