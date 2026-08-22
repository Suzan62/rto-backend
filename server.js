const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// MySQL Connection Pool
const pool = mysql.createPool({
  uri: process.env.DATABASE_URL,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost') 
    ? { rejectUnauthorized: false } 
    : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'rto_secret_key_2026';

app.use(cors());
app.use(express.json());

// Setup uploads folder for RC PDFs
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // Sanitize extension and base name properly
    const ext = path.extname(file.originalname).replace(/[^a-zA-Z0-9]/g, '');
    const nameWithoutExt = path.basename(file.originalname, path.extname(file.originalname))
      .replace(/[^a-zA-Z0-9_-]/g, '_');
    
    cb(null, `${Date.now()}-${nameWithoutExt}.${ext || 'pdf'}`);
  }
});
const upload = multer({ storage });

// ==========================================
// 1. AUTHENTICATION MIDDLEWARE
// ==========================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ==========================================
// 2. AUTH & PASSWORD ROUTES
// ==========================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const [rows] = await pool.query(
      `SELECT u.*, d.name AS dealer_name 
       FROM users u 
       LEFT JOIN dealers d ON u.dealer_id = d.dealer_id 
       WHERE u.username = ?`,
      [username]
    );

    if (rows.length === 0) return res.status(401).json({ error: 'Invalid username or password' });

    const user = rows[0];
    let isPasswordValid = (password === user.password_hash);
    if (!isPasswordValid && user.password_hash && user.password_hash.startsWith('$2')) {
      isPasswordValid = await bcrypt.compare(password, user.password_hash).catch(() => false);
    }

    if (!isPasswordValid) return res.status(401).json({ error: 'Invalid username or password' });

    const token = jwt.sign(
      { user_id: user.user_id, username: user.username, role: user.role, dealer_id: user.dealer_id }, 
      JWT_SECRET, 
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        id: user.user_id,
        username: user.username,
        role: user.role,
        dealer_id: user.dealer_id,
        dealer_name: user.dealer_name
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.user_id;

    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ error: 'New password must be at least 4 characters long' });
    }

    const [rows] = await pool.query('SELECT * FROM users WHERE user_id = ?', [userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = rows[0];
    const isOldValid = (oldPassword === user.password_hash) || 
      await bcrypt.compare(oldPassword, user.password_hash).catch(() => false);

    if (!isOldValid) return res.status(400).json({ error: 'Incorrect current password' });

    const newHashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = ? WHERE user_id = ?', [newHashed, userId]);

    res.json({ success: true, message: 'Password updated successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 3. DASHBOARD METRICS
// ==========================================
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const isDealer = req.user.role === 'DEALER';
    const dealerId = isDealer ? req.user.dealer_id : req.query.dealer_id;

    let statsQuery = `SELECT status, COUNT(*) as count FROM cases`;
    const params = [];

    if (dealerId && dealerId !== 'ALL') {
      params.push(dealerId);
      statsQuery += ` WHERE dealer_id = ? GROUP BY status`;
    } else {
      statsQuery += ` GROUP BY status`;
    }

    const [statsRows] = await pool.query(statsQuery, params);

    let totalWorkSum = 0;
    let totalPaidSum = 0;

    if (dealerId && dealerId !== 'ALL') {
      const [workRows] = await pool.query(
        `SELECT COALESCE(SUM(agent_fee + govt_fee), 0) AS total_work FROM cases WHERE dealer_id = ?`,
        [dealerId]
      );
      const [payRows] = await pool.query(
        `SELECT COALESCE(SUM(amount), 0) AS total_paid FROM dealer_payments WHERE dealer_id = ?`,
        [dealerId]
      );
      totalWorkSum = parseFloat(workRows[0]?.total_work) || 0;
      totalPaidSum = parseFloat(payRows[0]?.total_paid) || 0;
    } else {
      const [workRows] = await pool.query(`SELECT COALESCE(SUM(agent_fee + govt_fee), 0) AS total_work FROM cases`);
      const [payRows] = await pool.query(`SELECT COALESCE(SUM(amount), 0) AS total_paid FROM dealer_payments`);
      totalWorkSum = parseFloat(workRows[0]?.total_work) || 0;
      totalPaidSum = parseFloat(payRows[0]?.total_paid) || 0;
    }

    const counts = { NEW_CASES: 0, IN_PROGRESS: 0, SENT_TO_RTO: 0, RC_UPDATED: 0, COMPLETED: 0 };
    statsRows.forEach(r => { counts[r.status] = parseInt(r.count, 10); });

    res.json({
      unbilledIncome: Math.max(0, totalWorkSum - totalPaidSum),
      totalWork: totalWorkSum,
      totalPaid: totalPaidSum,
      counts
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 4. CASES CRUD
// ==========================================
app.get('/api/cases', authenticateToken, async (req, res) => {
  try {
    const { status, dealer_id } = req.query;
    let query = `
      SELECT c.*, d.name AS dealer_name, d.phone AS dealer_phone 
      FROM cases c 
      JOIN dealers d ON c.dealer_id = d.dealer_id 
      WHERE 1=1
    `;
    const params = [];

    if (status && status !== 'ALL') {
      params.push(status);
      query += ` AND c.status = ?`;
    }
    if (dealer_id) {
      params.push(dealer_id);
      query += ` AND c.dealer_id = ?`;
    }

    query += ' ORDER BY c.created_at DESC';
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cases', authenticateToken, async (req, res) => {
  try {
    let { dealer_id, vehicle_no, customer_name, service_type, govt_fee, agent_fee } = req.body;
    if (!dealer_id || !vehicle_no || !customer_name) {
      return res.status(400).json({ error: 'Dealer, vehicle number, and customer name are required.' });
    }

    vehicle_no = vehicle_no.replace(/\s+/g, '').toUpperCase();

    // Guard: Check for open duplicate case on the same vehicle
    const [dup] = await pool.query(
      `SELECT case_id FROM cases WHERE vehicle_no = ? AND status NOT IN ('COMPLETED', 'REJECTED')`,
      [vehicle_no]
    );
    if (dup.length > 0) {
      return res.status(400).json({ 
        error: `An active case for vehicle ${vehicle_no} is already open (Case #${dup[0].case_id}).` 
      });
    }

    const [result] = await pool.query(
      `INSERT INTO cases (dealer_id, vehicle_no, customer_name, service_type, govt_fee, agent_fee, status) 
       VALUES (?, ?, ?, ?, ?, ?, 'NEW_CASES')`,
      [dealer_id, vehicle_no, customer_name.trim(), service_type, parseFloat(govt_fee) || 0, parseFloat(agent_fee) || 0]
    );

    const [createdCase] = await pool.query('SELECT * FROM cases WHERE case_id = ?', [result.insertId]);
    res.status(201).json(createdCase[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update / Edit Full Case
app.put('/api/cases/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    let { vehicle_no, customer_name, service_type, govt_fee, agent_fee, status, error_reason } = req.body;

    if (!vehicle_no || !customer_name) {
      return res.status(400).json({ error: 'Vehicle number and customer name are required.' });
    }

    vehicle_no = vehicle_no.replace(/\s+/g, '').toUpperCase();

    const [result] = await pool.query(
      `UPDATE cases SET 
        vehicle_no = ?, 
        customer_name = ?, 
        service_type = ?, 
        govt_fee = ?, 
        agent_fee = ?, 
        status = ?, 
        error_reason = ? 
       WHERE case_id = ?`,
      [
        vehicle_no,
        customer_name.trim(),
        service_type,
        parseFloat(govt_fee) || 0,
        parseFloat(agent_fee) || 0,
        status || 'NEW_CASES',
        status === 'IN_PROGRESS' ? (error_reason || '').trim() : null,
        id
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Case not found' });
    }

    const [updatedCase] = await pool.query('SELECT * FROM cases WHERE case_id = ?', [id]);
    res.json(updatedCase[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete Case
app.delete('/api/cases/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await pool.query('DELETE FROM cases WHERE case_id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Case not found' });
    }

    res.json({ success: true, message: 'Case deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/cases/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, error_reason } = req.body;

    if (status === 'IN_PROGRESS' && (!error_reason || !error_reason.trim())) {
      return res.status(400).json({ error: 'Please specify the objection or document issue reason.' });
    }

    const updatedReason = status === 'IN_PROGRESS' ? error_reason.trim() : null;

    await pool.query(
      `UPDATE cases SET status = ?, error_reason = ? WHERE case_id = ?`,
      [status, updatedReason, id]
    );

    const [updatedCase] = await pool.query('SELECT * FROM cases WHERE case_id = ?', [id]);
    res.json(updatedCase[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cases/:id/upload-rc', authenticateToken, upload.single('rc_file'), async (req, res) => {
  try {
    const { id } = req.params;
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    const fileUrl = `/uploads/${req.file.filename}`;
    await pool.query(`UPDATE cases SET rc_file_url = ?, status = 'RC_UPDATED' WHERE case_id = ?`, [fileUrl, id]);
    const [updatedCase] = await pool.query('SELECT * FROM cases WHERE case_id = ?', [id]);
    res.json(updatedCase[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 5. DEALERS & KHATA / PAYMENT LEDGER
// ==========================================
app.get('/api/dealers', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM dealers ORDER BY name ASC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create Dealer (Without Mandatory Agent Fee)
app.post('/api/dealers', authenticateToken, async (req, res) => {
  try {
    const { name, phone } = req.body;
    if (!name || !phone) return res.status(400).json({ error: 'Dealer name and phone are required.' });

    const cleanPhone = phone.replace(/\D/g, '').trim();

    const [existing] = await pool.query('SELECT * FROM dealers WHERE phone = ?', [cleanPhone]);
    if (existing.length > 0) {
      return res.status(400).json({ 
        error: `Dealer with phone ${cleanPhone} already exists (${existing[0].name}).` 
      });
    }

    const [result] = await pool.query(
      `INSERT INTO dealers (name, phone, default_rate) VALUES (?, ?, 0)`,
      [name.trim(), cleanPhone]
    );

    const [newDealer] = await pool.query('SELECT * FROM dealers WHERE dealer_id = ?', [result.insertId]);
    res.status(201).json(newDealer[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/dealers/:id', authenticateToken, async (req, res) => {
  try {
    const dealerId = req.params.id;
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Only admins can delete dealers.' });

    const [activeCases] = await pool.query(
      `SELECT COUNT(*) as count FROM cases WHERE dealer_id = ? AND status != 'COMPLETED'`,
      [dealerId]
    );
    if (parseInt(activeCases[0].count, 10) > 0) {
      return res.status(400).json({ error: `Cannot delete: ${activeCases[0].count} active cases exist.` });
    }

    await pool.query('DELETE FROM dealers WHERE dealer_id = ?', [dealerId]);
    res.json({ success: true, message: 'Dealer deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dealers/:id/khata', authenticateToken, async (req, res) => {
  try {
    const dealerId = req.params.id;
    const [payments] = await pool.query(
      `SELECT * FROM dealer_payments WHERE dealer_id = ? ORDER BY created_at DESC`,
      [dealerId]
    );
    const [workRows] = await pool.query(
      `SELECT COALESCE(SUM(agent_fee + govt_fee), 0) AS total_work FROM cases WHERE dealer_id = ?`,
      [dealerId]
    );
    const [payRows] = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total_paid FROM dealer_payments WHERE dealer_id = ?`,
      [dealerId]
    );

    const totalWork = parseFloat(workRows[0]?.total_work) || 0;
    const totalPaid = parseFloat(payRows[0]?.total_paid) || 0;

    res.json({
      payments,
      totalWork,
      totalPaid,
      balanceDue: Math.max(0, totalWork - totalPaid)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/payments', authenticateToken, async (req, res) => {
  try {
    const { dealer_id, amount, payment_mode, notes } = req.body;
    if (!amount || parseFloat(amount) <= 0) {
      return res.status(400).json({ error: 'Please enter a valid payment amount' });
    }

    const [recentPayments] = await pool.query(
      `SELECT * FROM dealer_payments 
       WHERE dealer_id = ? AND amount = ? AND created_at >= (NOW() - INTERVAL 5 SECOND)`,
      [dealer_id, parseFloat(amount)]
    );

    if (recentPayments.length > 0) {
      return res.status(400).json({ error: 'Duplicate payment detected. Please wait a moment.' });
    }

    const [result] = await pool.query(
      `INSERT INTO dealer_payments (dealer_id, amount, payment_mode, notes) VALUES (?, ?, ?, ?)`,
      [dealer_id, parseFloat(amount), payment_mode || 'CASH', notes || '']
    );

    const [payment] = await pool.query('SELECT * FROM dealer_payments WHERE payment_id = ?', [result.insertId]);
    res.json({ success: true, payment: payment[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 6. SERVER INITIALIZATION
// ==========================================
const PORT = process.env.PORT || 5001;
app.listen(PORT, '0.0.0.0', () => console.log(`RTO Backend (MySQL) running on port ${PORT}`));