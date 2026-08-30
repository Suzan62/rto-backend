const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
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
    const result = await pool.query(
      `SELECT u.*, d.name as dealer_name 
       FROM users u 
       LEFT JOIN dealers d ON u.dealer_id = d.dealer_id 
       WHERE u.username = $1`,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = result.rows[0];

    let isPasswordValid = (password === user.password_hash);
    if (!isPasswordValid && user.password_hash && user.password_hash.startsWith('$2')) {
      isPasswordValid = await bcrypt.compare(password, user.password_hash).catch(() => false);
    }

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

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

    const userRes = await pool.query('SELECT * FROM users WHERE user_id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = userRes.rows[0];
    const isOldValid = (oldPassword === user.password_hash) || 
      await bcrypt.compare(oldPassword, user.password_hash).catch(() => false);

    if (!isOldValid) {
      return res.status(400).json({ error: 'Incorrect current password' });
    }

    const newHashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [newHashed, userId]);

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
      statsQuery += ` WHERE dealer_id = $1 GROUP BY status`;
    } else {
      statsQuery += ` GROUP BY status`;
    }

    const statsRes = await pool.query(statsQuery, params);

    let totalWorkSum = 0;
    let totalPaidSum = 0;

    if (dealerId && dealerId !== 'ALL') {
      const workRes = await pool.query(
        `SELECT COALESCE(SUM(agent_fee + govt_fee), 0) AS total_work FROM cases WHERE dealer_id = $1`,
        [dealerId]
      );
      const payRes = await pool.query(
        `SELECT COALESCE(SUM(amount), 0) AS total_paid FROM dealer_payments WHERE dealer_id = $1`,
        [dealerId]
      );
      totalWorkSum = parseFloat(workRes.rows[0].total_work);
      totalPaidSum = parseFloat(payRes.rows[0].total_paid);
    } else {
      const workRes = await pool.query(`SELECT COALESCE(SUM(agent_fee + govt_fee), 0) AS total_work FROM cases`);
      const payRes = await pool.query(`SELECT COALESCE(SUM(amount), 0) AS total_paid FROM dealer_payments`);
      totalWorkSum = parseFloat(workRes.rows[0].total_work);
      totalPaidSum = parseFloat(payRes.rows[0].total_paid);
    }

    const remainingKhataBalance = Math.max(0, totalWorkSum - totalPaidSum);
    const counts = { NEW_CASES: 0, IN_PROGRESS: 0, SENT_TO_RTO: 0, RC_UPDATED: 0, COMPLETED: 0 };
    statsRes.rows.forEach(r => { counts[r.status] = parseInt(r.count, 10); });

    res.json({
      unbilledIncome: remainingKhataBalance,
      totalWork: totalWorkSum,
      totalPaid: totalPaidSum,
      counts
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 4. CASES CRUD & EDGE CASES
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
      query += ` AND c.status = $${params.length}`;
    }
    if (dealer_id) {
      params.push(dealer_id);
      query += ` AND c.dealer_id = $${params.length}`;
    }

    query += ' ORDER BY c.created_at DESC';
    const result = await pool.query(query, params);
    res.json(result.rows);
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

    const duplicateCheck = await pool.query(
      `SELECT case_id FROM cases 
       WHERE vehicle_no = $1 AND status NOT IN ('COMPLETED', 'REJECTED')`,
      [vehicle_no]
    );

    if (duplicateCheck.rows.length > 0) {
      return res.status(400).json({ 
        error: `An active case for vehicle ${vehicle_no} is already open (Case #${duplicateCheck.rows[0].case_id}).` 
      });
    }

    const result = await pool.query(
      `INSERT INTO cases (dealer_id, vehicle_no, customer_name, service_type, govt_fee, agent_fee, status) 
       VALUES ($1, $2, $3, $4, $5, $6, 'NEW_CASES') RETURNING *`,
      [dealer_id, vehicle_no, customer_name.trim(), service_type, parseFloat(govt_fee) || 0, parseFloat(agent_fee) || 1500]
    );

    res.status(201).json(result.rows[0]);
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

    const result = await pool.query(
      `UPDATE cases 
       SET status = $1, error_reason = $2 
       WHERE case_id = $3 
       RETURNING *`,
      [status, updatedReason, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Case not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cases/:id/upload-rc', authenticateToken, upload.single('rc_file'), async (req, res) => {
  try {
    const { id } = req.params;
    const fileUrl = `/uploads/${req.file.filename}`;
    const result = await pool.query(
      `UPDATE cases SET rc_file_url = $1, status = 'RC_UPDATED' WHERE case_id = $2 RETURNING *`,
      [fileUrl, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 5. DEALERS & KHATA / PAYMENT LEDGER
// ==========================================
app.get('/api/dealers', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM dealers ORDER BY name ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CREATE NEW DEALER
app.post('/api/dealers', authenticateToken, async (req, res) => {
  try {
    const { name, phone, default_rate } = req.body;
    if (!name || !phone) {
      return res.status(400).json({ error: 'Dealer name and phone number are required.' });
    }

    const result = await pool.query(
      `INSERT INTO dealers (name, phone, default_rate) 
       VALUES ($1, $2, $3) RETURNING *`,
      [name.trim(), phone.trim(), parseFloat(default_rate) || 1500]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SAFE DEALER DELETION
app.delete('/api/dealers/:id', authenticateToken, async (req, res) => {
  try {
    const dealerId = req.params.id;
    if (req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Only admins can remove dealers.' });
    }

    const activeCases = await pool.query(
      `SELECT COUNT(*) FROM cases WHERE dealer_id = $1 AND status != 'COMPLETED'`,
      [dealerId]
    );

    if (parseInt(activeCases.rows[0].count, 10) > 0) {
      return res.status(400).json({ 
        error: `Cannot delete dealer: ${activeCases.rows[0].count} active cases exist.` 
      });
    }

    const workRes = await pool.query(
      `SELECT COALESCE(SUM(agent_fee + govt_fee), 0) AS total_work FROM cases WHERE dealer_id = $1`,
      [dealerId]
    );
    const payRes = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total_paid FROM dealer_payments WHERE dealer_id = $1`,
      [dealerId]
    );

    const pendingBalance = parseFloat(workRes.rows[0].total_work) - parseFloat(payRes.rows[0].total_paid);
    if (pendingBalance > 0) {
      return res.status(400).json({ 
        error: `Cannot delete dealer: Khata has an unsettled balance of ₹${pendingBalance.toLocaleString()}.` 
      });
    }

    await pool.query('DELETE FROM dealers WHERE dealer_id = $1', [dealerId]);
    res.json({ success: true, message: 'Dealer deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// KHATA LEDGER
// KHATA LEDGER
app.get('/api/dealers/:id/khata', authenticateToken, async (req, res) => {
  try {
    const dealerId = req.params.id;
    const paymentsRes = await pool.query(
      `SELECT * FROM dealer_payments WHERE dealer_id = $1 ORDER BY created_at DESC`,
      [dealerId]
    );
    const workRes = await pool.query(
      `SELECT COALESCE(SUM(agent_fee + govt_fee), 0) AS total_work FROM cases WHERE dealer_id = $1`,
      [dealerId]
    );
    const paidRes = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total_paid FROM dealer_payments WHERE dealer_id = $1`,
      [dealerId]
    );

    const totalWork = parseFloat(workRes.rows[0].total_work) || 0;
    const totalPaid = parseFloat(paidRes.rows[0].total_paid) || 0;

    res.json({
      payments: paymentsRes.rows,
      totalWork,
      totalPaid,
      balanceDue: Math.max(0, totalWork - totalPaid)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// RECORD PAYMENT
app.post('/api/payments', authenticateToken, async (req, res) => {
  try {
    const { dealer_id, amount, payment_mode, notes } = req.body;
    if (!amount || parseFloat(amount) <= 0) {
      return res.status(400).json({ error: 'Please enter a valid payment amount' });
    }

    const result = await pool.query(
      `INSERT INTO dealer_payments (dealer_id, amount, payment_mode, notes) 
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [dealer_id, amount, payment_mode || 'CASH', notes || '']
    );

    res.json({ success: true, payment: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 6. SERVER INITIALIZATION (Must be at bottom)
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`RTO Backend listening on port ${PORT}`));