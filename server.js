const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust Railway's proxy for secure cookies
app.set('trust proxy', 1);

// ── MIDDLEWARE ──
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ── DATABASE (deferred until start) ──
let pool = null;

// ── INIT DATABASE TABLES ──
async function initDB() {
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  // Set up session store backed by PostgreSQL
  const PgSession = require('connect-pg-simple')(session);
  app.use(session({
    store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || 'jmos-wv-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days — stay logged in
      secure: true,
      sameSite: 'lax'
    }
  }));

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      display_name VARCHAR(100),
      role VARCHAR(20) DEFAULT 'operator',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS submissions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      client_id VARCHAR(100),
      shift_date VARCHAR(10),
      shift_num VARCHAR(2),
      data JSONB NOT NULL,
      submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_submissions_date ON submissions(shift_date);
    CREATE INDEX IF NOT EXISTS idx_submissions_client ON submissions(client_id);
  `);

  // Create default admin user if no users exist
  const { rows } = await pool.query('SELECT COUNT(*) as cnt FROM users');
  if (parseInt(rows[0].cnt) === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      'INSERT INTO users (username, password_hash, display_name, role) VALUES ($1, $2, $3, $4)',
      ['admin', hash, 'Administrator', 'admin']
    );
    console.log('Default admin user created (username: admin, password: admin123)');
    console.log('IMPORTANT: Change this password after first login!');
  }

  // ── Register all API routes AFTER session middleware is ready ──
  registerRoutes();
}

// ── AUTH MIDDLEWARE ──
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ══════════════════════════════════════════
// ── ALL API ROUTES ──
// ══════════════════════════════════════════
function registerRoutes() {

  // ── AUTH ROUTES ──
  app.post('/api/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

      const { rows } = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
      if (rows.length === 0) return res.status(401).json({ error: 'Invalid username or password' });

      const user = rows[0];
      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) return res.status(401).json({ error: 'Invalid username or password' });

      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.displayName = user.display_name;

      res.json({
        user: {
          id: user.id,
          username: user.username,
          displayName: user.display_name,
          role: user.role
        }
      });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
      if (err) console.error('Logout error:', err);
      res.clearCookie('connect.sid');
      res.json({ ok: true });
    });
  });

  app.get('/api/me', async (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    try {
      const { rows } = await pool.query(
        'SELECT id, username, display_name, role FROM users WHERE id = $1',
        [req.session.userId]
      );
      if (rows.length === 0) return res.status(401).json({ error: 'User not found' });
      res.json({
        user: {
          id: rows[0].id,
          username: rows[0].username,
          displayName: rows[0].display_name,
          role: rows[0].role
        }
      });
    } catch (err) {
      console.error('Auth check error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // ── DATA ROUTES ──
  app.post('/api/submit', requireAuth, async (req, res) => {
    try {
      const { shiftData, equipData, clientId } = req.body;
      if (clientId) {
        const existing = await pool.query('SELECT id FROM submissions WHERE client_id = $1', [clientId]);
        if (existing.rows.length > 0) {
          return res.json({ ok: true, id: existing.rows[0].id, duplicate: true });
        }
      }
      const result = await pool.query(
        'INSERT INTO submissions (user_id, client_id, shift_date, shift_num, data) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [req.session.userId, clientId || null, shiftData?.shiftDate, shiftData?.shiftNum, JSON.stringify({ shiftData, equipData })]
      );
      res.json({ ok: true, id: result.rows[0].id });
    } catch (err) {
      console.error('Submit error:', err);
      res.status(500).json({ error: 'Failed to save data' });
    }
  });

  app.get('/api/data', requireAuth, async (req, res) => {
    try {
      const { from, to } = req.query;
      let query = 'SELECT data FROM submissions';
      const params = [];
      if (from && to) {
        query += ' WHERE shift_date >= $1 AND shift_date <= $2';
        params.push(from, to);
      } else if (from) {
        query += ' WHERE shift_date >= $1';
        params.push(from);
      }
      query += ' ORDER BY submitted_at';
      const { rows } = await pool.query(query, params);
      res.json(rows.map(r => r.data));
    } catch (err) {
      console.error('Data fetch error:', err);
      res.status(500).json({ error: 'Failed to fetch data' });
    }
  });

  app.post('/api/sync', requireAuth, async (req, res) => {
    try {
      const { submissions } = req.body;
      if (!Array.isArray(submissions)) return res.status(400).json({ error: 'Expected submissions array' });
      const results = [];
      for (const sub of submissions) {
        const { shiftData, equipData, clientId } = sub;
        if (clientId) {
          const existing = await pool.query('SELECT id FROM submissions WHERE client_id = $1', [clientId]);
          if (existing.rows.length > 0) {
            results.push({ clientId, ok: true, duplicate: true });
            continue;
          }
        }
        const result = await pool.query(
          'INSERT INTO submissions (user_id, client_id, shift_date, shift_num, data) VALUES ($1, $2, $3, $4, $5) RETURNING id',
          [req.session.userId, clientId || null, shiftData?.shiftDate, shiftData?.shiftNum, JSON.stringify({ shiftData, equipData })]
        );
        results.push({ clientId, ok: true, id: result.rows[0].id });
      }
      res.json({ ok: true, results });
    } catch (err) {
      console.error('Sync error:', err);
      res.status(500).json({ error: 'Sync failed' });
    }
  });

  // ── USER MANAGEMENT (admin only) ──
  app.get('/api/users', requireAdmin, async (req, res) => {
    try {
      const { rows } = await pool.query(
        'SELECT id, username, display_name, role, created_at FROM users ORDER BY username'
      );
      res.json(rows);
    } catch (err) {
      console.error('Users fetch error:', err);
      res.status(500).json({ error: 'Failed to fetch users' });
    }
  });

  app.post('/api/users', requireAdmin, async (req, res) => {
    try {
      const { username, password, displayName, role } = req.body;
      if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
      if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'INSERT INTO users (username, password_hash, display_name, role) VALUES ($1, $2, $3, $4)',
        [username.toLowerCase(), hash, displayName || username, role || 'operator']
      );
      res.json({ ok: true });
    } catch (err) {
      if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
      console.error('Create user error:', err);
      res.status(500).json({ error: 'Failed to create user' });
    }
  });

  app.put('/api/users/:id/password', requireAdmin, async (req, res) => {
    try {
      const { password } = req.body;
      if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.params.id]);
      res.json({ ok: true });
    } catch (err) {
      console.error('Password update error:', err);
      res.status(500).json({ error: 'Failed to update password' });
    }
  });

  app.delete('/api/users/:id', requireAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (id === req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
      await pool.query('DELETE FROM users WHERE id = $1', [id]);
      res.json({ ok: true });
    } catch (err) {
      console.error('Delete user error:', err);
      res.status(500).json({ error: 'Failed to delete user' });
    }
  });

  // ── SERVE STATIC FILES + APP (after API routes) ──
  app.use(express.static(path.join(__dirname), {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('sw.js')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      }
      if (filePath.endsWith('manifest.json')) {
        res.setHeader('Content-Type', 'application/manifest+json');
      }
    }
  }));

  app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
    res.sendFile(path.join(__dirname, 'WV_OEE_App.html'));
  });
}

// ── START SERVER ──
async function start() {
  if (!process.env.DATABASE_URL) {
    console.error('WARNING: DATABASE_URL not set.');
    app.get('*', (req, res) => {
      res.status(503).send('<html><body style="font-family:sans-serif;text-align:center;padding:60px"><h1>JMOS Setup In Progress</h1><p>Database not connected yet. Add PostgreSQL in Railway and set DATABASE_URL.</p></body></html>');
    });
    app.listen(PORT, '0.0.0.0', () => console.log(`Server waiting for database on port ${PORT}`));
    return;
  }
  try {
    await initDB();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`JMOS server running on port ${PORT}`);
      console.log(`Open: https://jmos-wv.up.railway.app`);
    });
  } catch (err) {
    console.error('Database initialization failed:', err);
    console.error('Retrying in 5 seconds...');
    setTimeout(start, 5000);
  }
}
start();
