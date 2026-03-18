const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const sharp = require('sharp');

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
      must_change_password BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    -- Add column if table already exists (default false — existing users keep their passwords)
    DO $$ BEGIN
      ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT false;
    EXCEPTION WHEN OTHERS THEN NULL;
    END $$;
    -- Clear any existing users that were accidentally flagged
    UPDATE users SET must_change_password = false WHERE must_change_password = true;
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
    CREATE TABLE IF NOT EXISTS settings (
      key VARCHAR(100) PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS target_rates (
      id SERIAL PRIMARY KEY,
      equip_code VARCHAR(50) NOT NULL,
      product_code VARCHAR(50) NOT NULL,
      rate INTEGER NOT NULL,
      source VARCHAR(20) DEFAULT 'default',
      effective_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      set_by VARCHAR(100),
      UNIQUE(equip_code, product_code)
    );
    CREATE TABLE IF NOT EXISTS target_rate_history (
      id SERIAL PRIMARY KEY,
      equip_code VARCHAR(50) NOT NULL,
      product_code VARCHAR(50) NOT NULL,
      old_rate INTEGER NOT NULL,
      new_rate INTEGER NOT NULL,
      source VARCHAR(20) DEFAULT 'bdr',
      changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      changed_by VARCHAR(100),
      notes TEXT
    );
    CREATE TABLE IF NOT EXISTS bdr_records (
      id SERIAL PRIMARY KEY,
      equip_code VARCHAR(50) NOT NULL,
      product_code VARCHAR(50) NOT NULL,
      detected_rate INTEGER NOT NULL,
      current_target INTEGER NOT NULL,
      hours_count INTEGER NOT NULL,
      total_good INTEGER NOT NULL,
      shift_date VARCHAR(10),
      operators TEXT[],
      status VARCHAR(20) DEFAULT 'pending',
      decided_by VARCHAR(100),
      decided_at TIMESTAMP,
      decline_reason TEXT,
      total_dt_minutes INTEGER DEFAULT 0,
      total_defects INTEGER DEFAULT 0,
      availability NUMERIC(5,1) DEFAULT 0,
      performance NUMERIC(5,1) DEFAULT 0,
      quality NUMERIC(5,1) DEFAULT 0,
      oee NUMERIC(5,1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    -- Add OEE columns if they don't exist yet (safe migration)
    DO $$ BEGIN
      ALTER TABLE bdr_records ADD COLUMN IF NOT EXISTS total_dt_minutes INTEGER DEFAULT 0;
      ALTER TABLE bdr_records ADD COLUMN IF NOT EXISTS total_defects INTEGER DEFAULT 0;
      ALTER TABLE bdr_records ADD COLUMN IF NOT EXISTS availability NUMERIC(5,1) DEFAULT 0;
      ALTER TABLE bdr_records ADD COLUMN IF NOT EXISTS performance NUMERIC(5,1) DEFAULT 0;
      ALTER TABLE bdr_records ADD COLUMN IF NOT EXISTS quality NUMERIC(5,1) DEFAULT 0;
      ALTER TABLE bdr_records ADD COLUMN IF NOT EXISTS oee NUMERIC(5,1) DEFAULT 0;
    END $$;
  `);

  // One-time migration: reassign Pipe Assembly records from Landis to new Pipe Assembly equipment
  await pool.query(`
    UPDATE submissions
    SET data = jsonb_set(data, '{equipCode}', '"WV-MISC-PIPEASSY"')
    WHERE data->>'equipCode' = 'WV-MISC-LANDISASSM'
      AND data->'hourData'->>'productCode' = 'P-PPA-001'
  `).catch(() => {});

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
          role: user.role,
          mustChangePassword: user.must_change_password === true
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
        'SELECT id, username, display_name, role, must_change_password FROM users WHERE id = $1',
        [req.session.userId]
      );
      if (rows.length === 0) return res.status(401).json({ error: 'User not found' });
      res.json({
        user: {
          id: rows[0].id,
          username: rows[0].username,
          displayName: rows[0].display_name,
          role: rows[0].role,
          mustChangePassword: rows[0].must_change_password === true
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
      const { clientId, ...rest } = req.body;
      const shiftData = rest.shiftData || null;
      const equipData = rest.equipData || null;
      const selectedEquip = rest.selectedEquip || null;
      if (clientId) {
        const existing = await pool.query('SELECT id FROM submissions WHERE client_id = $1', [clientId]);
        if (existing.rows.length > 0) {
          return res.json({ ok: true, id: existing.rows[0].id, duplicate: true });
        }
      }
      // Store the full payload so no data is lost (individual hours, full shifts, etc.)
      const dataToStore = { shiftData, equipData, selectedEquip };
      // For individual hour submissions, also store the hour-level fields
      if (rest.equipCode) {
        dataToStore.equipCode = rest.equipCode;
        dataToStore.hourIdx = rest.hourIdx;
        dataToStore.hourData = rest.hourData;
        dataToStore.resubmit = rest.resubmit || false;
      }
      // For individual hour resubmissions, update existing record instead of creating duplicate
      if (rest.equipCode && shiftData?.shiftDate && shiftData?.shiftNum) {
        const existing = await pool.query(
          `SELECT id FROM submissions WHERE shift_date = $1 AND shift_num = $2 AND data->>'equipCode' = $3 AND (data->>'hourIdx')::text = $4 LIMIT 1`,
          [shiftData.shiftDate, shiftData.shiftNum, rest.equipCode, String(rest.hourIdx)]
        );
        if (existing.rows.length > 0) {
          await pool.query('UPDATE submissions SET data = $1, submitted_at = NOW() WHERE id = $2', [JSON.stringify(dataToStore), existing.rows[0].id]);
          return res.json({ ok: true, id: existing.rows[0].id, updated: true });
        }
      }
      const result = await pool.query(
        'INSERT INTO submissions (user_id, client_id, shift_date, shift_num, data) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [req.session.userId, clientId || null, shiftData?.shiftDate, shiftData?.shiftNum, JSON.stringify(dataToStore)]
      );
      res.json({ ok: true, id: result.rows[0].id });
    } catch (err) {
      console.error('Submit error:', err);
      res.status(500).json({ error: 'Failed to save data' });
    }
  });

  // ── Master/settings persistence (survives cache clear) ──
  app.get('/api/settings/:key', requireAuth, async (req, res) => {
    try {
      const { rows } = await pool.query('SELECT value FROM settings WHERE key = $1', [req.params.key]);
      res.json(rows.length > 0 ? rows[0].value : null);
    } catch (err) {
      console.error('Settings fetch error:', err);
      res.status(500).json({ error: 'Failed to fetch settings' });
    }
  });
  app.put('/api/settings/:key', requireAuth, async (req, res) => {
    try {
      await pool.query(
        `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [req.params.key, JSON.stringify(req.body.value)]
      );
      res.json({ ok: true });
    } catch (err) {
      console.error('Settings save error:', err);
      res.status(500).json({ error: 'Failed to save settings' });
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
        const { clientId, ...rest } = sub;
        const shiftData = rest.shiftData || null;
        const equipData = rest.equipData || null;
        const selectedEquip = rest.selectedEquip || null;
        if (clientId) {
          const existing = await pool.query('SELECT id FROM submissions WHERE client_id = $1', [clientId]);
          if (existing.rows.length > 0) {
            results.push({ clientId, ok: true, duplicate: true });
            continue;
          }
        }
        // Store the full payload so no data is lost
        const dataToStore = { shiftData, equipData, selectedEquip };
        if (rest.equipCode) {
          dataToStore.equipCode = rest.equipCode;
          dataToStore.hourIdx = rest.hourIdx;
          dataToStore.hourData = rest.hourData;
          dataToStore.resubmit = rest.resubmit || false;
        }
        // For individual hour resubmissions, update existing record instead of creating duplicate
        if (rest.equipCode && shiftData?.shiftDate && shiftData?.shiftNum) {
          const existing = await pool.query(
            `SELECT id FROM submissions WHERE shift_date = $1 AND shift_num = $2 AND data->>'equipCode' = $3 AND (data->>'hourIdx')::text = $4 LIMIT 1`,
            [shiftData.shiftDate, shiftData.shiftNum, rest.equipCode, String(rest.hourIdx)]
          );
          if (existing.rows.length > 0) {
            await pool.query('UPDATE submissions SET data = $1, submitted_at = NOW() WHERE id = $2', [JSON.stringify(dataToStore), existing.rows[0].id]);
            results.push({ clientId, ok: true, id: existing.rows[0].id, updated: true });
            continue;
          }
        }
        const result = await pool.query(
          'INSERT INTO submissions (user_id, client_id, shift_date, shift_num, data) VALUES ($1, $2, $3, $4, $5) RETURNING id',
          [req.session.userId, clientId || null, shiftData?.shiftDate, shiftData?.shiftNum, JSON.stringify(dataToStore)]
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
        'INSERT INTO users (username, password_hash, display_name, role, must_change_password) VALUES ($1, $2, $3, $4, true)',
        [username.toLowerCase(), hash, displayName || username, role || 'operator']
      );
      res.json({ ok: true });
    } catch (err) {
      if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
      console.error('Create user error:', err);
      res.status(500).json({ error: 'Failed to create user' });
    }
  });

  // First-login password set (no current password needed, only when must_change_password is true)
  app.put('/api/users/me/first-password', requireAuth, async (req, res) => {
    try {
      const { newPassword } = req.body;
      if (!newPassword) return res.status(400).json({ error: 'New password required' });
      if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      const { rows } = await pool.query('SELECT must_change_password FROM users WHERE id = $1', [req.session.userId]);
      if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
      if (!rows[0].must_change_password) return res.status(403).json({ error: 'Password already set — use regular change' });
      const hash = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE users SET password_hash = $1, must_change_password = false WHERE id = $2', [hash, req.session.userId]);
      res.json({ ok: true });
    } catch (err) {
      console.error('First password set error:', err);
      res.status(500).json({ error: 'Failed to set password' });
    }
  });

  // Self-service password change (any authenticated user) — MUST be before /:id route
  app.put('/api/users/me/password', requireAuth, async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password required' });
      if (newPassword.length < 4) return res.status(400).json({ error: 'New password must be at least 4 characters' });
      const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.session.userId]);
      if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
      const valid = await bcrypt.compare(currentPassword, rows[0].password_hash);
      if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
      const hash = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE users SET password_hash = $1, must_change_password = false WHERE id = $2', [hash, req.session.userId]);
      res.json({ ok: true });
    } catch (err) {
      console.error('Self password change error:', err);
      res.status(500).json({ error: 'Failed to change password' });
    }
  });

  // Admin: reset any user's password by ID
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

  // ══════════════════════════════════════════
  // ── DAILY EMAIL REPORT ──
  // ══════════════════════════════════════════
  const EQUIP_NAMES={'WV-SHEAR-AS1':'Autoshear #1','WV-SHEAR-AS2':'Autoshear #2','WV-PRESS-400':'400 Press','WV-PRESS-500A':'500A Press','WV-PRESS-500B':'500B Press','WV-HEAD-H1':'Header #1','WV-HEAD-H2':'Header #2','WV-HEAD-H3':'Header #3','WV-HEAD-AUTO':'Auto Header','WV-THREAD-T1':'Threader #1','WV-THREAD-T2':'Threader #2','WV-THREAD-AT':'Autothreader','WV-PEEL-MAN':'Manual Peeler','WV-PEEL-AUTO':'AutoPeeler','WV-PEEL-SWAG':'Swager','WV-ASSY-A1':'Assembly #1','WV-ASSY-A2':'Assembly #2','WV-ASSY-A3':'Assembly #3','WV-ASSY-A4':'Assembly #4','WV-CABLE-C1':'Cable Line #1','WV-CABLE-C2':'Cable Line #2','WV-CABLE-C3':'Cable Line #3','WV-CABLE-C4':'Cable Line #4','WV-MISC-BIGSAW':'Big Saw','WV-MISC-TIELINE':'Tie Line','WV-MISC-OFFWELD':'Offline Welding','WV-MISC-EYEBOLT':'Eyebolt','WV-MISC-LANDISASSM':'Landis Threader/ASSM','WV-MISC-UNITS':'Unit Assembly'};

  function computeDailyReport(dateStr, submissions) {
    const shifts = { '1': [], '2': [] };
    // Deduplicate individual hour entries (keep latest by equip+hour)
    const hourMap = {};
    submissions.forEach(sub => {
      const d = sub.data || sub;
      const sd = d.shiftData || {};
      const shiftNum = sd.shiftNum || '1';
      if (!shifts[shiftNum]) shifts[shiftNum] = [];
      // Handle full-shift submissions (equipData object)
      const ed = d.equipData || {};
      Object.entries(ed).forEach(([equip, hours]) => {
        (hours || []).forEach(hr => {
          if (hr && hr.productCode) {
            const key = shiftNum + '|' + equip + '|' + hr.hourIdx;
            hourMap[key] = { ...hr, equipCode: equip, _shift: shiftNum };
          }
        });
      });
      // Handle individual hour submissions (equipCode + hourData)
      if (d.equipCode && d.hourData) {
        const hr = d.hourData;
        if (hr && hr.productCode) {
          const key = shiftNum + '|' + d.equipCode + '|' + (d.hourIdx || hr.hourIdx);
          hourMap[key] = { ...hr, equipCode: d.equipCode, _shift: shiftNum };
        }
      }
    });
    // Distribute deduplicated records into shifts
    Object.values(hourMap).forEach(hr => {
      const sn = hr._shift;
      if (!shifts[sn]) shifts[sn] = [];
      shifts[sn].push(hr);
    });

    function calcShift(records) {
      let totalTarget = 0, totalGood = 0, totalProduced = 0, totalScheduled = 0, totalDT = 0, totalHours = 0;
      const dtByEquip = {}, defByEquip = {};
      records.forEach(r => {
        const target = parseInt(r.target || 0);
        const good = parseInt(r.goodUnits || 0);
        const sched = parseInt(r.scheduledMins || 0);
        const dtMins = (r.downtime || []).reduce((s, d) => s + parseInt(d.mins || 0), 0);
        const defQty = (r.defects || []).reduce((s, d) => s + parseInt(d.qty || 0), 0);
        const eqName = EQUIP_NAMES[r.equipCode] || r.equipCode || 'Unknown';
        totalTarget += target;
        totalGood += good;
        totalProduced += good + defQty;
        totalScheduled += sched;
        totalDT += dtMins;
        totalHours++;
        if (dtMins > 0) {
          if (!dtByEquip[eqName]) dtByEquip[eqName] = 0;
          dtByEquip[eqName] += dtMins;
        }
        if (defQty > 0) {
          if (!defByEquip[eqName]) defByEquip[eqName] = 0;
          defByEquip[eqName] += defQty;
        }
      });
      // OEE formulas matching the dashboard exactly
      const totalMins = totalHours * 60;
      const sm = totalMins - totalScheduled;  // planned production time (60 - scheduledMins per hour)
      const run = sm - totalDT;               // actual operating time
      const avail = sm > 0 ? run / sm : 0;
      const perf = run > 0 && totalTarget > 0 ? (totalProduced * sm) / (run * totalTarget) : 0;
      const qual = totalProduced > 0 ? totalGood / totalProduced : (totalTarget > 0 ? 0 : 1);
      const oee = avail * perf * qual;
      const topDT = Object.entries(dtByEquip).sort((a, b) => b[1] - a[1]).slice(0, 5);
      const topDef = Object.entries(defByEquip).sort((a, b) => b[1] - a[1]).slice(0, 5);
      const totalDefects = Object.values(defByEquip).reduce((s, v) => s + v, 0);
      return { records: records.length, totalTarget, totalGood, totalProduced, totalScheduled, totalDT, totalDefects, avail, perf, qual, oee, topDT, topDef };
    }

    const s1 = calcShift(shifts['1']);
    const s2 = calcShift(shifts['2']);
    const all = calcShift([...shifts['1'], ...shifts['2']]);
    return { date: dateStr, shift1: s1, shift2: s2, combined: all };
  }

  function oeeColor(v) {
    if (v >= 0.85) return '#22c55e';
    if (v >= 0.65) return '#f59e0b';
    return '#ef4444';
  }
  function pct(v) { return (v * 100).toFixed(1) + '%'; }

  function buildReportSVG(report) {
    const W = 700, pad = 32;
    const d = new Date(report.date + 'T12:00:00');
    const dateDisplay = d.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
    const comb = report.combined;
    const s1 = report.shift1;
    const s2 = report.shift2;
    let parts = [];
    let y = 0;

    // ── Navy Header ──
    const hdrH = 110;
    parts.push(`<rect x="0" y="0" width="${W}" height="${hdrH}" rx="16" ry="16" fill="url(#navyGrad)"/>`);
    parts.push(`<rect x="0" y="${hdrH-16}" width="${W}" height="16" fill="url(#navyGrad)"/>`);
    parts.push(`<text x="${W/2}" y="40" text-anchor="middle" fill="#fff" font-size="26" font-weight="800" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">JMOS Dashboard</text>`);
    parts.push(`<text x="${W/2}" y="60" text-anchor="middle" fill="rgba(255,255,255,0.55)" font-size="12" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">West Virginia Bolt Plant</text>`);
    parts.push(`<rect x="${W/2-20}" y="70" width="40" height="2" rx="1" fill="#c8a951"/>`);
    parts.push(`<text x="${W/2}" y="92" text-anchor="middle" fill="rgba(255,255,255,0.75)" font-size="13" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${dateDisplay}</text>`);
    y = hdrH;

    // ── Combined OEE Hero ──
    const heroH = 120;
    parts.push(`<rect x="0" y="${y}" width="${W}" height="${heroH}" fill="#fff"/>`);
    parts.push(`<text x="${W/2}" y="${y+24}" text-anchor="middle" fill="#94a3b8" font-size="10" font-weight="600" font-family="DejaVu Sans,Arial,Helvetica,sans-serif" letter-spacing="2">OEE</text>`);
    if (comb.records > 0) {
      parts.push(`<text x="${W/2}" y="${y+72}" text-anchor="middle" fill="${oeeColor(comb.oee)}" font-size="52" font-weight="800" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${pct(comb.oee)}</text>`);
      const apqY = y + 100;
      const apqSpacing = 130;
      const cx = W / 2;
      [['Avail', comb.avail], ['Perf', comb.perf], ['Quality', comb.qual]].forEach(([lbl, val], i) => {
        const ax = cx + (i - 1) * apqSpacing;
        parts.push(`<text x="${ax}" y="${apqY}" text-anchor="middle" fill="${oeeColor(val)}" font-size="18" font-weight="700" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${pct(val)}</text>`);
        parts.push(`<text x="${ax}" y="${apqY+14}" text-anchor="middle" fill="#94a3b8" font-size="9" font-weight="600" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${lbl.toUpperCase()}</text>`);
      });
    } else {
      parts.push(`<text x="${W/2}" y="${y+65}" text-anchor="middle" fill="#94a3b8" font-size="36" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">No Data</text>`);
    }
    y += heroH;

    // ── Divider ──
    parts.push(`<rect x="${pad}" y="${y}" width="${W-pad*2}" height="1" fill="#e2e8f0"/>`);
    y += 1;

    // ── Shift Cards Side by Side ──
    const shiftH = 260;
    const colW = (W - pad * 2) / 2;
    parts.push(`<rect x="0" y="${y}" width="${W}" height="${shiftH}" fill="#fff"/>`);

    function drawShift(s, label, ox) {
      let sy = y + 12;
      // Gold underline header
      parts.push(`<rect x="${ox+colW/2-30}" y="${sy+14}" width="60" height="2" rx="1" fill="#c8a951"/>`);
      parts.push(`<text x="${ox+colW/2}" y="${sy+10}" text-anchor="middle" fill="#1b3d6e" font-size="12" font-weight="700" font-family="DejaVu Sans,Arial,Helvetica,sans-serif" letter-spacing="2">${label.toUpperCase()}</text>`);
      sy += 28;

      if (s.records === 0) {
        parts.push(`<text x="${ox+colW/2}" y="${sy+40}" text-anchor="middle" fill="#94a3b8" font-size="13" font-style="italic" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">No data submitted</text>`);
        return;
      }

      // OEE big number
      parts.push(`<text x="${ox+colW/2}" y="${sy+36}" text-anchor="middle" fill="${oeeColor(s.oee)}" font-size="40" font-weight="800" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${pct(s.oee)}</text>`);
      parts.push(`<text x="${ox+colW/2}" y="${sy+50}" text-anchor="middle" fill="#94a3b8" font-size="9" font-weight="600" font-family="DejaVu Sans,Arial,Helvetica,sans-serif" letter-spacing="2">OEE</text>`);
      sy += 64;

      // A / P / Q row
      const miniSpacing = colW / 4;
      [['A', s.avail], ['P', s.perf], ['Q', s.qual]].forEach(([lbl, val], i) => {
        const mx = ox + miniSpacing * (i + 0.5);
        parts.push(`<text x="${mx}" y="${sy+4}" text-anchor="middle" fill="${oeeColor(val)}" font-size="16" font-weight="700" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${pct(val)}</text>`);
        parts.push(`<text x="${mx}" y="${sy+16}" text-anchor="middle" fill="#94a3b8" font-size="8" font-weight="600" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${lbl}</text>`);
      });
      sy += 30;

      // Stats table
      const stats = [
        ['Good Units', s.totalGood.toLocaleString(), '#334155'],
        ['Produced', s.totalProduced.toLocaleString(), '#334155'],
        ['Target', s.totalTarget.toLocaleString(), '#334155'],
        ['Downtime', s.totalDT + ' min', '#ef4444'],
        ['Defects', s.totalDefects.toLocaleString(), '#f59e0b']
      ];
      stats.forEach(([lbl, val, clr], i) => {
        const ry = sy + i * 20;
        parts.push(`<text x="${ox+12}" y="${ry+12}" fill="#64748b" font-size="11" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${lbl}</text>`);
        parts.push(`<text x="${ox+colW-12}" y="${ry+12}" text-anchor="end" fill="${clr}" font-size="11" font-weight="700" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${val}</text>`);
        if (i < stats.length - 1) parts.push(`<rect x="${ox+8}" y="${ry+18}" width="${colW-16}" height="1" fill="#f1f5f9"/>`);
      });
    }

    drawShift(s1, 'Shift 1', pad);
    // Vertical divider
    parts.push(`<rect x="${W/2}" y="${y+8}" width="1" height="${shiftH-16}" fill="#e2e8f0"/>`);
    drawShift(s2, 'Shift 2', W/2);
    y += shiftH;

    // ── Divider ──
    parts.push(`<rect x="${pad}" y="${y}" width="${W-pad*2}" height="1" fill="#e2e8f0"/>`);
    y += 1;

    // ── Top Downtime & Top Defects ──
    if (comb.records > 0 && (comb.topDT.length > 0 || comb.topDef.length > 0)) {
      const issueRows = Math.max(comb.topDT.length, comb.topDef.length);
      const issueH = 40 + issueRows * 32;
      parts.push(`<rect x="0" y="${y}" width="${W}" height="${issueH}" fill="#fff"/>`);

      function drawIssues(items, label, ox, barColor, unit) {
        let iy = y + 8;
        parts.push(`<text x="${ox+12}" y="${iy+12}" fill="#94a3b8" font-size="9" font-weight="700" font-family="DejaVu Sans,Arial,Helvetica,sans-serif" letter-spacing="1.5">${label.toUpperCase()}</text>`);
        iy += 24;
        const maxVal = items.length > 0 ? items[0][1] : 1;
        const barW = colW - 24;
        items.forEach(([name, val], i) => {
          const ry = iy + i * 32;
          parts.push(`<text x="${ox+12}" y="${ry+4}" fill="#334155" font-size="11" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${name}</text>`);
          parts.push(`<text x="${ox+colW-12}" y="${ry+4}" text-anchor="end" fill="#475569" font-size="11" font-weight="700" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">${val}${unit}</text>`);
          // Bar background
          parts.push(`<rect x="${ox+12}" y="${ry+9}" width="${barW}" height="6" rx="3" fill="#f1f5f9"/>`);
          // Bar fill
          const fw = maxVal > 0 ? Math.round((val / maxVal) * barW) : 0;
          parts.push(`<rect x="${ox+12}" y="${ry+9}" width="${fw}" height="6" rx="3" fill="${barColor}"/>`);
        });
      }

      drawIssues(comb.topDT, 'Downtime by Equipment', pad, '#ef4444', ' min');
      drawIssues(comb.topDef, 'Quality by Equipment', W/2, '#f59e0b', ' defects');
      y += issueH;
    }

    // ── Footer ──
    const footH = 36;
    parts.push(`<rect x="0" y="${y}" width="${W}" height="${footH}" rx="0" fill="#f8fafc"/>`);
    parts.push(`<rect x="0" y="${y+footH-16}" width="${W}" height="16" rx="16" ry="16" fill="#f8fafc"/>`);
    parts.push(`<rect x="${pad}" y="${y}" width="${W-pad*2}" height="1" fill="#e2e8f0"/>`);
    parts.push(`<text x="${W/2}" y="${y+22}" text-anchor="middle" fill="#94a3b8" font-size="10" font-family="DejaVu Sans,Arial,Helvetica,sans-serif">jmos-wv.up.railway.app  ·  Auto-generated daily report</text>`);
    y += footH;

    const totalH = y;
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${totalH}" viewBox="0 0 ${W} ${totalH}">
  <defs>
    <linearGradient id="navyGrad" x1="0" y1="0" x2="${W}" y2="${hdrH}" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#0f1e38"/>
      <stop offset="100%" stop-color="#1b3d6e"/>
    </linearGradient>
  </defs>
  <rect width="${W}" height="${totalH}" fill="#f1f5f9" rx="16"/>
  ${parts.join('\n  ')}
</svg>`;
  }

  async function buildReportPNG(report) {
    const svg = buildReportSVG(report);
    console.log('SVG generated, length:', svg.length);
    try {
      const buf = await sharp(Buffer.from(svg)).png().toBuffer();
      console.log('PNG generated, size:', buf.length);
      return buf;
    } catch (err) {
      console.error('Sharp PNG error:', err);
      throw err;
    }
  }

  // Email via Resend HTTP API (no SMTP needed, works on Railway)
  async function sendEmail({ to, subject, html, pngBuffer }) {
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) throw new Error('RESEND_API_KEY not set');
    const fromAddr = process.env.EMAIL_FROM || 'JMOS Dashboard <onboarding@resend.dev>';
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: fromAddr,
        to: Array.isArray(to) ? to : to.split(',').map(e => e.trim()),
        subject,
        html,
        attachments: pngBuffer ? [{ filename: 'jmos-daily-oee.png', content: pngBuffer.toString('base64') }] : []
      })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.message || JSON.stringify(data));
    return data;
  }

  async function sendDailyReport(dateStr) {
    const { rows } = await pool.query('SELECT data FROM submissions WHERE shift_date = $1', [dateStr]);
    if (rows.length === 0) return { sent: false, reason: 'No data for ' + dateStr };

    const report = computeDailyReport(dateStr, rows);
    const pngBuffer = await buildReportPNG(report);
    const recipients = process.env.REPORT_EMAILS;
    if (!recipients) return { sent: false, reason: 'REPORT_EMAILS not configured' };

    const d = new Date(dateStr + 'T12:00:00');
    const subject = `JMOS Daily OEE — ${pct(report.combined.oee)} — ${d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`;

    const result = await sendEmail({
      to: recipients,
      subject,
      html: `<div style="font-family:sans-serif;text-align:center;padding:16px;background:#f1f5f9">
        <p style="margin:0 0 12px;font-size:14px;color:#475569">Your daily OEE report is attached as an image.</p>
        <p style="margin-top:12px;font-size:12px;color:#94a3b8"><a href="https://jmos-wv.up.railway.app" style="color:#1b3d6e;font-weight:600">Open JMOS Dashboard</a></p>
      </div>`,
      pngBuffer
    });
    return { sent: true, to: recipients, subject, id: result.id };
  }

  // API: preview report as PNG image
  app.get('/api/report/preview', requireAuth, async (req, res) => {
    try {
      const dateStr = req.query.date || new Date(Date.now() - 86400000).toISOString().slice(0, 10);
      const { rows } = await pool.query('SELECT data FROM submissions WHERE shift_date = $1', [dateStr]);
      if (rows.length === 0) return res.status(404).send('<h2 style="font-family:sans-serif;text-align:center;padding:60px;color:#64748b">No data for ' + dateStr + '</h2>');
      const report = computeDailyReport(dateStr, rows);
      const fmt = req.query.format || 'png';
      if (fmt === 'svg') {
        res.setHeader('Content-Type', 'image/svg+xml');
        return res.send(buildReportSVG(report));
      }
      const pngBuffer = await buildReportPNG(report);
      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Content-Disposition', `inline; filename="jmos-oee-${dateStr}.png"`);
      res.send(pngBuffer);
    } catch (err) {
      console.error('Report preview error:', err);
      res.status(500).json({ error: 'Failed to generate report' });
    }
  });

  // API: send report now (admin only) — with 30s timeout
  app.post('/api/report/send', requireAdmin, async (req, res) => {
    const timeout = setTimeout(() => {
      if (!res.headersSent) res.status(504).json({ error: 'Report generation timed out' });
    }, 30000);
    try {
      const dateStr = req.body.date || getPreviousWorkday(new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' })));
      console.log('Generating report for', dateStr);
      const result = await sendDailyReport(dateStr);
      clearTimeout(timeout);
      if (!res.headersSent) res.json(result);
    } catch (err) {
      clearTimeout(timeout);
      console.error('Report send error:', err);
      if (!res.headersSent) res.status(500).json({ error: 'Failed to send report: ' + err.message });
    }
  });


  // ══════════════════════════════════════════
  // ── BDR & TARGET RATE MANAGEMENT ──
  // ══════════════════════════════════════════

  // Get all current target rates (from DB, falling back to hardcoded defaults)
  app.get('/api/rates', requireAuth, async (req, res) => {
    try {
      const { rows } = await pool.query('SELECT equip_code, product_code, rate, source, effective_date, set_by FROM target_rates ORDER BY equip_code, product_code');
      res.json(rows);
    } catch (err) {
      console.error('Rates fetch error:', err);
      res.status(500).json({ error: 'Failed to fetch rates' });
    }
  });

  // Seed default rates into DB (called once from client on first load)
  app.post('/api/rates/seed', requireAuth, async (req, res) => {
    try {
      const { rates } = req.body; // [{equipCode, productCode, rate}, ...]
      if (!Array.isArray(rates)) return res.status(400).json({ error: 'Expected rates array' });
      let seeded = 0;
      for (const r of rates) {
        const result = await pool.query(
          `INSERT INTO target_rates (equip_code, product_code, rate, source, set_by)
           VALUES ($1, $2, $3, 'default', 'system')
           ON CONFLICT (equip_code, product_code) DO NOTHING`,
          [r.equipCode, r.productCode, r.rate]
        );
        seeded += result.rowCount;
      }
      res.json({ ok: true, seeded });
    } catch (err) {
      console.error('Rates seed error:', err);
      res.status(500).json({ error: 'Failed to seed rates' });
    }
  });

  // Get rate change history
  app.get('/api/rates/history', requireAuth, async (req, res) => {
    try {
      const { rows } = await pool.query(
        'SELECT * FROM target_rate_history ORDER BY changed_at DESC LIMIT 200'
      );
      res.json(rows);
    } catch (err) {
      console.error('Rate history fetch error:', err);
      res.status(500).json({ error: 'Failed to fetch rate history' });
    }
  });

  // Get all BDR records (pending + decided)
  app.get('/api/bdr', requireAuth, async (req, res) => {
    try {
      const status = req.query.status; // 'pending', 'approved', 'declined', or omit for all
      let query = 'SELECT * FROM bdr_records';
      const params = [];
      if (status) { query += ' WHERE status = $1'; params.push(status); }
      query += ' ORDER BY created_at DESC';
      const { rows } = await pool.query(query, params);
      res.json(rows);
    } catch (err) {
      console.error('BDR fetch error:', err);
      res.status(500).json({ error: 'Failed to fetch BDR records' });
    }
  });

  // Submit a new pending BDR
  app.post('/api/bdr', requireAuth, async (req, res) => {
    try {
      const { equipCode, productCode, detectedRate, currentTarget, hoursCount, totalGood, shiftDate, operators,
              totalDTMinutes, totalDefects, availability, performance, quality, oee } = req.body;
      if (!equipCode || !productCode || !detectedRate) return res.status(400).json({ error: 'Missing required fields' });
      // Skip if already approved or declined for the same equip+product+date
      if (shiftDate) {
        const decided = await pool.query(
          "SELECT id FROM bdr_records WHERE equip_code = $1 AND product_code = $2 AND shift_date = $3 AND status IN ('approved','declined')",
          [equipCode, productCode, shiftDate]
        );
        if (decided.rows.length > 0) return res.json({ ok: true, id: decided.rows[0].id, skipped: true });
      }
      // Check if there's already a pending BDR for this combo — update it if so
      const existing = await pool.query(
        "SELECT id FROM bdr_records WHERE equip_code = $1 AND product_code = $2 AND status = 'pending'",
        [equipCode, productCode]
      );
      if (existing.rows.length > 0) {
        await pool.query(
          `UPDATE bdr_records SET detected_rate = $1, current_target = $2, hours_count = $3,
           total_good = $4, shift_date = $5, operators = $6, total_dt_minutes = $7,
           total_defects = $8, availability = $9, performance = $10, quality = $11, oee = $12, created_at = NOW()
           WHERE id = $13`,
          [detectedRate, currentTarget, hoursCount, totalGood, shiftDate, operators || [],
           totalDTMinutes || 0, totalDefects || 0, availability || 0, performance || 0, quality || 0, oee || 0,
           existing.rows[0].id]
        );
        return res.json({ ok: true, id: existing.rows[0].id, updated: true });
      }
      const result = await pool.query(
        `INSERT INTO bdr_records (equip_code, product_code, detected_rate, current_target, hours_count, total_good, shift_date, operators,
         total_dt_minutes, total_defects, availability, performance, quality, oee)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id`,
        [equipCode, productCode, detectedRate, currentTarget, hoursCount, totalGood, shiftDate, operators || [],
         totalDTMinutes || 0, totalDefects || 0, availability || 0, performance || 0, quality || 0, oee || 0]
      );
      res.json({ ok: true, id: result.rows[0].id });
    } catch (err) {
      console.error('BDR submit error:', err);
      res.status(500).json({ error: 'Failed to submit BDR' });
    }
  });

  // Approve a pending BDR
  app.post('/api/bdr/:id/approve', requireAdmin, async (req, res) => {
    try {
      const bdrId = parseInt(req.params.id);
      const approvedBy = req.body.approvedBy || req.session.displayName || 'Admin';
      // Get the BDR record
      const { rows } = await pool.query("SELECT * FROM bdr_records WHERE id = $1 AND status = 'pending'", [bdrId]);
      if (rows.length === 0) return res.status(404).json({ error: 'Pending BDR not found' });
      const bdr = rows[0];
      // Get current rate from target_rates table
      const rateRow = await pool.query(
        'SELECT rate FROM target_rates WHERE equip_code = $1 AND product_code = $2',
        [bdr.equip_code, bdr.product_code]
      );
      const oldRate = rateRow.rows.length > 0 ? rateRow.rows[0].rate : bdr.current_target;
      // Log rate change to history
      await pool.query(
        `INSERT INTO target_rate_history (equip_code, product_code, old_rate, new_rate, source, changed_by, notes)
         VALUES ($1, $2, $3, $4, 'bdr', $5, $6)`,
        [bdr.equip_code, bdr.product_code, oldRate, bdr.detected_rate, approvedBy,
         'BDR from ' + bdr.shift_date + ' (' + bdr.hours_count + 'hrs, operators: ' + (bdr.operators || []).join(', ') + ')']
      );
      // Update or insert the target rate
      await pool.query(
        `INSERT INTO target_rates (equip_code, product_code, rate, source, effective_date, set_by)
         VALUES ($1, $2, $3, 'bdr', NOW(), $4)
         ON CONFLICT (equip_code, product_code) DO UPDATE SET rate = $3, source = 'bdr', effective_date = NOW(), set_by = $4`,
        [bdr.equip_code, bdr.product_code, bdr.detected_rate, approvedBy]
      );
      // Mark BDR as approved
      await pool.query(
        "UPDATE bdr_records SET status = 'approved', decided_by = $1, decided_at = NOW() WHERE id = $2",
        [approvedBy, bdrId]
      );
      res.json({ ok: true, oldRate, newRate: bdr.detected_rate });
    } catch (err) {
      console.error('BDR approve error:', err);
      res.status(500).json({ error: 'Failed to approve BDR' });
    }
  });

  // Decline a pending BDR
  app.post('/api/bdr/:id/decline', requireAdmin, async (req, res) => {
    try {
      const bdrId = parseInt(req.params.id);
      const declinedBy = req.body.declinedBy || req.session.displayName || 'Admin';
      const reason = req.body.reason || 'Declined by admin';
      const { rows } = await pool.query("SELECT * FROM bdr_records WHERE id = $1 AND status = 'pending'", [bdrId]);
      if (rows.length === 0) return res.status(404).json({ error: 'Pending BDR not found' });
      await pool.query(
        "UPDATE bdr_records SET status = 'declined', decided_by = $1, decided_at = NOW(), decline_reason = $2 WHERE id = $3",
        [declinedBy, reason, bdrId]
      );
      res.json({ ok: true });
    } catch (err) {
      console.error('BDR decline error:', err);
      res.status(500).json({ error: 'Failed to decline BDR' });
    }
  });

  // ── AI SETTINGS ASSISTANT ──
  app.post('/api/ai/settings', requireAuth, async (req, res) => {
    try {
      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) return res.status(503).json({ error: 'AI not configured — ANTHROPIC_API_KEY not set', reply: 'AI assistant is not configured. Please ask your administrator to set up the ANTHROPIC_API_KEY.', actions: [] });
      const { message, context, currentData, history } = req.body;
      if (!message) return res.status(400).json({ error: 'Missing message' });
      const systemPrompt = `You help manage the JMOS OEE Dashboard settings for Jennmar's WV Bolt Plant. Talk like a helpful coworker — friendly, direct, no corporate-speak or buzzwords.

HOW THE SETTINGS PAGE WORKS (so you can guide users):
The Settings page has tabs on the left sidebar:
- PERSONNEL tab: List of names, each with an X button to the right to remove them. Add via the input box at top.
- OPERATORS tab: Same layout — list with X buttons to remove. Add via input box at top.
- EQUIPMENT tab: Table with Code, Name, Process columns. Each row has an Active toggle switch and a trash icon to delete. Users can toggle active/inactive or delete.
- PRODUCTS tab: Table with Code, Name. Each row has a trash icon to delete.
- TARGET RATES tab: View/edit production target rates per equipment+product.
- USERS tab: Manage user accounts (admin only).
- DATABASE tab: View and export production data.

You can ADD four things via action chips (I'll generate confirm buttons):
1. PERSONNEL — data entry staff ("Entered By" dropdown)
2. OPERATORS — shop floor workers assigned to machines
3. EQUIPMENT — machines/workstations
4. PRODUCTS — part types that run on equipment

For REMOVING or EDITING — tell the user exactly how in the UI:
- Remove a person: "Go to the Operators tab (or Personnel tab) and click the X next to their name."
- Deactivate equipment: "Go to Equipment tab and toggle the Active switch off next to it."
- Delete a product: "Go to Products tab and click the trash icon next to it."
- Change a rate: "Go to Target Rates tab, find the equipment, and update the rate."
NEVER say "reach out to someone" or "contact an admin" for things they can do themselves.

WHAT'S ALREADY IN THE SYSTEM:
Personnel: ${(currentData?.supervisors || []).join(', ') || 'none yet'}
Operators: ${(currentData?.operators || []).join(', ') || 'none yet'}
Custom Equipment: ${(currentData?.customEquipment || []).map(e => e.name).join(', ') || 'none added'}
Custom Products: ${(currentData?.customProducts || []).map(p => p.name).join(', ') || 'none added'}

RESPONSE FORMAT — always valid JSON:
{
  "reply": "Your response. Confirm adds, or guide the user to the right tab/button for other actions.",
  "actions": [
    { "type": "add_personnel", "name": "LAST, FIRST" },
    { "type": "add_operator", "name": "LAST, FIRST" },
    { "type": "add_equipment", "code": "WV-PROC-XX", "name": "Equipment Name", "process": "Process Group" },
    { "type": "add_product", "code": "P-XXX-001", "name": "Product Description" }
  ]
}

RULES:
- Names: LAST, FIRST format, ALL CAPS. "add mike johnson" → "JOHNSON, MIKE".
- First name only → ask for last name.
- Vague equipment → ask for name and process group (Shears, Presses, Headers, Threaders, Peeling, Assembly, Cable Lines, Misc).
- Codes: equipment WV-[PROCESS]-[ID], products P-[TYPE]-[NUM]. Match existing patterns.
- No duplicates. Say it exists already.
- Multiple items = multiple actions.
- For removal/editing/toggling: guide them to the exact tab and button. You know the UI.
- Don't make up data. Ask if unsure.
- Be brief. 1-3 sentences. Sound human.`;

      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 600,
          system: systemPrompt,
          messages: Array.isArray(history) && history.length > 1
            ? history.filter(m => m.role === 'user' || m.role === 'assistant')
            : [{ role: 'user', content: message }]
        })
      });
      if (!resp.ok) { const err = await resp.text(); return res.status(502).json({ error: 'AI API error', reply: 'AI request failed. Please try again.', actions: [] }); }
      const data = await resp.json();
      const raw = data.content && data.content[0] ? data.content[0].text : '{}';
      let parsed = { reply: raw, actions: [] };
      try { parsed = JSON.parse(raw); } catch(e) {
        // Try to extract JSON from the text
        const match = raw.match(/\{[\s\S]*\}/);
        if (match) { try { parsed = JSON.parse(match[0]); } catch(e2) { parsed = { reply: raw, actions: [] }; } }
      }
      res.json({ reply: parsed.reply || 'Request processed.', actions: parsed.actions || [] });
    } catch (err) {
      console.error('AI settings error:', err);
      res.status(500).json({ error: 'Failed to process request', reply: 'An error occurred. Please try again.', actions: [] });
    }
  });

  // ── AI INSIGHTS (Claude API proxy) ──
  // Build database context for AI — only fetches based on provided filters
  async function buildDBContext(filters) {
    try {
      const { dateFrom, dateTo, shift } = filters || {};
      if (!dateFrom && !dateTo) return ''; // No filters = no DB context (user must press Load Data)

      // Query based on filters
      let query = 'SELECT shift_date, shift_num, data FROM submissions WHERE 1=1';
      const params = [];
      if (dateFrom) { params.push(dateFrom); query += ` AND shift_date >= $${params.length}`; }
      if (dateTo) { params.push(dateTo); query += ` AND shift_date <= $${params.length}`; }
      if (shift && shift !== 'all') { params.push(shift); query += ` AND shift_num = $${params.length}`; }
      query += ' ORDER BY shift_date DESC LIMIT 2000';

      const { rows } = await pool.query(query, params);
      if (rows.length === 0) return 'No production data found for the selected filters.';

      // Aggregate by date
      const byDate = {};
      const allOperators = new Set();
      rows.forEach(r => {
        const d = r.data;
        const date = r.shift_date || d.shiftData?.shiftDate || 'unknown';
        if (!byDate[date]) byDate[date] = { records: 0, good: 0, target: 0, dt: 0, defects: 0, equip: new Set(), operators: new Set() };
        byDate[date].records++;
        if (d.hourData) {
          byDate[date].good += parseInt(d.hourData.goodUnits || 0);
          byDate[date].target += parseInt(d.hourData.target || 0);
          byDate[date].dt += (d.hourData.downtime || []).reduce((s, x) => s + parseInt(x.mins || 0), 0);
          byDate[date].defects += (d.hourData.defects || []).reduce((s, x) => s + parseInt(x.qty || 0), 0);
          if (d.equipCode) byDate[date].equip.add(d.equipCode);
          // Track operators
          (d.hourData.operators || []).forEach(op => {
            if (op) { byDate[date].operators.add(op); allOperators.add(op); }
          });
        }
      });

      // Build summary for dates
      const dates = Object.keys(byDate).sort().reverse();
      const summary = dates.map(dt => {
        const d = byDate[dt];
        const oee = d.target > 0 ? Math.round(d.good / d.target * 100) : 0;
        const ops = d.operators.size > 0 ? `, operators: ${[...d.operators].join(', ')}` : '';
        return `${dt}: ${d.records} hrs, ${d.good} good/${d.target} target (${oee}% perf), ${d.dt}min DT, ${d.defects} defects, ${d.equip.size} equip${ops}`;
      });

      // Equipment + operator breakdown for most recent date in range
      const latestDate = dates[0];
      const latestRows = rows.filter(r => (r.shift_date || r.data.shiftData?.shiftDate) === latestDate);
      const equipSummary = {};
      latestRows.forEach(r => {
        const d = r.data;
        const ec = d.equipCode || 'unknown';
        if (!equipSummary[ec]) equipSummary[ec] = { good: 0, target: 0, dt: 0, defects: 0, hours: 0, products: new Set(), operators: new Set() };
        if (d.hourData) {
          equipSummary[ec].good += parseInt(d.hourData.goodUnits || 0);
          equipSummary[ec].target += parseInt(d.hourData.target || 0);
          equipSummary[ec].dt += (d.hourData.downtime || []).reduce((s, x) => s + parseInt(x.mins || 0), 0);
          equipSummary[ec].defects += (d.hourData.defects || []).reduce((s, x) => s + parseInt(x.qty || 0), 0);
          equipSummary[ec].hours++;
          if (d.hourData.productCode) equipSummary[ec].products.add(d.hourData.productCode);
          (d.hourData.operators || []).forEach(op => { if (op) equipSummary[ec].operators.add(op); });
        }
      });
      const equipLines = Object.entries(equipSummary).map(([ec, e]) =>
        `  ${ec}: ${e.good} good/${e.target} target, ${e.dt}min DT, ${e.defects} def, ${e.hours}hrs, products: ${[...e.products].join(',')}, operators: ${[...e.operators].join(', ') || 'none'}`
      );

      return `DATABASE (${rows.length} records, ${dateFrom || 'all'} to ${dateTo || 'all'}, shift: ${shift || 'all'}):\n\nDAILY SUMMARY:\n${summary.join('\n')}\n\nLATEST DATE (${latestDate}) EQUIPMENT+OPERATOR BREAKDOWN:\n${equipLines.join('\n')}\n\nALL OPERATORS IN RANGE: ${[...allOperators].join(', ') || 'none'}`;
    } catch (err) {
      console.error('DB context error:', err);
      return 'Could not load database context.';
    }
  }

  app.post('/api/ai/ask', requireAuth, async (req, res) => {
    try {
      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) return res.status(503).json({ error: 'AI not configured — ANTHROPIC_API_KEY not set' });
      const { question, context, section, filters } = req.body;
      if (!question) return res.status(400).json({ error: 'Missing question' });

      // Pull database context based on the user's current dashboard filters
      const dbContext = await buildDBContext(filters);

      const systemPrompt = `You are a senior OEE analyst for the JMOS Dashboard at Jennmar's West Virginia Bolt Plant. You provide expert manufacturing analysis.

The user is asking from the "${section || 'general'}" section of the dashboard. You have TWO data sources:
1. CHART CONTEXT: The specific data visible on their current chart/view (filtered by their selected dates and shift)
2. DATABASE: Production records from the database matching their current filters, including operator names, equipment, downtime, defects, and production output

ANALYSIS APPROACH:
- Start with the specific data the user is asking about (the chart they're viewing)
- Cross-reference with the database to identify patterns, trends, and root causes
- Name specific equipment, operators, downtime codes, and defect types when relevant
- Compare current performance to historical baselines when the data supports it
- Identify the top 1-2 actionable improvements

RESPONSE STYLE:
- Lead with the key finding or answer
- Support with specific numbers: units, percentages, minutes, equipment names, operator names
- End with a concrete recommendation or observation when applicable
- Use 3-6 sentences. Plain language like a plant floor report — no corporate jargon
- Never say you can't answer or need to investigate — analyze what's available and give your best assessment
- If data is limited, state what you can conclude and what additional data would help`;

      const userMsg = `CHART CONTEXT (what the user is currently viewing):\n${context || 'No chart context provided'}\n\nFULL DATABASE:\n${dbContext}\n\nQuestion: ${question}`;

      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 800,
          system: systemPrompt,
          messages: [{ role: 'user', content: userMsg }]
        })
      });
      if (!resp.ok) { const err = await resp.text(); return res.status(502).json({ error: 'AI API error: ' + resp.status }); }
      const data = await resp.json();
      const answer = data.content && data.content[0] ? data.content[0].text : 'No response';
      res.json({ answer });
    } catch (err) {
      console.error('AI ask error:', err);
      res.status(500).json({ error: 'Failed to get AI insight' });
    }
  });

  // Get previous working day (Mon→Fri, Tue-Fri→previous day, Sat/Sun→skip)
  function getPreviousWorkday(now) {
    const day = now.getDay(); // 0=Sun,1=Mon,...,6=Sat
    const prev = new Date(now);
    if (day === 1) prev.setDate(prev.getDate() - 3);      // Monday → Friday
    else if (day === 0) prev.setDate(prev.getDate() - 2);  // Sunday → Friday
    else if (day === 6) prev.setDate(prev.getDate() - 1);  // Saturday → Friday
    else prev.setDate(prev.getDate() - 1);                 // Tue-Fri → previous day
    return prev.toISOString().slice(0, 10);
  }

  // Daily auto-send scheduler (weekdays only, sends previous workday's data)
  const REPORT_HOUR = parseInt(process.env.REPORT_HOUR || '6'); // 6 AM ET default
  let lastReportDate = null;
  setInterval(async () => {
    try {
      const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
      const todayStr = now.toISOString().slice(0, 10);
      const dayOfWeek = now.getDay();
      // Only send on weekdays (Mon-Fri)
      if (dayOfWeek >= 1 && dayOfWeek <= 5 && now.getHours() >= REPORT_HOUR && lastReportDate !== todayStr) {
        const reportDate = getPreviousWorkday(now);
        console.log('Auto-sending daily report for', reportDate, '(today is', todayStr, ')');
        const result = await sendDailyReport(reportDate);
        console.log('Daily report result:', result);
        lastReportDate = todayStr;
      }
    } catch (err) {
      console.error('Daily report scheduler error:', err);
    }
  }, 30 * 60 * 1000); // Check every 30 minutes

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
// Start listening IMMEDIATELY so Railway sees the app is alive
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on port ${PORT}`);
});

// Temporary route while DB initializes
app.get('/__health', (req, res) => res.send('ok'));

async function start() {
  if (!process.env.DATABASE_URL) {
    console.error('WARNING: DATABASE_URL not set.');
    app.get('*', (req, res) => {
      res.status(503).send('<html><body style="font-family:sans-serif;text-align:center;padding:60px"><h1>JMOS Setup In Progress</h1><p>Database not connected yet. Add PostgreSQL in Railway and set DATABASE_URL.</p></body></html>');
    });
    return;
  }
  console.log('DATABASE_URL found, connecting to database...');
  console.log('DB host:', process.env.DATABASE_URL.split('@')[1]?.split('/')[0] || 'unknown');
  try {
    await initDB();
    console.log('Database initialized successfully!');
    console.log(`App ready at https://jmos-wv.up.railway.app`);
  } catch (err) {
    console.error('Database initialization failed:', err.message);
    console.error('Retrying in 5 seconds...');
    setTimeout(start, 5000);
  }
}
start();
