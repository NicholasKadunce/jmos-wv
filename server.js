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
let mysqlPool = null;

// ── MYSQL EQUIPMENT MAPPING ──
const MYSQL_EQUIP_MAP = {
  'WV-SHEAR-AS1':  { prodId: 'WVSHEAR1',     schedId: 'WV_Shear_1' },
  'WV-SHEAR-AS2':  { prodId: 'WVSHEAR2',     schedId: 'WV_Shear_2' },
  'WV-PRESS-400':  { prodId: 'WVPRESS1',     schedId: 'WV_Press_1' },
  'WV-PRESS-500A': { prodId: 'WVPRESS2',     schedId: 'WV_Press_2' },
  'WV-PRESS-500B': { prodId: 'WVPRESS3',     schedId: 'WV_Press_3' },
  'WV-HEAD-H2':    { prodId: 'WVHEADER2',    schedId: 'WV_Header_2' },
  'WV-THREAD-T1':  { prodId: 'WVTHREADER1',  schedId: 'WV_Threader_1' },
  'WV-THREAD-T2':  { prodId: 'WVTHREADER2',  schedId: 'WV_Threader_2' },
  'WV-THREAD-AT':  { prodId: 'WVTHREADER3',  schedId: 'WV_Threader_3' },
  'WV-PEEL-MAN':   { prodId: 'WVPEELER1',    schedId: 'WV_Peeler_1' },
  'WV-PEEL-AUTO':  { prodId: 'WVAUTOPEELER', schedId: 'WV_Auto_Peeler' },
  'WV-PEEL-SWAG':  { prodId: 'WVSWAGER3',    schedId: 'WV_Swager_3' },
  'WV-CABLE-C1':   { prodId: 'WVCABLE1',     schedId: 'WV_Cable_1' },
  'WV-CABLE-C2':   { prodId: 'WVCABLE2',     schedId: 'WV_Cable_2' },
  'WV-CABLE-C3':   { prodId: 'WVCABLE3',     schedId: 'WV_Cable_3' },
  'WV-CABLE-C4':   { prodId: 'WVCABLE4',     schedId: 'WV_Cable_4' },
};

// Reverse lookup: MySQL prodId → app equipCode
const MYSQL_REVERSE_MAP = {};
for (const [appCode, ids] of Object.entries(MYSQL_EQUIP_MAP)) {
  MYSQL_REVERSE_MAP[ids.prodId] = appCode;
}

// Per-equipment downtime thresholds in minutes (gaps shorter than this are normal cycle gaps)
const MYSQL_DT_THRESHOLDS = {
  'WV-PRESS-400': 2, 'WV-PRESS-500A': 2, 'WV-PRESS-500B': 2,
  'WV-PEEL-AUTO': 2, 'WV-PEEL-MAN': 2,
  'WV-SHEAR-AS1': 2, 'WV-SHEAR-AS2': 2,
  'WV-CABLE-C1': 5, 'WV-CABLE-C2': 5, 'WV-CABLE-C4': 5,
  'WV-CABLE-C3': 3,
  _default: 3
};
function getDTThreshold(equipCode) {
  return MYSQL_DT_THRESHOLDS[equipCode] || MYSQL_DT_THRESHOLDS._default;
}

// ── MYSQL CACHE ──
const mysqlCache = { production: null, downtime: null, timestamps: null, lastRefresh: 0, refreshing: false };
const MYSQL_CACHE_TTL = 60000; // 60 seconds

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

    -- MySQL downtime classification storage
    CREATE TABLE IF NOT EXISTS downtime_classifications (
      id SERIAL PRIMARY KEY,
      mysql_event_id BIGINT NOT NULL UNIQUE,
      equip_code VARCHAR(50) NOT NULL,
      shift_date VARCHAR(10),
      dt_code INTEGER NOT NULL,
      sub_item VARCHAR(100),
      classified_by VARCHAR(100),
      classified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_dt_class_event ON downtime_classifications(mysql_event_id);
    CREATE INDEX IF NOT EXISTS idx_dt_class_equip ON downtime_classifications(equip_code, shift_date);

    -- Operator shift assignments (smart assignment with timeline)
    CREATE TABLE IF NOT EXISTS operator_assignments (
      id SERIAL PRIMARY KEY,
      shift_date VARCHAR(10) NOT NULL,
      shift_num VARCHAR(2) NOT NULL,
      equip_code VARCHAR(50) NOT NULL,
      operator_name VARCHAR(100) NOT NULL,
      start_hour INTEGER DEFAULT 1,
      end_hour INTEGER,
      assigned_by VARCHAR(100),
      assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(shift_date, shift_num, equip_code, operator_name)
    );
    CREATE INDEX IF NOT EXISTS idx_op_assign_shift ON operator_assignments(shift_date, shift_num);

    -- Auto-equipment defect reports (quick-report anytime)
    CREATE TABLE IF NOT EXISTS auto_defect_reports (
      id SERIAL PRIMARY KEY,
      equip_code VARCHAR(50) NOT NULL,
      shift_date VARCHAR(10) NOT NULL,
      shift_num VARCHAR(2) NOT NULL,
      reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      def_code INTEGER NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      hour_idx INTEGER,
      reported_by VARCHAR(100),
      notes TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_auto_def_shift ON auto_defect_reports(equip_code, shift_date);

    -- Auto-production log: MySQL production data persisted to PG for historical access
    CREATE TABLE IF NOT EXISTS auto_production_log (
      id SERIAL PRIMARY KEY,
      date VARCHAR(10) NOT NULL,
      shift_num VARCHAR(2) NOT NULL,
      equip_code VARCHAR(50) NOT NULL,
      hour_idx INTEGER NOT NULL,
      clock_hour INTEGER NOT NULL,
      good_units INTEGER NOT NULL DEFAULT 0,
      synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(date, equip_code, clock_hour)
    );
    CREATE INDEX IF NOT EXISTS idx_auto_prod_date ON auto_production_log(date);
    CREATE INDEX IF NOT EXISTS idx_auto_prod_equip_date ON auto_production_log(equip_code, date);

    -- Auto-downtime log: MySQL downtime events persisted to PG for historical access
    CREATE TABLE IF NOT EXISTS auto_downtime_log (
      id SERIAL PRIMARY KEY,
      mysql_event_id BIGINT NOT NULL UNIQUE,
      equip_code VARCHAR(50) NOT NULL,
      date VARCHAR(10) NOT NULL,
      shift_num VARCHAR(2) NOT NULL,
      hour_idx INTEGER NOT NULL,
      start_time TIMESTAMPTZ,
      end_time TIMESTAMPTZ,
      duration_mins INTEGER NOT NULL DEFAULT 0,
      mysql_code VARCHAR(50),
      mysql_desc TEXT,
      synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_auto_dt_date ON auto_downtime_log(date);
    CREATE INDEX IF NOT EXISTS idx_auto_dt_equip_date ON auto_downtime_log(equip_code, date);

    -- Per-minute production counts (30-day retention for cycle time charts)
    CREATE TABLE IF NOT EXISTS auto_production_minutes (
      id SERIAL PRIMARY KEY,
      date VARCHAR(10) NOT NULL,
      equip_code VARCHAR(50) NOT NULL,
      clock_hour INTEGER NOT NULL,
      clock_minute INTEGER NOT NULL,
      part_count INTEGER NOT NULL DEFAULT 0,
      synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(date, equip_code, clock_hour, clock_minute)
    );
    CREATE INDEX IF NOT EXISTS idx_auto_prod_min_equip ON auto_production_minutes(equip_code, date);

    -- Per-hour cycle time statistics (30-day retention)
    CREATE TABLE IF NOT EXISTS auto_cycle_time_stats (
      id SERIAL PRIMARY KEY,
      date VARCHAR(10) NOT NULL,
      equip_code VARCHAR(50) NOT NULL,
      clock_hour INTEGER NOT NULL,
      avg_ct NUMERIC(8,2) NOT NULL DEFAULT 0,
      min_ct NUMERIC(8,2) NOT NULL DEFAULT 0,
      max_ct NUMERIC(8,2) NOT NULL DEFAULT 0,
      stddev_ct NUMERIC(8,2) NOT NULL DEFAULT 0,
      sample_count INTEGER NOT NULL DEFAULT 0,
      ucl NUMERIC(8,2) NOT NULL DEFAULT 0,
      lcl NUMERIC(8,2) NOT NULL DEFAULT 0,
      target_ct NUMERIC(8,2) NOT NULL DEFAULT 0,
      synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(date, equip_code, clock_hour)
    );
    CREATE INDEX IF NOT EXISTS idx_auto_ct_stats_equip ON auto_cycle_time_stats(equip_code, date);

    -- Individual cycle times (7-day retention for scatter plots)
    CREATE TABLE IF NOT EXISTS auto_cycle_times (
      id SERIAL PRIMARY KEY,
      date VARCHAR(10) NOT NULL,
      equip_code VARCHAR(50) NOT NULL,
      clock_hour INTEGER NOT NULL,
      ts TIMESTAMPTZ NOT NULL,
      cycle_seconds NUMERIC(8,2) NOT NULL,
      synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_auto_ct_equip_date ON auto_cycle_times(equip_code, date);
    CREATE INDEX IF NOT EXISTS idx_auto_ct_date ON auto_cycle_times(date);
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

      let manualSection = `MANUAL ENTRIES (${rows.length} records, ${dateFrom || 'all'} to ${dateTo || 'all'}, shift: ${shift || 'all'}):\n\nDAILY SUMMARY:\n${summary.join('\n')}\n\nLATEST DATE (${latestDate}) EQUIPMENT+OPERATOR BREAKDOWN:\n${equipLines.join('\n')}\n\nALL OPERATORS IN RANGE: ${[...allOperators].join(', ') || 'none'}`;

      // ── AUTO-EQUIPMENT DATA (MySQL-sourced, persisted to PG) ──
      let autoSection = '';
      try {
        const autoParams = [];
        let autoDateFilter = '';
        if (dateFrom) { autoParams.push(dateFrom); autoDateFilter += ` AND date >= $${autoParams.length}`; }
        if (dateTo) { autoParams.push(dateTo); autoDateFilter += ` AND date <= $${autoParams.length}`; }

        // Auto production totals by date + equipment
        const { rows: autoProd } = await pool.query(
          `SELECT date, equip_code, SUM(good_units) as total_parts, COUNT(*) as hour_count
           FROM auto_production_log WHERE 1=1 ${autoDateFilter}
           GROUP BY date, equip_code ORDER BY date DESC, equip_code`,
          autoParams
        );

        // Auto downtime totals by date + equipment
        const { rows: autoDT } = await pool.query(
          `SELECT d.date, d.equip_code, COUNT(*) as events, SUM(d.duration_mins) as total_mins,
                  COUNT(CASE WHEN c.dt_code IS NOT NULL THEN 1 END) as classified
           FROM auto_downtime_log d
           LEFT JOIN downtime_classifications c ON c.mysql_event_id = d.mysql_event_id
           WHERE 1=1 ${autoDateFilter.replace(/date/g, 'd.date')}
           GROUP BY d.date, d.equip_code ORDER BY d.date DESC`,
          autoParams
        );

        // Operator assignments
        const { rows: autoOps } = await pool.query(
          `SELECT shift_date, equip_code, operator_name
           FROM operator_assignments WHERE 1=1 ${autoDateFilter.replace(/date/g, 'shift_date')}
           ORDER BY shift_date DESC`,
          autoParams
        );

        // Cycle time stats (latest date only for brevity)
        const latestAutoDate = autoProd.length > 0 ? autoProd[0].date : null;
        let ctLines = [];
        if (latestAutoDate) {
          const { rows: ctStats } = await pool.query(
            `SELECT equip_code, clock_hour, avg_ct, min_ct, max_ct, stddev_ct, sample_count, ucl, lcl
             FROM auto_cycle_time_stats WHERE date = $1 ORDER BY equip_code, clock_hour`,
            [latestAutoDate]
          );
          // Summarize by equipment
          const ctByEquip = {};
          ctStats.forEach(r => {
            if (!ctByEquip[r.equip_code]) ctByEquip[r.equip_code] = { hours: 0, totalAvg: 0, minCT: Infinity, maxCT: 0, totalSamples: 0 };
            const e = ctByEquip[r.equip_code];
            e.hours++;
            e.totalAvg += parseFloat(r.avg_ct) * r.sample_count;
            e.totalSamples += r.sample_count;
            e.minCT = Math.min(e.minCT, parseFloat(r.min_ct));
            e.maxCT = Math.max(e.maxCT, parseFloat(r.max_ct));
          });
          ctLines = Object.entries(ctByEquip).map(([ec, e]) => {
            const wAvg = e.totalSamples > 0 ? (e.totalAvg / e.totalSamples).toFixed(1) : '?';
            return `  ${ec}: avg ${wAvg}s/part, min ${e.minCT.toFixed(1)}s, max ${e.maxCT.toFixed(1)}s, ${e.totalSamples} samples across ${e.hours} hours`;
          });
        }

        if (autoProd.length > 0) {
          // Summarize auto production by date
          const autoByDate = {};
          autoProd.forEach(r => {
            if (!autoByDate[r.date]) autoByDate[r.date] = { parts: 0, equip: new Set() };
            autoByDate[r.date].parts += parseInt(r.total_parts);
            autoByDate[r.date].equip.add(r.equip_code);
          });
          const autoDTByDate = {};
          autoDT.forEach(r => {
            if (!autoDTByDate[r.date]) autoDTByDate[r.date] = { events: 0, mins: 0, classified: 0 };
            autoDTByDate[r.date].events += parseInt(r.events);
            autoDTByDate[r.date].mins += parseInt(r.total_mins);
            autoDTByDate[r.date].classified += parseInt(r.classified);
          });
          const autoOpsByEquip = {};
          autoOps.forEach(r => {
            const key = r.equip_code;
            if (!autoOpsByEquip[key]) autoOpsByEquip[key] = new Set();
            autoOpsByEquip[key].add(r.operator_name);
          });

          const autoDates = Object.keys(autoByDate).sort().reverse();
          const autoSummary = autoDates.map(dt => {
            const p = autoByDate[dt];
            const d = autoDTByDate[dt] || { events: 0, mins: 0, classified: 0 };
            return `${dt}: ${p.parts} parts from ${p.equip.size} machines, ${d.events} DT events (${d.mins}min total, ${d.classified} classified)`;
          });

          // Per-equipment breakdown for latest auto date
          const latestAutoProd = autoProd.filter(r => r.date === latestAutoDate);
          const latestAutoDT = autoDT.filter(r => r.date === latestAutoDate);
          const autoEquipLines = latestAutoProd.map(r => {
            const dt = latestAutoDT.find(d => d.equip_code === r.equip_code);
            const ops = autoOpsByEquip[r.equip_code] ? [...autoOpsByEquip[r.equip_code]].join(', ') : 'none assigned';
            const eqName = EQUIP_NAMES[r.equip_code] || r.equip_code;
            return `  ${eqName} (${r.equip_code}): ${r.total_parts} parts, ${r.hour_count} active hours, ${dt ? dt.total_mins + 'min DT (' + dt.events + ' events)' : 'no DT'}, operators: ${ops}`;
          });

          autoSection = `\n\nAUTO-EQUIPMENT DATA (MySQL-sourced, ${autoProd.length} equip-date combos):\n\nDAILY SUMMARY:\n${autoSummary.join('\n')}\n\nLATEST DATE (${latestAutoDate}) AUTO EQUIPMENT BREAKDOWN:\n${autoEquipLines.join('\n')}`;
          if (ctLines.length > 0) {
            autoSection += `\n\nCYCLE TIME STATS (${latestAutoDate}):\n${ctLines.join('\n')}`;
          }
        }
      } catch (autoErr) {
        console.warn('Auto-equipment AI context error:', autoErr.message);
      }

      return manualSection + autoSection;
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

  // ═══════════════════════════════════════════════════════════════════════
  // MYSQL INTEGRATION — Automated production & downtime from JMWVL2
  // ═══════════════════════════════════════════════════════════════════════

  // ── MYSQL CONNECTION ──
  async function initMySQL(retryCount = 0) {
    const mysqlHost = process.env.MYSQL_HOST || '10.114.77.205';
    const mysqlUser = process.env.MYSQL_USER || 'powerBI';
    const mysqlPass = process.env.MYSQL_PASSWORD || 'ignitionData';
    const mysqlDb   = process.env.MYSQL_DATABASE || 'JMWVL2';
    try {
      const mysql = require('mysql2/promise');
      if (mysqlPool) { try { await mysqlPool.end(); } catch(e) {} }
      mysqlPool = await mysql.createPool({
        host: mysqlHost, user: mysqlUser, password: mysqlPass, database: mysqlDb,
        port: parseInt(process.env.MYSQL_PORT || '3306'),
        connectionLimit: 5, connectTimeout: 15000, waitForConnections: true
      });
      const [test] = await mysqlPool.query('SELECT 1');
      console.log('MySQL connected to ' + mysqlHost + ':' + (process.env.MYSQL_PORT || '3306') + '/' + mysqlDb);
      // Start background cache refresh
      refreshMySQLCache();
      setInterval(() => refreshMySQLCache(), MYSQL_CACHE_TTL);
    } catch (err) {
      console.warn('MySQL connection failed (attempt ' + (retryCount + 1) + '):', err.message);
      mysqlPool = null;
      // Retry every 60s up to 10 times, then every 5 min forever
      const delay = retryCount < 10 ? 60000 : 300000;
      console.log('Will retry MySQL connection in ' + (delay / 1000) + 's...');
      setTimeout(() => initMySQL(retryCount + 1), delay);
    }
  }

  // ── CACHE REFRESH — queries MySQL once per minute, serves all clients from cache ──
  async function refreshMySQLCache() {
    if (!mysqlPool || mysqlCache.refreshing) return;
    mysqlCache.refreshing = true;
    try {
      const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
      const today = now.toISOString().slice(0, 10);
      const yesterday = new Date(now.getTime() - 86400000).toISOString().slice(0, 10);

      // Get all MySQL production IDs
      const prodIds = Object.values(MYSQL_EQUIP_MAP).map(m => m.prodId);

      // Production: fetch today + yesterday (for 3rd shift overlap)
      const [prodRows] = await mysqlPool.query(
        'SELECT MachineID, ProductionDate, PartsProduced FROM ProductionRecording WHERE MachineID IN (?) AND ProductionDate >= ? ORDER BY MachineID, ProductionDate',
        [prodIds, yesterday + ' 00:00:00']
      );

      // Build hourly production per machine per date + raw timestamps for cycle time
      const prodByMachine = {};
      for (const row of prodRows) {
        const mid = row.MachineID;
        if (!prodByMachine[mid]) prodByMachine[mid] = [];
        prodByMachine[mid].push({ ts: new Date(row.ProductionDate), parts: row.PartsProduced });
      }

      // Aggregate into hourly buckets + minute buckets + raw timestamps
      const hourlyProduction = {};
      const rawTimestamps = {}; // {appCode: {date: [sorted timestamps]}}
      for (const [mid, records] of Object.entries(prodByMachine)) {
        const appCode = MYSQL_REVERSE_MAP[mid];
        if (!appCode) continue;
        hourlyProduction[appCode] = {};
        rawTimestamps[appCode] = {};

        // Group records by date
        const byDate = {};
        for (const r of records) {
          const d = r.ts.toISOString().slice(0, 10);
          if (!byDate[d]) byDate[d] = [];
          byDate[d].push(r);
        }

        for (const [date, dayRecords] of Object.entries(byDate)) {
          // Each record = one part produced at that timestamp
          const hourBuckets = {};
          for (const r of dayRecords) {
            const hour = r.ts.getHours();
            if (!hourBuckets[hour]) hourBuckets[hour] = 0;
            hourBuckets[hour]++;
          }
          const maxParts = dayRecords.length > 0 ? Math.max(...dayRecords.map(r => r.parts)) : 0;
          hourlyProduction[appCode][date] = { hourBuckets, totalParts: maxParts };

          // Store sorted raw timestamps for cycle time computation
          rawTimestamps[appCode][date] = dayRecords
            .map(r => r.ts)
            .sort((a, b) => a - b);
        }
      }

      // Downtime: fetch today + yesterday
      const [dtRows] = await mysqlPool.query(
        'SELECT DowntimeSeqNbr, MachineID, StartTime, EndTime, DowntimeCode, DowntimeDesc FROM DowntimeTracking WHERE MachineID IN (?) AND StartTime >= ? ORDER BY MachineID, StartTime',
        [prodIds, yesterday + ' 00:00:00']
      );

      // Map and filter downtime events
      const downtimeEvents = [];
      for (const row of dtRows) {
        const appCode = MYSQL_REVERSE_MAP[row.MachineID];
        if (!appCode) continue;
        const start = new Date(row.StartTime);
        const end = row.EndTime ? new Date(row.EndTime) : null;
        if (!end) continue; // Skip open-ended events (still in progress)
        const durationMins = Math.round((end - start) / 60000);
        const threshold = getDTThreshold(appCode);
        if (durationMins < threshold) continue; // Below threshold — normal cycle gap
        downtimeEvents.push({
          id: row.DowntimeSeqNbr,
          equipCode: appCode,
          date: start.toISOString().slice(0, 10),
          startTime: start.toISOString(),
          endTime: end.toISOString(),
          startHour: start.getHours(),
          durationMins,
          mysqlCode: row.DowntimeCode || null,
          mysqlDesc: row.DowntimeDesc || null,
          classified: false, dtCode: null, subItem: null
        });
      }

      // Fetch existing classifications from PostgreSQL
      if (downtimeEvents.length > 0) {
        const eventIds = downtimeEvents.map(e => e.id);
        const { rows: classifications } = await pool.query(
          'SELECT mysql_event_id, dt_code, sub_item, classified_by FROM downtime_classifications WHERE mysql_event_id = ANY($1)',
          [eventIds]
        );
        const classMap = {};
        for (const c of classifications) classMap[c.mysql_event_id] = c;
        for (const evt of downtimeEvents) {
          if (classMap[evt.id]) {
            evt.classified = true;
            evt.dtCode = classMap[evt.id].dt_code;
            evt.subItem = classMap[evt.id].sub_item || null;
            evt.classifiedBy = classMap[evt.id].classified_by || null;
          }
        }
      }

      mysqlCache.production = hourlyProduction;
      mysqlCache.downtime = downtimeEvents;
      mysqlCache.timestamps = rawTimestamps;
      mysqlCache.lastRefresh = Date.now();

      // ── Persist to PostgreSQL for historical access ──
      persistToPostgres(hourlyProduction, downtimeEvents).catch(e =>
        console.warn('PG persist warning:', e.message)
      );

      // ── Persist cycle time data to PostgreSQL ──
      persistCycleTimeData(rawTimestamps, downtimeEvents).catch(e =>
        console.warn('PG cycle time persist warning:', e.message)
      );

      // ── Cleanup old cycle time data (30-day retention) ──
      cleanupOldCycleData().catch(e =>
        console.warn('Cycle data cleanup warning:', e.message)
      );
    } catch (err) {
      console.error('MySQL cache refresh error:', err.message);
    } finally {
      mysqlCache.refreshing = false;
    }
  }

  // Persist MySQL data to PostgreSQL so historical queries don't need the tunnel
  async function persistToPostgres(hourlyProduction, downtimeEvents) {
    if (!pool) return;

    // Batch upsert production records (up to 50 per query for efficiency)
    const prodRows = [];
    for (const [appCode, dateData] of Object.entries(hourlyProduction)) {
      for (const [date, dayData] of Object.entries(dateData)) {
        for (const [hrStr, count] of Object.entries(dayData.hourBuckets)) {
          const clockHour = parseInt(hrStr);
          const { shiftNum, hourIdx } = getShiftForHour(date, clockHour);
          prodRows.push([date, shiftNum, appCode, hourIdx, clockHour, count]);
        }
      }
    }
    // Execute in batches
    for (let i = 0; i < prodRows.length; i += 50) {
      const batch = prodRows.slice(i, i + 50);
      const values = [];
      const placeholders = batch.map((row, idx) => {
        const base = idx * 6;
        values.push(...row);
        return `($${base+1}, $${base+2}, $${base+3}, $${base+4}, $${base+5}, $${base+6}, NOW())`;
      }).join(',');
      await pool.query(
        `INSERT INTO auto_production_log (date, shift_num, equip_code, hour_idx, clock_hour, good_units, synced_at)
         VALUES ${placeholders}
         ON CONFLICT (date, equip_code, clock_hour)
         DO UPDATE SET good_units = EXCLUDED.good_units, shift_num = EXCLUDED.shift_num, hour_idx = EXCLUDED.hour_idx, synced_at = NOW()`,
        values
      );
    }

    // Batch upsert downtime events
    for (let i = 0; i < downtimeEvents.length; i += 25) {
      const batch = downtimeEvents.slice(i, i + 25);
      const values = [];
      const placeholders = batch.map((evt, idx) => {
        const base = idx * 10;
        const { shiftNum, hourIdx } = getShiftForHour(evt.date, new Date(evt.startTime).getHours());
        values.push(evt.id, evt.equipCode, evt.date, shiftNum, hourIdx, evt.startTime, evt.endTime, evt.durationMins, evt.mysqlCode || null, evt.mysqlDesc || null);
        return `($${base+1}, $${base+2}, $${base+3}, $${base+4}, $${base+5}, $${base+6}, $${base+7}, $${base+8}, $${base+9}, $${base+10}, NOW())`;
      }).join(',');
      await pool.query(
        `INSERT INTO auto_downtime_log (mysql_event_id, equip_code, date, shift_num, hour_idx, start_time, end_time, duration_mins, mysql_code, mysql_desc, synced_at)
         VALUES ${placeholders}
         ON CONFLICT (mysql_event_id)
         DO UPDATE SET duration_mins = EXCLUDED.duration_mins, end_time = EXCLUDED.end_time, synced_at = NOW()`,
        values
      );
    }
    if (prodRows.length > 0 || downtimeEvents.length > 0) {
      console.log(`PG sync: ${prodRows.length} prod rows, ${downtimeEvents.length} DT events persisted`);
    }
  }

  // ── Compute cycle times from raw timestamps, filtering out downtime gaps ──
  function computeCycleTimes(timestamps, equipCode, downtimeEvents) {
    if (!timestamps || timestamps.length < 2) return [];
    const threshold = getDTThreshold(equipCode) * 60; // convert minutes to seconds
    const cycleTimes = [];
    for (let i = 1; i < timestamps.length; i++) {
      const gap = (timestamps[i] - timestamps[i - 1]) / 1000; // seconds
      if (gap <= 0) continue;
      if (gap > threshold) continue; // Skip downtime gaps
      cycleTimes.push({ ts: timestamps[i], seconds: gap });
    }
    return cycleTimes;
  }

  // ── Compute stats from an array of cycle time values ──
  function computeCTStats(cycleTimes) {
    if (!cycleTimes || cycleTimes.length === 0) return null;
    const vals = cycleTimes.map(c => c.seconds);
    const n = vals.length;
    const avg = vals.reduce((s, v) => s + v, 0) / n;
    const min = Math.min(...vals);
    const max = Math.max(...vals);
    const variance = vals.reduce((s, v) => s + (v - avg) ** 2, 0) / n;
    const stddev = Math.sqrt(variance);
    const ucl = avg + 3 * stddev;
    const lcl = Math.max(0, avg - 3 * stddev);
    return { avg, min, max, stddev, ucl, lcl, count: n };
  }

  // ── Persist per-minute counts and cycle time stats to PostgreSQL ──
  async function persistCycleTimeData(rawTimestamps, downtimeEvents) {
    if (!pool || !rawTimestamps) return;

    const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
    const todayStr = now.toISOString().slice(0, 10);
    const sevenDaysAgo = new Date(now.getTime() - 7 * 86400000).toISOString().slice(0, 10);

    for (const [appCode, dateData] of Object.entries(rawTimestamps)) {
      for (const [date, timestamps] of Object.entries(dateData)) {
        if (timestamps.length === 0) continue;

        // ── Per-minute counts ──
        const minuteBuckets = {};
        for (const ts of timestamps) {
          const h = ts.getHours();
          const m = ts.getMinutes();
          const key = h + ':' + m;
          if (!minuteBuckets[key]) minuteBuckets[key] = { hour: h, minute: m, count: 0 };
          minuteBuckets[key].count++;
        }

        // Batch upsert minute data
        const minRows = Object.values(minuteBuckets);
        for (let i = 0; i < minRows.length; i += 50) {
          const batch = minRows.slice(i, i + 50);
          const values = [];
          const placeholders = batch.map((row, idx) => {
            const base = idx * 5;
            values.push(date, appCode, row.hour, row.minute, row.count);
            return `($${base+1}, $${base+2}, $${base+3}, $${base+4}, $${base+5}, NOW())`;
          }).join(',');
          await pool.query(
            `INSERT INTO auto_production_minutes (date, equip_code, clock_hour, clock_minute, part_count, synced_at)
             VALUES ${placeholders}
             ON CONFLICT (date, equip_code, clock_hour, clock_minute)
             DO UPDATE SET part_count = EXCLUDED.part_count, synced_at = NOW()`,
            values
          );
        }

        // ── Cycle times per hour ──
        // Group timestamps by hour
        const byHour = {};
        for (const ts of timestamps) {
          const h = ts.getHours();
          if (!byHour[h]) byHour[h] = [];
          byHour[h].push(ts);
        }

        for (const [hrStr, hourTs] of Object.entries(byHour)) {
          const clockHour = parseInt(hrStr);
          hourTs.sort((a, b) => a - b);

          // Compute cycle times for this hour
          const cts = computeCycleTimes(hourTs, appCode, downtimeEvents);
          const stats = computeCTStats(cts);
          if (!stats) continue;

          // Upsert hourly stats
          await pool.query(
            `INSERT INTO auto_cycle_time_stats (date, equip_code, clock_hour, avg_ct, min_ct, max_ct, stddev_ct, sample_count, ucl, lcl, target_ct, synced_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, NOW())
             ON CONFLICT (date, equip_code, clock_hour)
             DO UPDATE SET avg_ct=EXCLUDED.avg_ct, min_ct=EXCLUDED.min_ct, max_ct=EXCLUDED.max_ct,
                           stddev_ct=EXCLUDED.stddev_ct, sample_count=EXCLUDED.sample_count,
                           ucl=EXCLUDED.ucl, lcl=EXCLUDED.lcl, synced_at=NOW()`,
            [date, appCode, clockHour, stats.avg.toFixed(2), stats.min.toFixed(2), stats.max.toFixed(2),
             stats.stddev.toFixed(2), stats.count, stats.ucl.toFixed(2), stats.lcl.toFixed(2)]
          );

          // Store individual cycle times for scatter plots (7-day retention)
          if (date >= sevenDaysAgo && cts.length > 0) {
            // Delete existing for this hour then re-insert (simpler than upsert for individual timestamps)
            await pool.query(
              'DELETE FROM auto_cycle_times WHERE date = $1 AND equip_code = $2 AND clock_hour = $3',
              [date, appCode, clockHour]
            );
            // Batch insert individual cycle times
            for (let i = 0; i < cts.length; i += 100) {
              const batch = cts.slice(i, i + 100);
              const values = [];
              const placeholders = batch.map((ct, idx) => {
                const base = idx * 5;
                values.push(date, appCode, clockHour, ct.ts.toISOString(), ct.seconds.toFixed(2));
                return `($${base+1}, $${base+2}, $${base+3}, $${base+4}::timestamptz, $${base+5}, NOW())`;
              }).join(',');
              await pool.query(
                `INSERT INTO auto_cycle_times (date, equip_code, clock_hour, ts, cycle_seconds, synced_at)
                 VALUES ${placeholders}`,
                values
              );
            }
          }
        }
      }
    }
  }

  // ── Cleanup old cycle time data (30-day retention for minutes/stats, 7-day for individual CTs) ──
  async function cleanupOldCycleData() {
    if (!pool) return;
    const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 86400000).toISOString().slice(0, 10);
    const sevenDaysAgo = new Date(now.getTime() - 7 * 86400000).toISOString().slice(0, 10);

    await pool.query('DELETE FROM auto_production_minutes WHERE date < $1', [thirtyDaysAgo]);
    await pool.query('DELETE FROM auto_cycle_time_stats WHERE date < $1', [thirtyDaysAgo]);
    await pool.query('DELETE FROM auto_cycle_times WHERE date < $1', [sevenDaysAgo]);
  }

  // Helper: convert clock hour (0-23) + date to shift info
  function getShiftForHour(date, clockHour) {
    // Shift 1: 5am-1pm (hours 5-12), Shift 2: 1pm-9pm (hours 13-20), Shift 3: 9pm-5am (hours 21-23,0-4)
    // Return shift number and hourIdx (1-based within shift)
    if (clockHour >= 5 && clockHour <= 12) return { shiftNum: '1', hourIdx: clockHour - 4 }; // 5am=hr1, 12pm=hr8
    if (clockHour >= 13 && clockHour <= 20) return { shiftNum: '2', hourIdx: clockHour - 12 }; // 1pm=hr1, 8pm=hr8
    // 3rd shift: 9pm(21)=hr1 through 4am(4)=hr8
    if (clockHour >= 21) return { shiftNum: '3', hourIdx: clockHour - 20 }; // 9pm=hr1, 11pm=hr3
    return { shiftNum: '3', hourIdx: clockHour + 4 }; // 12am=hr4, 4am=hr8
  }

  // ── API: MySQL status ──
  app.get('/api/mysql/status', async (req, res) => {
    const status = {
      connected: !!mysqlPool,
      cacheAge: mysqlCache.lastRefresh ? Date.now() - mysqlCache.lastRefresh : null,
      equipCount: Object.keys(MYSQL_EQUIP_MAP).length,
      cachedProductionDates: mysqlCache.production ? Object.keys(Object.values(mysqlCache.production)[0] || {}) : [],
      cachedDowntimeEvents: mysqlCache.downtime ? mysqlCache.downtime.length : 0,
      config: { host: process.env.MYSQL_HOST || '10.114.77.205', port: process.env.MYSQL_PORT || '3306', database: process.env.MYSQL_DATABASE || 'JMWVL2' }
    };
    // Live connection test if requested
    if (req.query.test === '1') {
      try {
        const mysql = require('mysql2/promise');
        const testConn = await mysql.createConnection({
          host: process.env.MYSQL_HOST || '10.114.77.205',
          port: parseInt(process.env.MYSQL_PORT || '3306'),
          user: process.env.MYSQL_USER || 'powerBI',
          password: process.env.MYSQL_PASSWORD || 'ignitionData',
          database: process.env.MYSQL_DATABASE || 'JMWVL2',
          connectTimeout: 10000
        });
        const [rows] = await testConn.query('SELECT COUNT(*) as cnt FROM ProductionRecording WHERE DATE(ProductionDate) = CURDATE()');
        status.liveTest = { success: true, todayRecords: rows[0].cnt };
        await testConn.end();
        // If pool was null but test succeeded, reinitialize
        if (!mysqlPool) { initMySQL(0); }
      } catch (e) {
        status.liveTest = { success: false, error: e.message, code: e.code || null };
      }
    }
    res.json(status);
  });

  // ── API: Hourly production from MySQL ──
  app.get('/api/mysql/production', (req, res) => {
    if (!mysqlPool) return res.status(503).json({ error: 'MySQL not connected' });
    const date = req.query.date;
    if (!date) return res.status(400).json({ error: 'date parameter required' });

    const result = {};
    const prod = mysqlCache.production || {};
    for (const [appCode, dateData] of Object.entries(prod)) {
      const dayData = dateData[date];
      if (!dayData) continue;
      const hours = [];
      for (const [hr, count] of Object.entries(dayData.hourBuckets)) {
        const clockHour = parseInt(hr);
        const { shiftNum, hourIdx } = getShiftForHour(date, clockHour);
        hours.push({ clockHour, shiftNum, hourIdx, goodUnits: count });
      }
      result[appCode] = { hours, totalParts: dayData.totalParts };
    }
    res.json({ date, equipment: result, cacheAge: Date.now() - mysqlCache.lastRefresh });
  });

  // ── API: Downtime events from MySQL ──
  app.get('/api/mysql/downtime', (req, res) => {
    if (!mysqlPool) return res.status(503).json({ error: 'MySQL not connected' });
    const date = req.query.date;
    if (!date) return res.status(400).json({ error: 'date parameter required' });

    const events = (mysqlCache.downtime || []).filter(e => e.date === date);
    // Add shift info to each event
    const enriched = events.map(e => {
      const startDt = new Date(e.startTime);
      const { shiftNum, hourIdx } = getShiftForHour(e.date, startDt.getHours());
      return { ...e, shiftNum, hourIdx };
    });
    const unclassified = enriched.filter(e => !e.classified).length;
    res.json({ date, events: enriched, total: enriched.length, unclassified, cacheAge: Date.now() - mysqlCache.lastRefresh });
  });

  // ── API: Classify a downtime event ──
  app.post('/api/mysql/classify-downtime', async (req, res) => {
    try {
      const { mysqlEventId, equipCode, dtCode, subItem, classifiedBy } = req.body;
      if (!mysqlEventId || !equipCode || dtCode === undefined) {
        return res.status(400).json({ error: 'mysqlEventId, equipCode, and dtCode required' });
      }
      const date = req.body.shiftDate || new Date().toISOString().slice(0, 10);
      await pool.query(
        `INSERT INTO downtime_classifications (mysql_event_id, equip_code, shift_date, dt_code, sub_item, classified_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (mysql_event_id) DO UPDATE SET dt_code=$4, sub_item=$5, classified_by=$6, classified_at=NOW()`,
        [mysqlEventId, equipCode, date, dtCode, subItem || null, classifiedBy || null]
      );
      // Update cache immediately
      if (mysqlCache.downtime) {
        const evt = mysqlCache.downtime.find(e => e.id === mysqlEventId);
        if (evt) { evt.classified = true; evt.dtCode = dtCode; evt.subItem = subItem || null; }
      }
      res.json({ ok: true });
    } catch (err) {
      console.error('Classify downtime error:', err);
      res.status(500).json({ error: 'Failed to classify' });
    }
  });

  // ── API: Batch classify downtime events ──
  app.post('/api/mysql/classify-downtime/batch', async (req, res) => {
    try {
      const { events } = req.body;
      if (!Array.isArray(events) || events.length === 0) {
        return res.status(400).json({ error: 'events array required' });
      }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        for (const evt of events) {
          await client.query(
            `INSERT INTO downtime_classifications (mysql_event_id, equip_code, shift_date, dt_code, sub_item, classified_by)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (mysql_event_id) DO UPDATE SET dt_code=$4, sub_item=$5, classified_by=$6, classified_at=NOW()`,
            [evt.mysqlEventId, evt.equipCode, evt.shiftDate || new Date().toISOString().slice(0, 10), evt.dtCode, evt.subItem || null, evt.classifiedBy || null]
          );
        }
        await client.query('COMMIT');
        // Update cache
        if (mysqlCache.downtime) {
          for (const evt of events) {
            const cached = mysqlCache.downtime.find(e => e.id === evt.mysqlEventId);
            if (cached) { cached.classified = true; cached.dtCode = evt.dtCode; cached.subItem = evt.subItem || null; }
          }
        }
        res.json({ ok: true, classified: events.length });
      } finally { client.release(); }
    } catch (err) {
      console.error('Batch classify error:', err);
      res.status(500).json({ error: 'Batch classification failed' });
    }
  });

  // ── API: Quick-report defect for automated equipment ──
  app.post('/api/mysql/report-defect', async (req, res) => {
    try {
      const { equipCode, shiftDate, shiftNum, defCode, quantity, hourIdx, reportedBy, notes } = req.body;
      if (!equipCode || !shiftDate || !shiftNum || defCode === undefined || !quantity) {
        return res.status(400).json({ error: 'equipCode, shiftDate, shiftNum, defCode, quantity required' });
      }
      const { rows } = await pool.query(
        `INSERT INTO auto_defect_reports (equip_code, shift_date, shift_num, def_code, quantity, hour_idx, reported_by, notes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
        [equipCode, shiftDate, shiftNum, defCode, quantity, hourIdx || null, reportedBy || null, notes || null]
      );
      res.json({ ok: true, id: rows[0].id });
    } catch (err) {
      console.error('Report defect error:', err);
      res.status(500).json({ error: 'Failed to report defect' });
    }
  });

  // ── API: Get defect reports for a shift ──
  app.get('/api/mysql/defects', async (req, res) => {
    try {
      const { date, shift } = req.query;
      if (!date) return res.status(400).json({ error: 'date parameter required' });
      let q = 'SELECT * FROM auto_defect_reports WHERE shift_date = $1';
      const params = [date];
      if (shift) { q += ' AND shift_num = $2'; params.push(shift); }
      q += ' ORDER BY reported_at DESC';
      const { rows } = await pool.query(q, params);
      res.json({ defects: rows });
    } catch (err) {
      console.error('Get defects error:', err);
      res.status(500).json({ error: 'Failed to get defects' });
    }
  });

  // ── API: Operator assignments ──
  app.post('/api/mysql/operator-assign', async (req, res) => {
    try {
      const { shiftDate, shiftNum, equipCode, operatorName, startHour, endHour, assignedBy } = req.body;
      if (!shiftDate || !shiftNum || !equipCode || !operatorName) {
        return res.status(400).json({ error: 'shiftDate, shiftNum, equipCode, operatorName required' });
      }
      await pool.query(
        `INSERT INTO operator_assignments (shift_date, shift_num, equip_code, operator_name, start_hour, end_hour, assigned_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (shift_date, shift_num, equip_code, operator_name)
         DO UPDATE SET start_hour=$5, end_hour=$6, assigned_by=$7, assigned_at=NOW()`,
        [shiftDate, shiftNum, equipCode, operatorName, startHour || 1, endHour || null, assignedBy || null]
      );
      res.json({ ok: true });
    } catch (err) {
      console.error('Operator assign error:', err);
      res.status(500).json({ error: 'Failed to assign operator' });
    }
  });

  // ── API: Get operator assignments for a shift ──
  app.get('/api/mysql/operators', async (req, res) => {
    try {
      const { date, shift } = req.query;
      if (!date) return res.status(400).json({ error: 'date parameter required' });
      let q = 'SELECT * FROM operator_assignments WHERE shift_date = $1';
      const params = [date];
      if (shift) { q += ' AND shift_num = $2'; params.push(shift); }
      q += ' ORDER BY equip_code, operator_name';
      const { rows } = await pool.query(q, params);
      res.json({ assignments: rows });
    } catch (err) {
      console.error('Get operators error:', err);
      res.status(500).json({ error: 'Failed to get operators' });
    }
  });

  // ── API: Move operator between equipment ──
  app.post('/api/mysql/operator-move', async (req, res) => {
    try {
      const { shiftDate, shiftNum, operatorName, fromEquip, toEquip, atHour, movedBy } = req.body;
      if (!shiftDate || !shiftNum || !operatorName || !fromEquip || !toEquip || !atHour) {
        return res.status(400).json({ error: 'All fields required' });
      }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        // End the old assignment at the move hour
        await client.query(
          `UPDATE operator_assignments SET end_hour = $1
           WHERE shift_date = $2 AND shift_num = $3 AND equip_code = $4 AND operator_name = $5 AND end_hour IS NULL`,
          [atHour - 1, shiftDate, shiftNum, fromEquip, operatorName]
        );
        // Create new assignment on the target equipment
        await client.query(
          `INSERT INTO operator_assignments (shift_date, shift_num, equip_code, operator_name, start_hour, assigned_by)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (shift_date, shift_num, equip_code, operator_name)
           DO UPDATE SET start_hour = $5, end_hour = NULL, assigned_by = $6, assigned_at = NOW()`,
          [shiftDate, shiftNum, toEquip, operatorName, atHour, movedBy || null]
        );
        await client.query('COMMIT');
        res.json({ ok: true });
      } finally { client.release(); }
    } catch (err) {
      console.error('Operator move error:', err);
      res.status(500).json({ error: 'Failed to move operator' });
    }
  });

  // ── API: Merged records (combined production + downtime + classifications) ──
  // Supports: ?date=2026-03-20 (single day) or ?from=2026-03-01&to=2026-03-20 (range)
  // For today/yesterday: uses live MySQL cache. For older dates: queries PostgreSQL history.
  app.get('/api/mysql/merged', async (req, res) => {
    try {
      const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
      const todayStr = now.toISOString().slice(0, 10);
      const yesterdayStr = new Date(now.getTime() - 86400000).toISOString().slice(0, 10);

      // Determine date range
      let dateFrom, dateTo;
      if (req.query.from && req.query.to) {
        dateFrom = req.query.from;
        dateTo = req.query.to;
      } else if (req.query.date) {
        dateFrom = req.query.date;
        dateTo = req.query.date;
      } else {
        return res.status(400).json({ error: 'date or from+to parameters required' });
      }

      const allRecords = [];
      let totalEvents = 0, totalUnclassified = 0;

      // Split dates into "live" (today/yesterday from cache) and "historical" (from PG)
      const liveDates = [];
      const histDates = [];

      // Generate date list
      const dateList = [];
      for (let d = new Date(dateFrom + 'T12:00:00Z'); d <= new Date(dateTo + 'T12:00:00Z'); d.setDate(d.getDate() + 1)) {
        dateList.push(d.toISOString().slice(0, 10));
      }

      for (const date of dateList) {
        if ((date === todayStr || date === yesterdayStr) && mysqlPool && mysqlCache.production) {
          liveDates.push(date);
        } else {
          histDates.push(date);
        }
      }

      // ── LIVE DATES: Build from MySQL cache ──
      for (const date of liveDates) {
        const prod = mysqlCache.production || {};
        const dtEvents = (mysqlCache.downtime || []).filter(e => e.date === date);

        const { rows: assignments } = await pool.query(
          'SELECT * FROM operator_assignments WHERE shift_date = $1', [date]
        );
        const { rows: defects } = await pool.query(
          'SELECT * FROM auto_defect_reports WHERE shift_date = $1', [date]
        );

        for (const [appCode, dateData] of Object.entries(prod)) {
          const dayData = dateData[date];
          if (!dayData) continue;

          for (const [hrStr, count] of Object.entries(dayData.hourBuckets)) {
            const clockHour = parseInt(hrStr);
            if (count === 0) continue;
            const { shiftNum, hourIdx } = getShiftForHour(date, clockHour);

            const hourDT = dtEvents.filter(e => e.equipCode === appCode && e.startHour === clockHour);
            const dtArray = hourDT.map(e => ({
              id: 'mysql-' + e.id, mysqlEventId: e.id, mins: String(e.durationMins),
              dtCode: e.dtCode !== null ? String(e.dtCode) : '', subItem: e.subItem || '',
              startTime: e.startTime, endTime: e.endTime, classified: e.classified, autoDetected: true
            }));

            const shiftOps = assignments.filter(a =>
              a.equip_code === appCode && a.shift_num === shiftNum &&
              a.start_hour <= hourIdx && (a.end_hour === null || a.end_hour >= hourIdx)
            ).map(a => a.operator_name);

            const hourDefs = defects.filter(d =>
              d.equip_code === appCode && d.shift_num === shiftNum &&
              (d.hour_idx === hourIdx || d.hour_idx === null)
            ).map(d => ({ id: 'autodef-' + d.id, qty: String(d.quantity), defCode: String(d.def_code) }));

            const totalDTMins = dtArray.reduce((s, d) => s + parseInt(d.mins || 0), 0);
            allRecords.push({
              date, shiftNum, equipCode: appCode, hourIdx, clockHour,
              productCode: '', scheduledMins: 0, target: 0,
              goodUnits: count, downtime: dtArray, defects: hourDefs,
              operators: shiftOps, autoData: true, totalDTMins
            });
          }
        }
        totalEvents += dtEvents.length;
        totalUnclassified += dtEvents.filter(e => !e.classified).length;
      }

      // ── HISTORICAL DATES: Query PostgreSQL ──
      if (histDates.length > 0) {
        const hFrom = histDates[0], hTo = histDates[histDates.length - 1];

        // Production from PG
        const { rows: prodRows } = await pool.query(
          'SELECT date, shift_num, equip_code, hour_idx, clock_hour, good_units FROM auto_production_log WHERE date >= $1 AND date <= $2 ORDER BY date, equip_code, clock_hour',
          [hFrom, hTo]
        );

        // Downtime from PG (joined with classifications)
        const { rows: dtRows } = await pool.query(
          `SELECT d.mysql_event_id, d.equip_code, d.date, d.shift_num, d.hour_idx,
                  d.start_time, d.end_time, d.duration_mins, d.mysql_code, d.mysql_desc,
                  c.dt_code, c.sub_item, c.classified_by
           FROM auto_downtime_log d
           LEFT JOIN downtime_classifications c ON c.mysql_event_id = d.mysql_event_id
           WHERE d.date >= $1 AND d.date <= $2
           ORDER BY d.date, d.equip_code, d.start_time`,
          [hFrom, hTo]
        );

        // Operator assignments
        const { rows: assignments } = await pool.query(
          'SELECT * FROM operator_assignments WHERE shift_date >= $1 AND shift_date <= $2', [hFrom, hTo]
        );

        // Defect reports
        const { rows: defects } = await pool.query(
          'SELECT * FROM auto_defect_reports WHERE shift_date >= $1 AND shift_date <= $2', [hFrom, hTo]
        );

        // Build records from PG data
        for (const row of prodRows) {
          const { date, shift_num: shiftNum, equip_code: equipCode, hour_idx: hourIdx, clock_hour: clockHour, good_units: goodUnits } = row;

          // Downtime for this hour
          const hourDT = dtRows.filter(d => d.equip_code === equipCode && d.date === date && d.hour_idx === hourIdx);
          const dtArray = hourDT.map(d => ({
            id: 'mysql-' + d.mysql_event_id, mysqlEventId: d.mysql_event_id,
            mins: String(d.duration_mins),
            dtCode: d.dt_code !== null && d.dt_code !== undefined ? String(d.dt_code) : '',
            subItem: d.sub_item || '',
            startTime: d.start_time, endTime: d.end_time,
            classified: d.dt_code !== null && d.dt_code !== undefined,
            autoDetected: true
          }));

          // Operators
          const shiftOps = assignments.filter(a =>
            a.equip_code === equipCode && a.shift_date === date && a.shift_num === shiftNum &&
            a.start_hour <= hourIdx && (a.end_hour === null || a.end_hour >= hourIdx)
          ).map(a => a.operator_name);

          // Defects
          const hourDefs = defects.filter(d =>
            d.equip_code === equipCode && d.shift_date === date && d.shift_num === shiftNum &&
            (d.hour_idx === hourIdx || d.hour_idx === null)
          ).map(d => ({ id: 'autodef-' + d.id, qty: String(d.quantity), defCode: String(d.def_code) }));

          const totalDTMins = dtArray.reduce((s, d) => s + parseInt(d.mins || 0), 0);
          allRecords.push({
            date, shiftNum, equipCode, hourIdx, clockHour,
            productCode: '', scheduledMins: 0, target: 0,
            goodUnits, downtime: dtArray, defects: hourDefs,
            operators: shiftOps, autoData: true, totalDTMins
          });
        }
        // Count historical DT events
        const histDTCount = dtRows.length;
        const histUnclassified = dtRows.filter(d => d.dt_code === null || d.dt_code === undefined).length;
        totalEvents += histDTCount;
        totalUnclassified += histUnclassified;
      }

      res.json({ dateFrom, dateTo, records: allRecords, eventCount: totalEvents, unclassified: totalUnclassified });
    } catch (err) {
      console.error('Merged records error:', err);
      res.status(500).json({ error: 'Failed to build merged records' });
    }
  });

  // ── API: Cycle time data (individual cycle times + hourly stats) ──
  // ?equip=WV-SHEAR-AS1&date=2026-03-20 → hourly stats for entire day
  // ?equip=WV-SHEAR-AS1&date=2026-03-20&hour=8 → individual cycle times for that hour
  app.get('/api/mysql/cycle-data', async (req, res) => {
    try {
      const { equip, date, hour } = req.query;
      if (!equip || !date) return res.status(400).json({ error: 'equip and date required' });

      const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
      const todayStr = now.toISOString().slice(0, 10);
      const yesterdayStr = new Date(now.getTime() - 86400000).toISOString().slice(0, 10);
      const isLive = (date === todayStr || date === yesterdayStr) && mysqlCache.timestamps;

      if (hour !== undefined) {
        // ── Individual cycle times for a specific hour ──
        const clockHour = parseInt(hour);

        if (isLive && mysqlCache.timestamps[equip] && mysqlCache.timestamps[equip][date]) {
          // Compute from live raw timestamps
          const allTs = mysqlCache.timestamps[equip][date];
          const hourTs = allTs.filter(ts => ts.getHours() === clockHour);
          hourTs.sort((a, b) => a - b);
          const cts = computeCycleTimes(hourTs, equip, mysqlCache.downtime || []);
          const stats = computeCTStats(cts);
          return res.json({
            equip, date, clockHour, live: true,
            cycleTimes: cts.map(c => ({ ts: c.ts.toISOString(), seconds: parseFloat(c.seconds.toFixed(2)) })),
            stats: stats || { avg: 0, min: 0, max: 0, stddev: 0, ucl: 0, lcl: 0, count: 0 }
          });
        }

        // Fall back to PG (individual cycle times if within 7 days, otherwise just stats)
        const { rows: ctRows } = await pool.query(
          'SELECT ts, cycle_seconds FROM auto_cycle_times WHERE equip_code = $1 AND date = $2 AND clock_hour = $3 ORDER BY ts',
          [equip, date, clockHour]
        );
        const { rows: statsRows } = await pool.query(
          'SELECT * FROM auto_cycle_time_stats WHERE equip_code = $1 AND date = $2 AND clock_hour = $3',
          [equip, date, clockHour]
        );
        const pgStats = statsRows[0] || null;
        return res.json({
          equip, date, clockHour, live: false,
          cycleTimes: ctRows.map(r => ({ ts: r.ts, seconds: parseFloat(r.cycle_seconds) })),
          stats: pgStats ? {
            avg: parseFloat(pgStats.avg_ct), min: parseFloat(pgStats.min_ct),
            max: parseFloat(pgStats.max_ct), stddev: parseFloat(pgStats.stddev_ct),
            ucl: parseFloat(pgStats.ucl), lcl: parseFloat(pgStats.lcl), count: pgStats.sample_count
          } : { avg: 0, min: 0, max: 0, stddev: 0, ucl: 0, lcl: 0, count: 0 }
        });
      }

      // ── Hourly stats for the entire day ──
      if (isLive && mysqlCache.timestamps[equip] && mysqlCache.timestamps[equip][date]) {
        // Compute from live raw timestamps
        const allTs = mysqlCache.timestamps[equip][date];
        const byHour = {};
        for (const ts of allTs) {
          const h = ts.getHours();
          if (!byHour[h]) byHour[h] = [];
          byHour[h].push(ts);
        }
        const hourlyStats = [];
        for (const [hStr, hourTs] of Object.entries(byHour)) {
          hourTs.sort((a, b) => a - b);
          const cts = computeCycleTimes(hourTs, equip, mysqlCache.downtime || []);
          const stats = computeCTStats(cts);
          if (stats) {
            const { shiftNum, hourIdx } = getShiftForHour(date, parseInt(hStr));
            hourlyStats.push({
              clockHour: parseInt(hStr), shiftNum, hourIdx,
              avg: parseFloat(stats.avg.toFixed(2)), min: parseFloat(stats.min.toFixed(2)),
              max: parseFloat(stats.max.toFixed(2)), stddev: parseFloat(stats.stddev.toFixed(2)),
              ucl: parseFloat(stats.ucl.toFixed(2)), lcl: parseFloat(stats.lcl.toFixed(2)),
              count: stats.count
            });
          }
        }
        return res.json({ equip, date, live: true, hourlyStats });
      }

      // Fall back to PG
      const { rows } = await pool.query(
        'SELECT * FROM auto_cycle_time_stats WHERE equip_code = $1 AND date = $2 ORDER BY clock_hour',
        [equip, date]
      );
      const hourlyStats = rows.map(r => {
        const { shiftNum, hourIdx } = getShiftForHour(date, r.clock_hour);
        return {
          clockHour: r.clock_hour, shiftNum, hourIdx,
          avg: parseFloat(r.avg_ct), min: parseFloat(r.min_ct),
          max: parseFloat(r.max_ct), stddev: parseFloat(r.stddev_ct),
          ucl: parseFloat(r.ucl), lcl: parseFloat(r.lcl), count: r.sample_count
        };
      });
      res.json({ equip, date, live: false, hourlyStats });
    } catch (err) {
      console.error('Cycle data error:', err);
      res.status(500).json({ error: 'Failed to get cycle data' });
    }
  });

  // ── API: Per-minute production data ──
  // ?equip=WV-SHEAR-AS1&date=2026-03-20&hour=8 → per-minute counts for that hour
  app.get('/api/mysql/minute-data', async (req, res) => {
    try {
      const { equip, date, hour } = req.query;
      if (!equip || !date) return res.status(400).json({ error: 'equip and date required' });

      const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
      const todayStr = now.toISOString().slice(0, 10);
      const yesterdayStr = new Date(now.getTime() - 86400000).toISOString().slice(0, 10);
      const isLive = (date === todayStr || date === yesterdayStr) && mysqlCache.timestamps;

      if (isLive && mysqlCache.timestamps[equip] && mysqlCache.timestamps[equip][date]) {
        const allTs = mysqlCache.timestamps[equip][date];
        let filtered = allTs;
        if (hour !== undefined) {
          const clockHour = parseInt(hour);
          filtered = allTs.filter(ts => ts.getHours() === clockHour);
        }
        // Build minute-level counts
        const minuteCounts = {};
        for (const ts of filtered) {
          const key = ts.getHours() + ':' + String(ts.getMinutes()).padStart(2, '0');
          if (!minuteCounts[key]) minuteCounts[key] = { hour: ts.getHours(), minute: ts.getMinutes(), count: 0 };
          minuteCounts[key].count++;
        }
        return res.json({
          equip, date, live: true,
          minutes: Object.values(minuteCounts).sort((a, b) => a.hour * 60 + a.minute - (b.hour * 60 + b.minute))
        });
      }

      // Fall back to PG
      let q = 'SELECT clock_hour, clock_minute, part_count FROM auto_production_minutes WHERE equip_code = $1 AND date = $2';
      const params = [equip, date];
      if (hour !== undefined) { q += ' AND clock_hour = $3'; params.push(parseInt(hour)); }
      q += ' ORDER BY clock_hour, clock_minute';
      const { rows } = await pool.query(q, params);
      res.json({
        equip, date, live: false,
        minutes: rows.map(r => ({ hour: r.clock_hour, minute: r.clock_minute, count: r.part_count }))
      });
    } catch (err) {
      console.error('Minute data error:', err);
      res.status(500).json({ error: 'Failed to get minute data' });
    }
  });

  // ── API: Live status of all auto equipment (for TV Display 30s refresh) ──
  app.get('/api/mysql/live-status', async (req, res) => {
    try {
      const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
      const todayStr = now.toISOString().slice(0, 10);
      const currentHour = now.getHours();
      const currentMinute = now.getMinutes();
      const { shiftNum } = getShiftForHour(todayStr, currentHour);

      const equipStatus = {};
      const prod = mysqlCache.production || {};
      const timestamps = mysqlCache.timestamps || {};
      const dtEvents = (mysqlCache.downtime || []).filter(e => e.date === todayStr);

      for (const [appCode, ids] of Object.entries(MYSQL_EQUIP_MAP)) {
        const dayData = prod[appCode] && prod[appCode][todayStr];
        const equipTs = timestamps[appCode] && timestamps[appCode][todayStr];

        // Current hour output
        const currentHourOutput = dayData ? (dayData.hourBuckets[currentHour] || 0) : 0;

        // Shift total output (sum hours in current shift)
        let shiftTotal = 0;
        if (dayData) {
          for (const [hrStr, count] of Object.entries(dayData.hourBuckets)) {
            const h = parseInt(hrStr);
            const si = getShiftForHour(todayStr, h);
            if (si.shiftNum === shiftNum) shiftTotal += count;
          }
        }

        // Live cycle time (from last few parts of current hour)
        let liveCT = null;
        if (equipTs) {
          const currentHourTs = equipTs.filter(ts => ts.getHours() === currentHour);
          if (currentHourTs.length >= 2) {
            currentHourTs.sort((a, b) => a - b);
            // Get last few cycle times
            const recentCTs = [];
            const threshold = getDTThreshold(appCode) * 60;
            for (let i = currentHourTs.length - 1; i > 0 && recentCTs.length < 5; i--) {
              const gap = (currentHourTs[i] - currentHourTs[i - 1]) / 1000;
              if (gap > 0 && gap <= threshold) recentCTs.push(gap);
            }
            if (recentCTs.length > 0) {
              liveCT = parseFloat((recentCTs.reduce((s, v) => s + v, 0) / recentCTs.length).toFixed(1));
            }
          }
        }

        // Last part timestamp
        let lastPartAt = null;
        if (equipTs && equipTs.length > 0) {
          lastPartAt = equipTs[equipTs.length - 1].toISOString();
        }

        // Active downtime (currently in progress — endTime is null or > now)
        const activeDowntime = dtEvents.find(e =>
          e.equipCode === appCode && !e.endTime
        );
        // Check if last part was long ago (machine may be down)
        let idleSince = null;
        if (equipTs && equipTs.length > 0) {
          const lastTs = equipTs[equipTs.length - 1];
          const idleSeconds = (now - lastTs) / 1000;
          const threshold = getDTThreshold(appCode) * 60;
          if (idleSeconds > threshold) idleSince = lastTs.toISOString();
        }

        equipStatus[appCode] = {
          currentHourOutput, shiftTotal, liveCycleTime: liveCT,
          lastPartAt, activeDowntime: activeDowntime ? {
            id: activeDowntime.id, startTime: activeDowntime.startTime,
            durationMins: activeDowntime.durationMins, mysqlDesc: activeDowntime.mysqlDesc
          } : null,
          idleSince,
          shiftNum
        };
      }

      res.json({
        timestamp: now.toISOString(),
        currentHour, currentMinute, shiftNum,
        cacheAge: Date.now() - mysqlCache.lastRefresh,
        connected: !!mysqlPool,
        equipment: equipStatus
      });
    } catch (err) {
      console.error('Live status error:', err);
      res.status(500).json({ error: 'Failed to get live status' });
    }
  });

  // Initialize MySQL connection (non-blocking)
  initMySQL();

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
