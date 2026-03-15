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

  // ══════════════════════════════════════════
  // ── DAILY EMAIL REPORT ──
  // ══════════════════════════════════════════
  const DT_CODES={1:'Tooling',2:'Hydraulic Issues',3:'Air Issues',4:'Water Issues',5:'Electrical Issues',6:'Sensor Issues',7:'Encoder Issues',8:'Mechanical Issues',9:'Lubrication Issues',10:'Changeover',11:'Loading Material',12:'Unloading Material',13:'Material Issues',14:'QC',15:'Assisting Operator',16:'Scheduled Downtime',17:'Programming Issues',18:'Vibration Issues',19:'Robot Issues',20:'Welder Issues',21:'Vision Issues'};
  const DEF_CODES={1:'Bent Bar',2:'Burr',3:'Bad Ribs',4:'Failing Bar Length',5:'Failing Peel Length',6:'Failing Diameter',7:'Cross Thread',8:'Incomplete Starter Thread',9:'Cracked Threads',10:'Failing Thread Length',11:'Failing Stamp',12:'Head Off-Center',13:'Failing Washer',14:'Failing Tensile',15:'Failing Yield',16:'Bad Break',17:'Rounded Head',18:'Improper Assembly',19:'Failing Width',20:'Failing Length',21:'Cracked Steel',22:'Bend Cable',23:'Broken Strand',24:'Broken Housing',25:'Failing Cable Length',26:'Failing Bird Cage',27:'Failing Crimp',28:'Failing Teeth Depth',29:'Failing Weld',30:'Hole Alignment',31:'Missing Component'};

  function computeDailyReport(dateStr, submissions) {
    const shifts = { '1': [], '2': [] };
    submissions.forEach(sub => {
      const d = sub.data || sub;
      const sd = d.shiftData || {};
      const ed = d.equipData || {};
      const shiftNum = sd.shiftNum || '1';
      if (!shifts[shiftNum]) shifts[shiftNum] = [];
      Object.entries(ed).forEach(([equip, hours]) => {
        (hours || []).forEach(hr => {
          if (hr && hr.productCode) shifts[shiftNum].push({ ...hr, equipCode: equip });
        });
      });
    });

    function calcShift(records) {
      let totalTarget = 0, totalGood = 0, totalProduced = 0, totalScheduled = 0, totalDT = 0;
      const dtMap = {}, defMap = {};
      records.forEach(r => {
        const target = parseInt(r.target || 0);
        const good = parseInt(r.goodUnits || 0);
        const sched = parseInt(r.scheduledMins || 0);
        const dtMins = (r.downtime || []).reduce((s, d) => s + parseInt(d.mins || 0), 0);
        const defQty = (r.defects || []).reduce((s, d) => s + parseInt(d.qty || 0), 0);
        totalTarget += target;
        totalGood += good;
        totalProduced += good + defQty;
        totalScheduled += sched;
        totalDT += dtMins;
        (r.downtime || []).forEach(d => {
          const nm = DT_CODES[d.dtCode] || ('Code ' + d.dtCode);
          if (!dtMap[nm]) dtMap[nm] = 0;
          dtMap[nm] += parseInt(d.mins || 0);
        });
        (r.defects || []).forEach(d => {
          const nm = DEF_CODES[d.defCode] || ('Code ' + d.defCode);
          if (!defMap[nm]) defMap[nm] = 0;
          defMap[nm] += parseInt(d.qty || 0);
        });
      });
      const avail = totalScheduled > 0 ? (totalScheduled - totalDT) / totalScheduled : 0;
      const perf = (totalTarget > 0 && (totalScheduled - totalDT) > 0) ? totalProduced / totalTarget : 0;
      const qual = totalProduced > 0 ? totalGood / totalProduced : (totalTarget > 0 ? 0 : 1);
      const oee = avail * perf * qual;
      const topDT = Object.entries(dtMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
      const topDef = Object.entries(defMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
      const totalDefects = Object.values(defMap).reduce((s, v) => s + v, 0);
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
    parts.push(`<text x="${W/2}" y="40" text-anchor="middle" fill="#fff" font-size="26" font-weight="800" font-family="system-ui,sans-serif">JMOS Dashboard</text>`);
    parts.push(`<text x="${W/2}" y="60" text-anchor="middle" fill="rgba(255,255,255,0.55)" font-size="12" font-family="system-ui,sans-serif">West Virginia Bolt Plant</text>`);
    parts.push(`<rect x="${W/2-20}" y="70" width="40" height="2" rx="1" fill="#c8a951"/>`);
    parts.push(`<text x="${W/2}" y="92" text-anchor="middle" fill="rgba(255,255,255,0.75)" font-size="13" font-family="system-ui,sans-serif">${dateDisplay}</text>`);
    y = hdrH;

    // ── Combined OEE Hero ──
    const heroH = 120;
    parts.push(`<rect x="0" y="${y}" width="${W}" height="${heroH}" fill="#fff"/>`);
    parts.push(`<text x="${W/2}" y="${y+24}" text-anchor="middle" fill="#94a3b8" font-size="10" font-weight="600" font-family="system-ui,sans-serif" letter-spacing="2">DAILY COMBINED OEE</text>`);
    if (comb.records > 0) {
      parts.push(`<text x="${W/2}" y="${y+72}" text-anchor="middle" fill="${oeeColor(comb.oee)}" font-size="52" font-weight="800" font-family="system-ui,sans-serif">${pct(comb.oee)}</text>`);
      const apqY = y + 100;
      const apqSpacing = 130;
      const cx = W / 2;
      [['Avail', comb.avail], ['Perf', comb.perf], ['Quality', comb.qual]].forEach(([lbl, val], i) => {
        const ax = cx + (i - 1) * apqSpacing;
        parts.push(`<text x="${ax}" y="${apqY}" text-anchor="middle" fill="${oeeColor(val)}" font-size="18" font-weight="700" font-family="system-ui,sans-serif">${pct(val)}</text>`);
        parts.push(`<text x="${ax}" y="${apqY+14}" text-anchor="middle" fill="#94a3b8" font-size="9" font-weight="600" font-family="system-ui,sans-serif">${lbl.toUpperCase()}</text>`);
      });
    } else {
      parts.push(`<text x="${W/2}" y="${y+65}" text-anchor="middle" fill="#94a3b8" font-size="36" font-family="system-ui,sans-serif">No Data</text>`);
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
      parts.push(`<text x="${ox+colW/2}" y="${sy+10}" text-anchor="middle" fill="#1b3d6e" font-size="12" font-weight="700" font-family="system-ui,sans-serif" letter-spacing="2">${label.toUpperCase()}</text>`);
      sy += 28;

      if (s.records === 0) {
        parts.push(`<text x="${ox+colW/2}" y="${sy+40}" text-anchor="middle" fill="#94a3b8" font-size="13" font-style="italic" font-family="system-ui,sans-serif">No data submitted</text>`);
        return;
      }

      // OEE big number
      parts.push(`<text x="${ox+colW/2}" y="${sy+36}" text-anchor="middle" fill="${oeeColor(s.oee)}" font-size="40" font-weight="800" font-family="system-ui,sans-serif">${pct(s.oee)}</text>`);
      parts.push(`<text x="${ox+colW/2}" y="${sy+50}" text-anchor="middle" fill="#94a3b8" font-size="9" font-weight="600" font-family="system-ui,sans-serif" letter-spacing="2">OEE</text>`);
      sy += 64;

      // A / P / Q row
      const miniSpacing = colW / 4;
      [['A', s.avail], ['P', s.perf], ['Q', s.qual]].forEach(([lbl, val], i) => {
        const mx = ox + miniSpacing * (i + 0.5);
        parts.push(`<text x="${mx}" y="${sy+4}" text-anchor="middle" fill="${oeeColor(val)}" font-size="16" font-weight="700" font-family="system-ui,sans-serif">${pct(val)}</text>`);
        parts.push(`<text x="${mx}" y="${sy+16}" text-anchor="middle" fill="#94a3b8" font-size="8" font-weight="600" font-family="system-ui,sans-serif">${lbl}</text>`);
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
        parts.push(`<text x="${ox+12}" y="${ry+12}" fill="#64748b" font-size="11" font-family="system-ui,sans-serif">${lbl}</text>`);
        parts.push(`<text x="${ox+colW-12}" y="${ry+12}" text-anchor="end" fill="${clr}" font-size="11" font-weight="700" font-family="system-ui,sans-serif">${val}</text>`);
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
        parts.push(`<text x="${ox+12}" y="${iy+12}" fill="#94a3b8" font-size="9" font-weight="700" font-family="system-ui,sans-serif" letter-spacing="1.5">${label.toUpperCase()}</text>`);
        iy += 24;
        const maxVal = items.length > 0 ? items[0][1] : 1;
        const barW = colW - 24;
        items.forEach(([name, val], i) => {
          const ry = iy + i * 32;
          parts.push(`<text x="${ox+12}" y="${ry+4}" fill="#334155" font-size="11" font-family="system-ui,sans-serif">${name}</text>`);
          parts.push(`<text x="${ox+colW-12}" y="${ry+4}" text-anchor="end" fill="#475569" font-size="11" font-weight="700" font-family="system-ui,sans-serif">${val}${unit}</text>`);
          // Bar background
          parts.push(`<rect x="${ox+12}" y="${ry+9}" width="${barW}" height="6" rx="3" fill="#f1f5f9"/>`);
          // Bar fill
          const fw = maxVal > 0 ? Math.round((val / maxVal) * barW) : 0;
          parts.push(`<rect x="${ox+12}" y="${ry+9}" width="${fw}" height="6" rx="3" fill="${barColor}"/>`);
        });
      }

      drawIssues(comb.topDT, 'Top Downtime', pad, '#ef4444', ' min');
      drawIssues(comb.topDef, 'Top Defects', W/2, '#f59e0b', '');
      y += issueH;
    }

    // ── Footer ──
    const footH = 36;
    parts.push(`<rect x="0" y="${y}" width="${W}" height="${footH}" rx="0" fill="#f8fafc"/>`);
    parts.push(`<rect x="0" y="${y+footH-16}" width="${W}" height="16" rx="16" ry="16" fill="#f8fafc"/>`);
    parts.push(`<rect x="${pad}" y="${y}" width="${W-pad*2}" height="1" fill="#e2e8f0"/>`);
    parts.push(`<text x="${W/2}" y="${y+22}" text-anchor="middle" fill="#94a3b8" font-size="10" font-family="system-ui,sans-serif">jmos-wv.up.railway.app  ·  Auto-generated daily report</text>`);
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
    const sharp = require('sharp');
    const svg = buildReportSVG(report);
    return sharp(Buffer.from(svg)).png().toBuffer();
  }

  // Email transporter (configured via env vars)
  let emailTransporter = null;
  function getEmailTransporter() {
    if (emailTransporter) return emailTransporter;
    const nodemailer = require('nodemailer');
    if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
    emailTransporter = nodemailer.createTransport({
      service: process.env.SMTP_SERVICE || 'gmail',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    return emailTransporter;
  }

  async function sendDailyReport(dateStr) {
    const { rows } = await pool.query('SELECT data FROM submissions WHERE shift_date = $1', [dateStr]);
    if (rows.length === 0) return { sent: false, reason: 'No data for ' + dateStr };

    const report = computeDailyReport(dateStr, rows);
    const pngBuffer = await buildReportPNG(report);
    const recipients = process.env.REPORT_EMAILS;
    if (!recipients) return { sent: false, reason: 'REPORT_EMAILS not configured' };

    const transporter = getEmailTransporter();
    if (!transporter) return { sent: false, reason: 'SMTP not configured' };

    const d = new Date(dateStr + 'T12:00:00');
    const subject = `JMOS Daily OEE — ${pct(report.combined.oee)} — ${d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`;

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: recipients,
      subject,
      html: `<div style="font-family:sans-serif;text-align:center;padding:16px;background:#f1f5f9">
        <img src="cid:dailyreport" alt="JMOS Daily OEE Report" style="max-width:100%;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.1)"/>
        <p style="margin-top:12px;font-size:12px;color:#94a3b8"><a href="https://jmos-wv.up.railway.app" style="color:#1b3d6e;font-weight:600">Open JMOS Dashboard</a></p>
      </div>`,
      attachments: [{
        filename: 'jmos-daily-oee.png',
        content: pngBuffer,
        cid: 'dailyreport'
      }]
    });
    return { sent: true, to: recipients, subject };
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

  // API: send report now (admin only)
  app.post('/api/report/send', requireAdmin, async (req, res) => {
    try {
      const dateStr = req.body.date || new Date(Date.now() - 86400000).toISOString().slice(0, 10);
      const result = await sendDailyReport(dateStr);
      res.json(result);
    } catch (err) {
      console.error('Report send error:', err);
      res.status(500).json({ error: 'Failed to send report' });
    }
  });

  // Daily auto-send scheduler (runs every hour, sends at configured hour)
  const REPORT_HOUR = parseInt(process.env.REPORT_HOUR || '6'); // 6 AM ET default
  let lastReportDate = null;
  setInterval(async () => {
    try {
      const now = new Date(new Date().toLocaleString('en-US', { timeZone: process.env.TZ || 'America/New_York' }));
      const todayStr = now.toISOString().slice(0, 10);
      if (now.getHours() >= REPORT_HOUR && lastReportDate !== todayStr) {
        const yesterday = new Date(now);
        yesterday.setDate(yesterday.getDate() - 1);
        const yStr = yesterday.toISOString().slice(0, 10);
        console.log('Auto-sending daily report for', yStr);
        const result = await sendDailyReport(yStr);
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
