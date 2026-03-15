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

  function buildEmailHTML(report) {
    const d = new Date(report.date + 'T12:00:00');
    const dateDisplay = d.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

    function shiftBlock(label, s) {
      if (s.records === 0) return `<div style="text-align:center;padding:20px;color:#94a3b8;font-style:italic">No data submitted</div>`;
      return `
        <div style="text-align:center;margin-bottom:16px">
          <div style="font-size:48px;font-weight:800;color:${oeeColor(s.oee)};letter-spacing:-2px">${pct(s.oee)}</div>
          <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:2px;margin-top:2px">OEE</div>
        </div>
        <table style="width:100%;border-collapse:collapse;margin-bottom:12px">
          <tr>
            <td style="text-align:center;padding:8px 4px">
              <div style="font-size:22px;font-weight:700;color:${oeeColor(s.avail)}">${pct(s.avail)}</div>
              <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Availability</div>
            </td>
            <td style="text-align:center;padding:8px 4px">
              <div style="font-size:22px;font-weight:700;color:${oeeColor(s.perf)}">${pct(s.perf)}</div>
              <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Performance</div>
            </td>
            <td style="text-align:center;padding:8px 4px">
              <div style="font-size:22px;font-weight:700;color:${oeeColor(s.qual)}">${pct(s.qual)}</div>
              <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Quality</div>
            </td>
          </tr>
        </table>
        <table style="width:100%;border-collapse:collapse;font-size:13px;color:#475569">
          <tr><td style="padding:4px 0">Good Units</td><td style="text-align:right;font-weight:600">${s.totalGood.toLocaleString()}</td></tr>
          <tr><td style="padding:4px 0">Total Produced</td><td style="text-align:right;font-weight:600">${s.totalProduced.toLocaleString()}</td></tr>
          <tr><td style="padding:4px 0">Target</td><td style="text-align:right;font-weight:600">${s.totalTarget.toLocaleString()}</td></tr>
          <tr><td style="padding:4px 0">Downtime</td><td style="text-align:right;font-weight:600;color:#ef4444">${s.totalDT} min</td></tr>
          <tr><td style="padding:4px 0">Defects</td><td style="text-align:right;font-weight:600;color:#f59e0b">${s.totalDefects.toLocaleString()}</td></tr>
        </table>`;
    }

    function topIssues(label, items, unit) {
      if (items.length === 0) return '';
      const max = items[0][1];
      return `
        <div style="margin-top:16px">
          <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;font-weight:600">${label}</div>
          ${items.map(([name, val]) => {
            const w = max > 0 ? Math.round((val / max) * 100) : 0;
            return `<div style="margin-bottom:6px">
              <div style="display:flex;justify-content:space-between;font-size:12px;color:#334155;margin-bottom:2px">
                <span>${name}</span><span style="font-weight:600">${val}${unit}</span>
              </div>
              <div style="background:#f1f5f9;border-radius:4px;height:6px;overflow:hidden">
                <div style="width:${w}%;height:100%;background:${label.includes('Downtime') ? '#ef4444' : '#f59e0b'};border-radius:4px"></div>
              </div>
            </div>`;
          }).join('')}
        </div>`;
    }

    return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<div style="max-width:640px;margin:0 auto;padding:24px 16px">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#0f1e38 0%,#1b3d6e 100%);border-radius:16px 16px 0 0;padding:32px 28px;text-align:center">
    <div style="font-size:28px;font-weight:800;color:#fff;letter-spacing:-0.5px">JMOS Dashboard</div>
    <div style="font-size:13px;color:rgba(255,255,255,0.6);margin-top:4px">West Virginia Bolt Plant</div>
    <div style="width:40px;height:2px;background:linear-gradient(90deg,#c8a951,#e8d48b);margin:12px auto 0;border-radius:2px"></div>
    <div style="font-size:14px;color:rgba(255,255,255,0.8);margin-top:12px">${dateDisplay}</div>
  </div>

  <!-- Combined OEE Hero -->
  <div style="background:#fff;padding:28px;text-align:center;border-bottom:1px solid #e2e8f0">
    <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:2px;margin-bottom:4px">Daily Combined OEE</div>
    <div style="font-size:64px;font-weight:800;color:${oeeColor(report.combined.oee)};letter-spacing:-3px;line-height:1">${report.combined.records > 0 ? pct(report.combined.oee) : '—'}</div>
    ${report.combined.records > 0 ? `
    <table style="width:240px;margin:16px auto 0;border-collapse:collapse">
      <tr>
        <td style="text-align:center;padding:4px">
          <div style="font-size:18px;font-weight:700;color:${oeeColor(report.combined.avail)}">${pct(report.combined.avail)}</div>
          <div style="font-size:9px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Avail</div>
        </td>
        <td style="text-align:center;padding:4px">
          <div style="font-size:18px;font-weight:700;color:${oeeColor(report.combined.perf)}">${pct(report.combined.perf)}</div>
          <div style="font-size:9px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Perf</div>
        </td>
        <td style="text-align:center;padding:4px">
          <div style="font-size:18px;font-weight:700;color:${oeeColor(report.combined.qual)}">${pct(report.combined.qual)}</div>
          <div style="font-size:9px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Quality</div>
        </td>
      </tr>
    </table>` : ''}
  </div>

  <!-- Shift Cards Side by Side -->
  <div style="display:flex;gap:0;background:#fff">
    <div style="flex:1;padding:24px 20px;border-right:1px solid #e2e8f0">
      <div style="text-align:center;font-size:12px;font-weight:700;color:#1b3d6e;text-transform:uppercase;letter-spacing:2px;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #c8a951">Shift 1</div>
      ${shiftBlock('Shift 1', report.shift1)}
    </div>
    <div style="flex:1;padding:24px 20px">
      <div style="text-align:center;font-size:12px;font-weight:700;color:#1b3d6e;text-transform:uppercase;letter-spacing:2px;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #c8a951">Shift 2</div>
      ${shiftBlock('Shift 2', report.shift2)}
    </div>
  </div>

  <!-- Top Issues -->
  ${report.combined.records > 0 ? `
  <div style="background:#fff;padding:20px 24px;border-top:1px solid #e2e8f0">
    <div style="display:flex;gap:24px">
      <div style="flex:1">
        ${topIssues('Top Downtime', report.combined.topDT, ' min')}
      </div>
      <div style="flex:1">
        ${topIssues('Top Defects', report.combined.topDef, '')}
      </div>
    </div>
  </div>` : ''}

  <!-- Footer -->
  <div style="background:#f8fafc;border-radius:0 0 16px 16px;padding:16px 24px;text-align:center;border-top:1px solid #e2e8f0">
    <div style="font-size:11px;color:#94a3b8">
      <a href="https://jmos-wv.up.railway.app" style="color:#1b3d6e;text-decoration:none;font-weight:600">Open JMOS Dashboard</a>
      &nbsp;·&nbsp; Auto-generated daily report
    </div>
  </div>

</div>
</body></html>`;
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
    const html = buildEmailHTML(report);
    const recipients = process.env.REPORT_EMAILS;
    if (!recipients) return { sent: false, reason: 'REPORT_EMAILS not configured', report, html };

    const transporter = getEmailTransporter();
    if (!transporter) return { sent: false, reason: 'SMTP not configured', report, html };

    const d = new Date(dateStr + 'T12:00:00');
    const subject = `JMOS Daily OEE — ${pct(report.combined.oee)} — ${d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`;

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: recipients,
      subject,
      html
    });
    return { sent: true, to: recipients, subject };
  }

  // API: preview report (returns HTML)
  app.get('/api/report/preview', requireAuth, async (req, res) => {
    try {
      const dateStr = req.query.date || new Date(Date.now() - 86400000).toISOString().slice(0, 10);
      const { rows } = await pool.query('SELECT data FROM submissions WHERE shift_date = $1', [dateStr]);
      if (rows.length === 0) return res.status(404).send('<h2 style="font-family:sans-serif;text-align:center;padding:60px;color:#64748b">No data for ' + dateStr + '</h2>');
      const report = computeDailyReport(dateStr, rows);
      res.send(buildEmailHTML(report));
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
