'use strict';

require('dotenv').config();

const express    = require('express');
const Database   = require('better-sqlite3');
const multer     = require('multer');
const bcrypt     = require('bcryptjs');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');
const rateLimit  = require('express-rate-limit');

// ============ CONFIG ============
const PORT          = parseInt(process.env.PORT || '3000', 10);
const DB_PATH       = path.resolve(process.env.DB_PATH || './sedap-klh.db');
const IP_SALT       = process.env.IP_SALT || 'sedap-klh-salt-2026';
const ADMIN_PASS    = process.env.ADMIN_PASSWORD  || 'admin123';
const RPPLH_PASS    = process.env.RPPLH_PASSWORD  || 'rpplh123';
const ZI_PASS       = process.env.ZI_PASSWORD     || 'zi123';

const app = express();

// ============ DIRECTORIES ============
const uploadsDir = path.join(__dirname, 'uploads');
const logsDir    = path.join(__dirname, 'logs');
[uploadsDir, logsDir].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// ============ RATE LIMITERS ============
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,      // 1 menit
  max: 300,                  // maks 300 request per IP per menit
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Terlalu banyak request, coba lagi nanti.' },
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 10,                   // maks 10 percobaan login per IP per 15 menit
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.' },
});
app.use(globalLimiter);

// ============ SECURITY HEADERS ============
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.jsdelivr.net cdnjs.cloudflare.com; " +
    "font-src 'self' fonts.gstatic.com cdnjs.cloudflare.com; " +
    "img-src 'self' data: blob: img.youtube.com www.youtube.com images.unsplash.com *.googleapis.com *.gstatic.com *.google.com *.openstreetmap.org *.tile.openstreetmap.org; " +
    "frame-src 'self' www.youtube.com youtube.com www.google.com maps.google.com *.google.com www.openstreetmap.org openstreetmap.org; " +
    "object-src 'self'; " +
    "connect-src 'self'; " +
    "media-src 'self' blob:;"
  );
  res.removeHeader('X-Powered-By');
  next();
});

// ============ MIDDLEWARE ============
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));

// ============ MULTER ============
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename:    (_req, file, cb) => {
    const suffix = crypto.randomBytes(8).toString('hex');
    cb(null, suffix + path.extname(file.originalname).toLowerCase());
  },
});
const ALLOWED_EXTENSIONS = /\.(jpeg|jpg|png|gif|webp|pdf|doc|docx|xls|xlsx|txt|mp3|mp4|webm|mov|avi|wav|pptx|ppt)$/i;
const ALLOWED_MIMES = new Set([
  'image/jpeg','image/jpg','image/png','image/gif','image/webp',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'text/plain',
  'audio/mpeg','audio/mp3','audio/wav',
  'video/mp4','video/webm','video/quicktime','video/x-msvideo',
]);
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB (video support)
  fileFilter: (_req, file, cb) => {
    const extOk  = ALLOWED_EXTENSIONS.test(path.extname(file.originalname));
    const mimeOk = ALLOWED_MIMES.has(file.mimetype);
    if (extOk && mimeOk) cb(null, true);
    else cb(new Error('Tipe file tidak didukung atau tidak cocok'));
  },
});

// ============ DATABASE ============
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    UNIQUE NOT NULL,
    password   TEXT    NOT NULL,
    role       TEXT    NOT NULL DEFAULT 'admin',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS reports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id      TEXT UNIQUE NOT NULL,
    category       TEXT NOT NULL,
    subject        TEXT NOT NULL,
    description    TEXT NOT NULL,
    severity       TEXT DEFAULT 'medium',
    location       TEXT,
    date_incident  TEXT,
    status         TEXT DEFAULT 'pending',
    admin_notes    TEXT DEFAULT '',
    anonymous_hash TEXT NOT NULL,
    ip_hash        TEXT,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS attachments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id     INTEGER,
    service_id    INTEGER,
    filename      TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_size     INTEGER,
    mime_type     TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS report_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id  INTEGER NOT NULL,
    sender     TEXT    NOT NULL DEFAULT 'reporter',
    message    TEXT    NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS services (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id           TEXT UNIQUE NOT NULL,
    service_type        TEXT NOT NULL,
    jenis_pemda         TEXT,
    provinsi            TEXT,
    kabkota             TEXT,
    metode              TEXT,
    tahap_penyusunan    TEXT,
    nama                TEXT NOT NULL,
    nip                 TEXT,
    jabatan             TEXT,
    instansi            TEXT,
    hp                  TEXT,
    email               TEXT,
    alamat              TEXT,
    kebutuhan           TEXT,
    status              TEXT DEFAULT 'pending',
    tanggal_pelaksanaan TEXT,
    waktu_pelaksanaan   TEXT,
    lokasi_pelaksanaan  TEXT,
    link_zoom           TEXT,
    zoom_id             TEXT,
    zoom_passcode       TEXT,
    surat_balasan       TEXT,
    surat_saran         TEXT,
    admin_notes         TEXT DEFAULT '',
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS surveys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    survey_type TEXT NOT NULL,
    data        TEXT NOT NULL,
    ip_hash     TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS content (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    content_type TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT,
    url          TEXT,
    image        TEXT,
    file_path    TEXT,
    published    INTEGER DEFAULT 1,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);

// ============ SEED DEFAULT USERS ============
// Password diambil dari .env agar tidak hardcoded di source code
const defaultUsers = [
  { username: 'admin', password: ADMIN_PASS, role: 'admin' },
  { username: 'rpplh', password: RPPLH_PASS, role: 'rpplh' },
  { username: 'zi',    password: ZI_PASS,    role: 'zi'    },
];
for (const u of defaultUsers) {
  const exists = db.prepare('SELECT id FROM admins WHERE username = ?').get(u.username);
  if (!exists) {
    const hashed = bcrypt.hashSync(u.password, 10);
    db.prepare('INSERT INTO admins (username, password, role) VALUES (?, ?, ?)').run(u.username, hashed, u.role);
  }
}

// ============ HELPERS ============
function generateTicketId(prefix = 'WB') {
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

function hashIP(ip) {
  return crypto.createHash('sha256').update((ip || '') + IP_SALT).digest('hex').substring(0, 16);
}

// ============ AUTH — Persistent DB token store ============
const TOKEN_TTL  = 8 * 60 * 60 * 1000; // 8 jam

// Bersihkan token kadaluarsa setiap 30 menit
setInterval(() => {
  try { db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()); } catch(e) {}
}, 30 * 60 * 1000);

function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (!session || session.expires_at < Date.now()) {
      if (session) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
      return res.status(401).json({ error: 'Sesi habis, silakan login kembali' });
    }
    req.user = { id: session.user_id, username: session.username, role: session.role };
    next();
  } catch (e) {
    return res.status(500).json({ error: 'Kesalahan server auth' });
  }
}

function roleCheck(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Akses ditolak' });
    next();
  };
}

// ============ AUTH API ============
app.post('/api/admin/login', loginLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username dan password wajib diisi' });
    const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
    if (!admin || !bcrypt.compareSync(password, admin.password)) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token, user_id, username, role, expires_at) VALUES (?, ?, ?, ?, ?)').run(
      token, admin.id, admin.username, admin.role, Date.now() + TOKEN_TTL
    );
    res.json({ success: true, token, username: admin.username, role: admin.role });
  } catch (err) {
    console.error('[login]', err.message);
    res.status(500).json({ error: 'Login gagal' });
  }
});

app.post('/api/admin/logout', authMiddleware, (req, res) => {
  try {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Logout gagal' });
  }
});

// ============ GANTI PASSWORD ============
app.post('/api/admin/change-password', authMiddleware, (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Password lama dan baru wajib diisi' });
    }
    if (new_password.length < 8) {
      return res.status(400).json({ error: 'Password baru minimal 8 karakter' });
    }
    const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.user.id);
    if (!admin || !bcrypt.compareSync(current_password, admin.password)) {
      return res.status(401).json({ error: 'Password lama tidak sesuai' });
    }
    const hashed = bcrypt.hashSync(new_password, 10);
    db.prepare('UPDATE admins SET password = ? WHERE id = ?').run(hashed, req.user.id);
    // Hapus semua sesi lain (paksa login ulang di perangkat lain)
    const currentToken = req.headers['authorization']?.replace('Bearer ', '');
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').run(req.user.id, currentToken);
    res.json({ success: true, message: 'Password berhasil diubah' });
  } catch (err) {
    console.error('[change-password]', err.message);
    res.status(500).json({ error: 'Gagal mengubah password' });
  }
});


app.post('/api/reports', upload.array('attachments', 5), (req, res) => {
  try {
    const { category, subject, description, severity, location, date_incident } = req.body;
    if (!category || !subject || !description) {
      return res.status(400).json({ error: 'Kategori, subjek, dan deskripsi wajib diisi' });
    }
    const ticket_id      = generateTicketId('WB');
    const anonymous_hash = crypto.randomBytes(16).toString('hex');
    const ip_hash        = hashIP(req.ip || req.socket?.remoteAddress);
    const result         = db.prepare(
      'INSERT INTO reports (ticket_id,category,subject,description,severity,location,date_incident,anonymous_hash,ip_hash) VALUES (?,?,?,?,?,?,?,?,?)'
    ).run(ticket_id, category, subject, description, severity || 'medium', location || '', date_incident || '', anonymous_hash, ip_hash);
    if (req.files?.length) {
      const stmt = db.prepare('INSERT INTO attachments (report_id,filename,original_name,file_size,mime_type) VALUES (?,?,?,?,?)');
      for (const f of req.files) stmt.run(result.lastInsertRowid, f.filename, f.originalname, f.size, f.mimetype);
    }
    res.json({ success: true, ticket_id, anonymous_hash, message: 'Laporan berhasil dikirim secara anonim' });
  } catch (err) {
    console.error('[reports POST]', err.message);
    res.status(500).json({ error: 'Gagal mengirim laporan' });
  }
});

app.get('/api/reports/track/:ticketId', (req, res) => {
  try {
    const report = db.prepare(
      'SELECT ticket_id,category,subject,status,severity,created_at,updated_at,admin_notes FROM reports WHERE ticket_id=?'
    ).get(req.params.ticketId);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });
    const messages = db.prepare(
      'SELECT sender,message,created_at FROM report_messages WHERE report_id=(SELECT id FROM reports WHERE ticket_id=?) ORDER BY created_at ASC'
    ).all(req.params.ticketId);
    res.json({ ...report, messages });
  } catch (err) {
    console.error('[reports track]', err.message);
    res.status(500).json({ error: 'Gagal mengambil data laporan' });
  }
});

app.post('/api/reports/track/:ticketId/message', (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Pesan tidak boleh kosong' });
    const report = db.prepare('SELECT id FROM reports WHERE ticket_id=?').get(req.params.ticketId);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });
    db.prepare('INSERT INTO report_messages (report_id,sender,message) VALUES (?,?,?)').run(report.id, 'reporter', message);
    res.json({ success: true });
  } catch (err) {
    console.error('[reports message]', err.message);
    res.status(500).json({ error: 'Gagal mengirim pesan' });
  }
});

// ============ SERVICES PUBLIC API ============
app.post('/api/services', upload.array('documents', 5), (req, res) => {
  try {
    const { service_type, jenis_pemda, provinsi, kabkota, metode, tahap_penyusunan,
            nama, nip, jabatan, instansi, hp, email, alamat, kebutuhan } = req.body;
    if (!service_type || !nama) return res.status(400).json({ error: 'Data tidak lengkap' });
    const prefix    = service_type === 'bimtek' ? 'BT' : 'KS';
    const ticket_id = generateTicketId(prefix);
    const result    = db.prepare(
      'INSERT INTO services (ticket_id,service_type,jenis_pemda,provinsi,kabkota,metode,tahap_penyusunan,nama,nip,jabatan,instansi,hp,email,alamat,kebutuhan) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    ).run(ticket_id, service_type, jenis_pemda||'', provinsi||'', kabkota||'', metode||'', tahap_penyusunan||'', nama, nip||'', jabatan||'', instansi||'', hp||'', email||'', alamat||'', kebutuhan||'');
    if (req.files?.length) {
      const stmt = db.prepare('INSERT INTO attachments (service_id,filename,original_name,file_size,mime_type) VALUES (?,?,?,?,?)');
      for (const f of req.files) stmt.run(result.lastInsertRowid, f.filename, f.originalname, f.size, f.mimetype);
    }
    res.json({ success: true, ticket_id, message: 'Permohonan berhasil dikirim' });
  } catch (err) {
    console.error('[services POST]', err.message);
    res.status(500).json({ error: 'Gagal mengirim permohonan' });
  }
});

app.get('/api/services/track/:ticketId', (req, res) => {
  try {
    const svc = db.prepare(
      'SELECT ticket_id,service_type,status,tanggal_pelaksanaan,waktu_pelaksanaan,lokasi_pelaksanaan,link_zoom,surat_balasan,surat_saran,admin_notes,created_at,updated_at FROM services WHERE ticket_id=?'
    ).get(req.params.ticketId);
    if (!svc) return res.status(404).json({ error: 'Layanan tidak ditemukan' });
    res.json(svc);
  } catch (err) {
    console.error('[services track]', err.message);
    res.status(500).json({ error: 'Gagal mengambil data layanan' });
  }
});

// ============ SURVEYS PUBLIC API ============
app.post('/api/surveys', (req, res) => {
  try {
    const { survey_type, data } = req.body;
    if (!survey_type || !data) return res.status(400).json({ error: 'Data survei tidak lengkap' });
    db.prepare('INSERT INTO surveys (survey_type,data,ip_hash) VALUES (?,?,?)').run(
      survey_type, JSON.stringify(data), hashIP(req.ip || req.socket?.remoteAddress)
    );
    res.json({ success: true, message: 'Terima kasih atas partisipasi Anda' });
  } catch (err) {
    console.error('[surveys POST]', err.message);
    res.status(500).json({ error: 'Gagal menyimpan survei' });
  }
});

// ============ ADMIN API: STATS ============
app.get('/api/admin/stats', authMiddleware, (req, res) => {
  try {
    const total        = db.prepare('SELECT COUNT(*) as c FROM reports').get().c;
    const pending      = db.prepare("SELECT COUNT(*) as c FROM reports WHERE status='pending'").get().c;
    const investigating= db.prepare("SELECT COUNT(*) as c FROM reports WHERE status='investigating'").get().c;
    const resolved     = db.prepare("SELECT COUNT(*) as c FROM reports WHERE status='resolved'").get().c;
    const dismissed    = db.prepare("SELECT COUNT(*) as c FROM reports WHERE status='dismissed'").get().c;
    const byCategory   = db.prepare('SELECT category,COUNT(*) as count FROM reports GROUP BY category').all();
    const bySeverity   = db.prepare('SELECT severity,COUNT(*) as count FROM reports GROUP BY severity').all();
    const recentReports= db.prepare('SELECT ticket_id,subject,category,severity,status,created_at FROM reports ORDER BY created_at DESC LIMIT 5').all();
    const totalServices   = db.prepare('SELECT COUNT(*) as c FROM services').get().c;
    const pendingServices = db.prepare("SELECT COUNT(*) as c FROM services WHERE status='pending'").get().c;
    const totalSurveys    = db.prepare('SELECT COUNT(*) as c FROM surveys').get().c;
    const totalSKM        = db.prepare("SELECT COUNT(*) as c FROM surveys WHERE survey_type='kepuasan'").get().c;
    const totalPAK        = db.prepare("SELECT COUNT(*) as c FROM surveys WHERE survey_type='antikorupsi'").get().c;
    res.json({ total, pending, investigating, resolved, dismissed, byCategory, bySeverity,
               recentReports, totalServices, pendingServices, totalSurveys, totalSKM, totalPAK });
  } catch (err) {
    console.error('[stats]', err.message);
    res.status(500).json({ error: 'Gagal mengambil statistik' });
  }
});

// ============ ADMIN API: REPORTS ============
app.get('/api/admin/reports', authMiddleware, roleCheck('admin', 'zi'), (req, res) => {
  try {
    const { status, category, search, sort } = req.query;
    let q = 'SELECT * FROM reports WHERE 1=1'; const p = [];
    if (status   && status   !== 'all') { q += ' AND status=?';   p.push(status); }
    if (category && category !== 'all') { q += ' AND category=?'; p.push(category); }
    if (search) { q += ' AND (subject LIKE ? OR ticket_id LIKE ?)'; p.push(`%${search}%`, `%${search}%`); }
    q += sort === 'oldest' ? ' ORDER BY created_at ASC' : ' ORDER BY created_at DESC';
    const reports = db.prepare(q).all(...p);
    for (const r of reports) {
      r.attachment_count = db.prepare('SELECT COUNT(*) as c FROM attachments WHERE report_id=?').get(r.id).c;
      r.message_count    = db.prepare('SELECT COUNT(*) as c FROM report_messages WHERE report_id=?').get(r.id).c;
    }
    res.json(reports);
  } catch (err) {
    console.error('[admin reports]', err.message);
    res.status(500).json({ error: 'Gagal mengambil data laporan' });
  }
});

app.get('/api/admin/reports/:id', authMiddleware, roleCheck('admin', 'zi'), (req, res) => {
  try {
    const report = db.prepare('SELECT * FROM reports WHERE id=?').get(req.params.id);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });
    const attachments = db.prepare('SELECT * FROM attachments WHERE report_id=?').all(report.id);
    const messages    = db.prepare('SELECT * FROM report_messages WHERE report_id=? ORDER BY created_at ASC').all(report.id);
    res.json({ ...report, attachments, messages });
  } catch (err) {
    console.error('[admin reports/:id]', err.message);
    res.status(500).json({ error: 'Gagal mengambil detail laporan' });
  }
});

app.put('/api/admin/reports/:id', authMiddleware, roleCheck('admin', 'zi'), (req, res) => {
  try {
    const { status, admin_notes } = req.body;
    const report = db.prepare('SELECT id FROM reports WHERE id=?').get(req.params.id);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });
    if (status      !== undefined) db.prepare('UPDATE reports SET status=?,     updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status, req.params.id);
    if (admin_notes !== undefined) db.prepare('UPDATE reports SET admin_notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(admin_notes, req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error('[admin reports PUT]', err.message);
    res.status(500).json({ error: 'Gagal memperbarui laporan' });
  }
});

app.post('/api/admin/reports/:id/message', authMiddleware, roleCheck('admin', 'zi'), (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Pesan tidak boleh kosong' });
    const report = db.prepare('SELECT id FROM reports WHERE id=?').get(req.params.id);
    if (!report) return res.status(404).json({ error: 'Laporan tidak ditemukan' });
    db.prepare('INSERT INTO report_messages (report_id,sender,message) VALUES (?,?,?)').run(report.id, 'admin', message);
    res.json({ success: true });
  } catch (err) {
    console.error('[admin reports message]', err.message);
    res.status(500).json({ error: 'Gagal mengirim pesan' });
  }
});

app.delete('/api/admin/reports/:id', authMiddleware, roleCheck('admin', 'zi'), (req, res) => {
  try {
    const attachments = db.prepare('SELECT filename FROM attachments WHERE report_id=?').all(req.params.id);
    for (const a of attachments) {
      const fp = path.join(uploadsDir, a.filename);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    db.prepare('DELETE FROM attachments    WHERE report_id=?').run(req.params.id);
    db.prepare('DELETE FROM report_messages WHERE report_id=?').run(req.params.id);
    db.prepare('DELETE FROM reports         WHERE id=?').run(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error('[admin reports DELETE]', err.message);
    res.status(500).json({ error: 'Gagal menghapus laporan' });
  }
});

// ============ ADMIN API: SERVICES ============
app.get('/api/admin/services', authMiddleware, roleCheck('admin', 'rpplh'), (req, res) => {
  try {
    const { status, service_type, search, sort } = req.query;
    let q = 'SELECT * FROM services WHERE 1=1'; const p = [];
    if (status       && status       !== 'all') { q += ' AND status=?';       p.push(status); }
    if (service_type && service_type !== 'all') { q += ' AND service_type=?'; p.push(service_type); }
    if (search) { q += ' AND (nama LIKE ? OR instansi LIKE ? OR ticket_id LIKE ? OR provinsi LIKE ?)'; p.push(...Array(4).fill(`%${search}%`)); }
    q += sort === 'oldest' ? ' ORDER BY created_at ASC' : ' ORDER BY created_at DESC';
    const services = db.prepare(q).all(...p);
    for (const s of services) {
      s.attachment_count = db.prepare('SELECT COUNT(*) as c FROM attachments WHERE service_id=?').get(s.id).c;
    }
    res.json(services);
  } catch (err) {
    console.error('[admin services]', err.message);
    res.status(500).json({ error: 'Gagal mengambil data layanan' });
  }
});

app.get('/api/admin/services/:id', authMiddleware, roleCheck('admin', 'rpplh'), (req, res) => {
  try {
    const svc = db.prepare('SELECT * FROM services WHERE id=?').get(req.params.id);
    if (!svc) return res.status(404).json({ error: 'Layanan tidak ditemukan' });
    const attachments = db.prepare('SELECT * FROM attachments WHERE service_id=?').all(svc.id);
    res.json({ ...svc, attachments });
  } catch (err) {
    console.error('[admin services/:id]', err.message);
    res.status(500).json({ error: 'Gagal mengambil detail layanan' });
  }
});

app.put('/api/admin/services/:id', authMiddleware, roleCheck('admin', 'rpplh'),
  upload.fields([{ name: 'surat_balasan', maxCount: 1 }, { name: 'surat_saran', maxCount: 1 }]),
  (req, res) => {
    try {
      const { status, tanggal_pelaksanaan, waktu_pelaksanaan, lokasi_pelaksanaan,
              link_zoom, zoom_id, zoom_passcode, admin_notes } = req.body;
      const svc = db.prepare('SELECT id FROM services WHERE id=?').get(req.params.id);
      if (!svc) return res.status(404).json({ error: 'Layanan tidak ditemukan' });
      const upd = [], vals = [];
      const push = (col, val) => { upd.push(`${col}=?`); vals.push(val); };
      if (status              !== undefined) push('status',               status);
      if (tanggal_pelaksanaan !== undefined) push('tanggal_pelaksanaan',  tanggal_pelaksanaan);
      if (waktu_pelaksanaan   !== undefined) push('waktu_pelaksanaan',    waktu_pelaksanaan);
      if (lokasi_pelaksanaan  !== undefined) push('lokasi_pelaksanaan',   lokasi_pelaksanaan);
      if (link_zoom           !== undefined) push('link_zoom',            link_zoom);
      if (zoom_id             !== undefined) push('zoom_id',              zoom_id);
      if (zoom_passcode       !== undefined) push('zoom_passcode',        zoom_passcode);
      if (admin_notes         !== undefined) push('admin_notes',          admin_notes);
      if (req.files?.surat_balasan) push('surat_balasan', req.files.surat_balasan[0].filename);
      if (req.files?.surat_saran)   push('surat_saran',   req.files.surat_saran[0].filename);
      if (upd.length) {
        upd.push('updated_at=CURRENT_TIMESTAMP');
        vals.push(req.params.id);
        db.prepare(`UPDATE services SET ${upd.join(',')} WHERE id=?`).run(...vals);
      }
      res.json({ success: true });
    } catch (err) {
      console.error('[admin services PUT]', err.message);
      res.status(500).json({ error: 'Gagal memperbarui layanan' });
    }
  }
);

// ============ ADMIN API: SURVEYS ============
app.get('/api/admin/surveys', authMiddleware, roleCheck('admin', 'zi'), (req, res) => {
  try {
    const { survey_type, sort } = req.query;
    let q = 'SELECT * FROM surveys WHERE 1=1'; const p = [];
    if (survey_type && survey_type !== 'all') { q += ' AND survey_type=?'; p.push(survey_type); }
    q += sort === 'oldest' ? ' ORDER BY created_at ASC' : ' ORDER BY created_at DESC';
    const surveys = db.prepare(q).all(...p);
    surveys.forEach(s => { try { s.data = JSON.parse(s.data); } catch (_) {} });
    res.json(surveys);
  } catch (err) {
    console.error('[admin surveys]', err.message);
    res.status(500).json({ error: 'Gagal mengambil data survei' });
  }
});

app.get('/api/admin/surveys/stats', authMiddleware, roleCheck('admin', 'zi'), (req, res) => {
  try {
    const totalSKM = db.prepare("SELECT COUNT(*) as c FROM surveys WHERE survey_type='kepuasan'").get().c;
    const totalPAK = db.prepare("SELECT COUNT(*) as c FROM surveys WHERE survey_type='antikorupsi'").get().c;
    res.json({ totalSKM, totalPAK, total: totalSKM + totalPAK });
  } catch (err) {
    console.error('[admin surveys stats]', err.message);
    res.status(500).json({ error: 'Gagal mengambil statistik survei' });
  }
});

// ============ ADMIN API: CONTENT ============
app.get('/api/admin/content', authMiddleware, roleCheck('admin'), (req, res) => {
  try {
    const { content_type } = req.query;
    let q = 'SELECT * FROM content'; const p = [];
    if (content_type && content_type !== 'all') { q += ' WHERE content_type=?'; p.push(content_type); }
    q += ' ORDER BY created_at DESC';
    res.json(db.prepare(q).all(...p));
  } catch (err) {
    console.error('[admin content GET]', err.message);
    res.status(500).json({ error: 'Gagal mengambil konten' });
  }
});

app.post('/api/admin/content', authMiddleware, roleCheck('admin'),
  upload.fields([{ name: 'image', maxCount: 1 }, { name: 'file', maxCount: 1 }]),
  (req, res) => {
    try {
      const { content_type, title, description, url } = req.body;
      const VALID_CONTENT_TYPES = ['berita', 'infografis', 'videografis', 'peraturan'];
      if (!content_type || !VALID_CONTENT_TYPES.includes(content_type)) {
        return res.status(400).json({ error: 'Tipe konten tidak valid' });
      }
      if (!title || title.trim().length === 0) return res.status(400).json({ error: 'Judul wajib diisi' });
      if (title.length > 500) return res.status(400).json({ error: 'Judul terlalu panjang (maks 500 karakter)' });
      const image     = req.files?.image ? req.files.image[0].filename : '';
      const file_path = req.files?.file  ? req.files.file[0].filename  : '';
      db.prepare('INSERT INTO content (content_type,title,description,url,image,file_path) VALUES (?,?,?,?,?,?)').run(
        content_type, title, description || '', url || '', image, file_path
      );
      res.json({ success: true });
    } catch (err) {
      console.error('[admin content POST]', err.message);
      res.status(500).json({ error: 'Gagal menambah konten' });
    }
  }
);

app.put('/api/admin/content/:id', authMiddleware, roleCheck('admin'),
  upload.fields([{ name: 'image', maxCount: 1 }, { name: 'file', maxCount: 1 }]),
  (req, res) => {
    try {
      const { title, description, url, published } = req.body;
      const existing = db.prepare('SELECT id FROM content WHERE id=?').get(req.params.id);
      if (!existing) return res.status(404).json({ error: 'Konten tidak ditemukan' });
      const upd = ['updated_at=CURRENT_TIMESTAMP'], vals = [];
      if (title       !== undefined) { upd.push('title=?');       vals.push(title); }
      if (description !== undefined) { upd.push('description=?'); vals.push(description); }
      if (url         !== undefined) { upd.push('url=?');         vals.push(url); }
      if (published   !== undefined) { upd.push('published=?');   vals.push(parseInt(published)); }
      if (req.files?.image) { upd.push('image=?');     vals.push(req.files.image[0].filename); }
      if (req.files?.file)  { upd.push('file_path=?'); vals.push(req.files.file[0].filename); }
      vals.push(req.params.id);
      db.prepare(`UPDATE content SET ${upd.join(',')} WHERE id=?`).run(...vals);
      res.json({ success: true });
    } catch (err) {
      console.error('[admin content PUT]', err.message);
      res.status(500).json({ error: 'Gagal memperbarui konten' });
    }
  }
);

app.delete('/api/admin/content/:id', authMiddleware, roleCheck('admin'), (req, res) => {
  try {
    db.prepare('DELETE FROM content WHERE id=?').run(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error('[admin content DELETE]', err.message);
    res.status(500).json({ error: 'Gagal menghapus konten' });
  }
});

// ============ PUBLIC CONTENT API ============
app.get('/api/content', (req, res) => {
  try {
    const { content_type } = req.query;
    let q = 'SELECT * FROM content WHERE published=1'; const p = [];
    if (content_type) { q += ' AND content_type=?'; p.push(content_type); }
    q += ' ORDER BY created_at DESC';
    res.json(db.prepare(q).all(...p));
  } catch (err) {
    console.error('[content public]', err.message);
    res.status(500).json({ error: 'Gagal mengambil konten' });
  }
});

// ============ CATCH-ALL (SPA fallback) ============
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ GRACEFUL SHUTDOWN ============
function gracefulShutdown(signal) {
  console.log(`\n[${signal}] Menutup server...`);
  db.close();
  process.exit(0);
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

// ============ START ============
app.listen(PORT, () => {
  console.log(`🌿 SEDAP KLH berjalan di http://localhost:${PORT}`);
  console.log(`📋 Admin Panel: http://localhost:${PORT}/admin.html`);
});
