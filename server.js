import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'student-activity-dev-secret-change-in-prod';
const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const isNeon = Boolean(DATABASE_URL);
const DB_FILE = path.join(__dirname, 'activity-db.json');

const MANAGEMENT_ROLES = ['president', 'vice_president', 'officer'];
const ALLOWED_ROLES = ['president', 'vice_president', 'officer', 'member'];
const ALL_PERMISSIONS = [
  'manage_directory',
  'manage_broadcasts',
  'manage_activities',
  'manage_discipline',
  'review_submissions',
  'issue_directives',
];
const DEFAULT_ROLE_PERMISSIONS = {
  president: [...ALL_PERMISSIONS],
  vice_president: [...ALL_PERMISSIONS],
  officer: ['manage_activities', 'manage_discipline', 'manage_broadcasts', 'review_submissions', 'issue_directives'],
  member: [],
};

const isMgmt = (role) => MANAGEMENT_ROLES.includes(role);
const isSupremePresident = (user) => Boolean(user && user.username === 'president');
const hasPerm = (user, perm) => {
  if (!user) return false;
  if (isSupremePresident(user)) return true;
  const perms = Array.isArray(user.permissions)
    ? user.permissions
    : DEFAULT_ROLE_PERMISSIONS[user.role] || [];
  return perms.includes(perm);
};
const hasAllSixPerms = (user) => {
  if (!user) return false;
  if (isSupremePresident(user)) return true;
  return ALL_PERMISSIONS.every((p) => hasPerm(user, p));
};
const sanitizePermissions = (input) => {
  if (!Array.isArray(input)) return undefined;
  return input.filter((p) => ALL_PERMISSIONS.includes(p));
};

let pool = null;
function getPool() {
  if (!pool && DATABASE_URL) {
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: DATABASE_URL.includes('localhost') || DATABASE_URL.includes('127.0.0.1')
        ? false
        : { rejectUnauthorized: false },
    });
  }
  return pool;
}

function createInitialData() {
  const now = new Date().toISOString();
  const adminHash = bcrypt.hashSync('Admin@123', 10);
  return {
    counters: {
      users: 2,
      activities: 2,
      broadcasts: 1,
      discipline: 0,
      directives: 1,
      submissions: 0,
      complaints: 0,
      suggestions: 0,
    },
    users: [
      {
        id: 1,
        memberCode: 'CMD-001',
        loginCode: '245662',
        username: 'president',
        fullName: 'عبدالرحمن نسيم',
        passwordHash: adminHash,
        role: 'president',
        unit: 'command',
        phone: '0551001001',
        gradeOrDept: 'الإدارة العليا',
        points: 100,
        isActive: true,
        permissions: [...ALL_PERMISSIONS],
        createdAt: now,
      },
      {
        id: 2,
        memberCode: 'CMD-002',
        loginCode: '324662',
        username: 'vice',
        fullName: 'خالد رحيم',
        passwordHash: adminHash,
        role: 'vice_president',
        unit: 'command',
        phone: '0551001002',
        gradeOrDept: 'الإدارة العليا',
        points: 96,
        isActive: true,
        permissions: [...ALL_PERMISSIONS],
        createdAt: now,
      },
    ],
    activities: [
      {
        id: 1,
        title: 'مسابقة الإلقاء والخطابة',
        unit: 'activity_1',
        category: 'ثقافي',
        description: 'مسابقة للطلاب في الإلقاء والخطابة على مسرح المدرسة.',
        eventDate: '2026-11-22',
        eventTime: '09:30',
        location: 'المسرح المدرسي',
        status: 'approved',
        officerReady: true,
        createdByName: 'عبدالرحمن نسيم',
        createdAt: now,
      },
      {
        id: 2,
        title: 'دوري كرة القدم المصغر',
        unit: 'activity_2',
        category: 'رياضي',
        description: 'مباريات ودية بين فصول المرحلة المتوسطة في الفسحة.',
        eventDate: '2026-11-24',
        eventTime: '09:45',
        location: 'الملعب الرئيسي',
        status: 'approved',
        officerReady: true,
        createdByName: 'خالد رحيم',
        createdAt: now,
      },
    ],
    broadcasts: [
      {
        id: 1,
        title: 'إذاعة الانضباط والهمة العالية',
        airDate: '2026-11-17',
        airTime: '07:15',
        theme: 'القيم والانضباط',
        presenters: 'يُحدد من أفراد الإذاعة',
        supervisorName: 'إدارة النشاط الطلابي',
        status: 'approved',
        officerChecked: true,
        segments: {
          intro: 'بسم الله الرحمن الرحيم، أهلاً بكم في إذاعتنا الصباحية لهذا اليوم.',
          quran: 'آيات مباركة من سورة العصر.',
          hadith: 'قال رسول الله صلى الله عليه وسلم: كلكم راعٍ وكلكم مسؤول عن رعيته.',
          morningWord: 'الالتزام بالوقت والمحافظة على النظام سر تميز الطالب المتفوق.',
          didYouKnow: 'هل تعلم أن الاستيقاظ المبكر ينشط الذاكرة ويزيد التركيز في الحصص؟',
          closing: 'شكراً لحسن استماعكم، ونتمنى لكم يوماً دراسياً سعيداً.',
        },
        createdAt: now,
      },
    ],
    disciplineLogs: [],
    directives: [
      {
        id: 1,
        title: 'بدء استقبال إنجازات واقتراحات الطلاب',
        content: 'نرحب بجميع الطلاب المسجلين في النشاط لرفع إنجازاتهم واقتراحاتهم عبر المنصة ليتم تقييمها واحتساب نقاطها.',
        targetUnit: 'all',
        priority: 'normal',
        issuedByName: 'عبدالرحمن نسيم',
        issuedByRole: 'president',
        createdAt: now,
      },
    ],
    submissions: [],
    complaints: [],
    suggestions: [],
  };
}

function readLocal() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = createInitialData();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeLocal(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

let dbInitPromise = null;
async function ensureReady() {
  if (!isNeon) {
    readLocal();
    return;
  }
  if (!dbInitPromise) {
    dbInitPromise = (async () => {
      const p = getPool();
      await p.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          member_code TEXT NOT NULL UNIQUE,
          login_code TEXT NOT NULL UNIQUE,
          username TEXT NOT NULL UNIQUE,
          full_name TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL,
          unit TEXT NOT NULL,
          phone TEXT NOT NULL DEFAULT '',
          grade_or_dept TEXT NOT NULL DEFAULT '',
          points INTEGER NOT NULL DEFAULT 0,
          is_active BOOLEAN NOT NULL DEFAULT TRUE,
          permissions JSONB,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB;
        CREATE TABLE IF NOT EXISTS activities (
          id SERIAL PRIMARY KEY,
          title TEXT NOT NULL,
          unit TEXT NOT NULL,
          category TEXT NOT NULL DEFAULT 'عام',
          description TEXT NOT NULL DEFAULT '',
          event_date TEXT NOT NULL,
          event_time TEXT NOT NULL,
          location TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'approved',
          officer_ready BOOLEAN NOT NULL DEFAULT FALSE,
          created_by_name TEXT NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS broadcasts (
          id SERIAL PRIMARY KEY,
          title TEXT NOT NULL,
          air_date TEXT NOT NULL,
          air_time TEXT NOT NULL,
          theme TEXT NOT NULL DEFAULT 'عام',
          presenters TEXT NOT NULL DEFAULT '',
          supervisor_name TEXT NOT NULL DEFAULT 'الإدارة',
          status TEXT NOT NULL DEFAULT 'pending_approval',
          officer_checked BOOLEAN NOT NULL DEFAULT FALSE,
          segments JSONB NOT NULL DEFAULT '{}'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS discipline_logs (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          user_name TEXT NOT NULL,
          user_code TEXT NOT NULL,
          unit TEXT NOT NULL,
          category TEXT NOT NULL,
          points_delta INTEGER NOT NULL DEFAULT 0,
          note TEXT NOT NULL,
          recorded_by_name TEXT NOT NULL,
          log_date TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS directives (
          id SERIAL PRIMARY KEY,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          target_unit TEXT NOT NULL DEFAULT 'all',
          priority TEXT NOT NULL DEFAULT 'normal',
          issued_by_name TEXT NOT NULL,
          issued_by_role TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS submissions (
          id SERIAL PRIMARY KEY,
          student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          student_name TEXT NOT NULL,
          student_code TEXT NOT NULL,
          unit TEXT NOT NULL,
          title TEXT NOT NULL,
          details TEXT NOT NULL DEFAULT '',
          activity_date TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          awarded_points INTEGER NOT NULL DEFAULT 0,
          admin_note TEXT NOT NULL DEFAULT '',
          reviewed_by_name TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS complaints (
          id SERIAL PRIMARY KEY,
          reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          reporter_name TEXT NOT NULL,
          target_student_name TEXT NOT NULL,
          reason TEXT NOT NULL,
          details TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'new',
          admin_response TEXT NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS suggestions (
          id SERIAL PRIMARY KEY,
          student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          student_name TEXT NOT NULL,
          title TEXT NOT NULL,
          details TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'new',
          admin_response TEXT NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      const countRes = await p.query('SELECT COUNT(*)::int AS cnt FROM users');
      if (countRes.rows[0].cnt === 0) {
        const seed = createInitialData();
        for (const u of seed.users) {
          await p.query(
            `INSERT INTO users (member_code, login_code, username, full_name, password_hash, role, unit, phone, grade_or_dept, points, is_active, permissions)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`,
            [u.memberCode, u.loginCode, u.username, u.fullName, u.passwordHash, u.role, u.unit, u.phone, u.gradeOrDept, u.points, u.isActive, JSON.stringify(u.permissions)]
          );
        }
        for (const a of seed.activities) {
          await p.query(
            `INSERT INTO activities (title, unit, category, description, event_date, event_time, location, status, officer_ready, created_by_name)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [a.title, a.unit, a.category, a.description, a.eventDate, a.eventTime, a.location, a.status, a.officerReady, a.createdByName]
          );
        }
        for (const b of seed.broadcasts) {
          await p.query(
            `INSERT INTO broadcasts (title, air_date, air_time, theme, presenters, supervisor_name, status, officer_checked, segments)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`,
            [b.title, b.airDate, b.airTime, b.theme, b.presenters, b.supervisorName, b.status, b.officerChecked, JSON.stringify(b.segments)]
          );
        }
        for (const d of seed.directives) {
          await p.query(
            `INSERT INTO directives (title, content, target_unit, priority, issued_by_name, issued_by_role)
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [d.title, d.content, d.targetUnit, d.priority, d.issuedByName, d.issuedByRole]
          );
        }
      }
    })();
  }
  return dbInitPromise;
}

const mapUser = (r) => ({
  id: r.id,
  memberCode: r.member_code,
  loginCode: r.login_code,
  username: r.username,
  fullName: r.full_name,
  passwordHash: r.password_hash,
  role: r.role,
  unit: r.unit,
  phone: r.phone,
  gradeOrDept: r.grade_or_dept,
  points: Number(r.points || 0),
  isActive: Boolean(r.is_active),
  permissions: Array.isArray(r.permissions)
    ? r.permissions
    : DEFAULT_ROLE_PERMISSIONS[r.role] || [],
  createdAt: new Date(r.created_at).toISOString(),
});

const sanitizeUser = (u, viewer = null) => {
  const { passwordHash: _, ...rest } = u;
  const pub = {
    ...rest,
    permissions:
      isSupremePresident(u)
        ? [...ALL_PERMISSIONS]
        : Array.isArray(u.permissions)
          ? u.permissions
          : DEFAULT_ROLE_PERMISSIONS[u.role] || [],
  };
  if (!viewer) return pub;
  const viewerAll = hasAllSixPerms(viewer);
  const targetIsSupreme = isSupremePresident(u);
  const canSeeCode =
    u.id === viewer.id ||
    isSupremePresident(viewer) ||
    (viewerAll && !targetIsSupreme);
  return {
    ...pub,
    loginCode: canSeeCode ? pub.loginCode : '',
    permissions: viewerAll || u.id === viewer.id ? pub.permissions : undefined,
  };
};

async function findUserByLoginCode(code) {
  await ensureReady();
  const clean = String(code || '').trim();
  if (!isNeon) {
    return readLocal().users.find((u) => u.loginCode === clean) || null;
  }
  const r = await getPool().query('SELECT * FROM users WHERE login_code = $1 LIMIT 1', [clean]);
  return r.rows[0] ? mapUser(r.rows[0]) : null;
}

async function findUserById(id) {
  await ensureReady();
  if (!isNeon) {
    return readLocal().users.find((u) => u.id === Number(id)) || null;
  }
  const r = await getPool().query('SELECT * FROM users WHERE id = $1 LIMIT 1', [Number(id)]);
  return r.rows[0] ? mapUser(r.rows[0]) : null;
}

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'يرجى تسجيل الدخول' });
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    const u = await findUserById(payload.userId);
    if (!u || !u.isActive) return res.status(401).json({ error: 'الجلسة منتهية أو الحساب موقوف' });
    req.user = sanitizeUser(u);
    next();
  } catch {
    res.status(401).json({ error: 'رمز الجلسة غير صالح' });
  }
}

const requireMgmt = (req, res, next) => {
  if (!req.user || !isMgmt(req.user.role)) return res.status(403).json({ error: 'صلاحية للإدارة فقط' });
  next();
};

app.get('/api/health', async (_req, res) => {
  try {
    await ensureReady();
    res.json({ ok: true, database: isNeon ? 'neon-postgres' : 'local-json' });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { code, portalType } = req.body || {};
    if (!String(code || '').trim()) return res.status(400).json({ error: 'يرجى إدخال رمز الدخول' });
    const u = await findUserByLoginCode(code);
    if (!u) return res.status(401).json({ error: 'رمز الدخول غير صحيح' });
    if (!u.isActive) return res.status(403).json({ error: 'الحساب موقوف حالياً' });
    if (portalType === 'management' && !isMgmt(u.role)) {
      return res.status(403).json({ error: 'هذا الرمز مخصص لبوابة الأفراد (الطلاب)' });
    }
    if (portalType === 'member' && isMgmt(u.role)) {
      return res.status(403).json({ error: 'هذا الرمز مخصص لبوابة الإدارة' });
    }
    const token = jwt.sign({ userId: u.id, role: u.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: sanitizeUser(u) });
  } catch {
    res.status(500).json({ error: 'تعذر تسجيل الدخول' });
  }
});

app.post('/api/auth/register-member', (_req, res) => {
  res.status(403).json({ error: 'التسجيل الذاتي مغلق؛ تُضاف الحسابات من الإدارة فقط' });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/workspace', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const viewer = req.user;
    const canSeeUsers =
      hasAllSixPerms(viewer) ||
      isMgmt(viewer.role) ||
      hasPerm(viewer, 'manage_activities') ||
      hasPerm(viewer, 'manage_discipline');
    const canSeeBroadcasts = hasPerm(viewer, 'manage_broadcasts');
    const canSeeDiscipline = isMgmt(viewer.role) || hasPerm(viewer, 'manage_discipline');
    const canReviewSubs = isMgmt(viewer.role) || hasPerm(viewer, 'review_submissions');

    if (!isNeon) {
      const db = readLocal();
      const visibleUsers = canSeeUsers ? db.users : db.users.filter((u) => u.id === viewer.id);
      return res.json({
        users: visibleUsers.map((u) => sanitizeUser(u, viewer)),
        activities: db.activities,
        broadcasts: canSeeBroadcasts ? db.broadcasts : [],
        disciplineLogs: canSeeDiscipline ? db.disciplineLogs : db.disciplineLogs.filter((d) => d.userId === viewer.id),
        directives: db.directives,
        submissions: canReviewSubs ? db.submissions : db.submissions.filter((s) => s.studentId === viewer.id),
        complaints: canReviewSubs ? db.complaints : db.complaints.filter((c) => c.reporterId === viewer.id),
        suggestions: canReviewSubs ? db.suggestions : db.suggestions.filter((s) => s.studentId === viewer.id),
      });
    }
    const p = getPool();
    const [uR, aR, bR, disR, dirR, subR, cmpR, sugR] = await Promise.all([
      canSeeUsers ? p.query('SELECT * FROM users ORDER BY id ASC') : p.query('SELECT * FROM users WHERE id=$1', [viewer.id]),
      p.query('SELECT * FROM activities ORDER BY id DESC'),
      canSeeBroadcasts ? p.query('SELECT * FROM broadcasts ORDER BY id DESC') : Promise.resolve({ rows: [] }),
      canSeeDiscipline
        ? p.query('SELECT * FROM discipline_logs ORDER BY id DESC')
        : p.query('SELECT * FROM discipline_logs WHERE user_id=$1 ORDER BY id DESC', [viewer.id]),
      p.query('SELECT * FROM directives ORDER BY id DESC'),
      canReviewSubs
        ? p.query('SELECT * FROM submissions ORDER BY id DESC')
        : p.query('SELECT * FROM submissions WHERE student_id=$1 ORDER BY id DESC', [viewer.id]),
      canReviewSubs
        ? p.query('SELECT * FROM complaints ORDER BY id DESC')
        : p.query('SELECT * FROM complaints WHERE reporter_id=$1 ORDER BY id DESC', [viewer.id]),
      canReviewSubs
        ? p.query('SELECT * FROM suggestions ORDER BY id DESC')
        : p.query('SELECT * FROM suggestions WHERE student_id=$1 ORDER BY id DESC', [viewer.id]),
    ]);
    res.json({
      users: uR.rows.map((r) => sanitizeUser(mapUser(r), viewer)),
      activities: aR.rows.map((r) => ({
        id: r.id, title: r.title, unit: r.unit, category: r.category, description: r.description,
        eventDate: r.event_date, eventTime: r.event_time, location: r.location, status: r.status,
        officerReady: r.officer_ready, createdByName: r.created_by_name,
      })),
      broadcasts: bR.rows.map((r) => ({
        id: r.id, title: r.title, airDate: r.air_date, airTime: r.air_time, theme: r.theme,
        presenters: r.presenters, supervisorName: r.supervisor_name, status: r.status,
        officerChecked: r.officer_checked, segments: r.segments || {},
      })),
      disciplineLogs: disR.rows.map((r) => ({
        id: r.id, userId: r.user_id, userName: r.user_name, userCode: r.user_code, unit: r.unit,
        category: r.category, pointsDelta: r.points_delta, note: r.note,
        recordedByName: r.recorded_by_name, logDate: r.log_date,
      })),
      directives: dirR.rows.map((r) => ({
        id: r.id, title: r.title, content: r.content, targetUnit: r.target_unit,
        priority: r.priority, issuedByName: r.issued_by_name, issuedByRole: r.issued_by_role,
      })),
      submissions: subR.rows.map((r) => ({
        id: r.id, studentId: r.student_id, studentName: r.student_name, studentCode: r.student_code,
        unit: r.unit, title: r.title, details: r.details, activityDate: r.activity_date,
        status: r.status, awardedPoints: r.awarded_points, adminNote: r.admin_note,
        reviewedByName: r.reviewed_by_name,
      })),
      complaints: cmpR.rows.map((r) => ({
        id: r.id, reporterId: r.reporter_id, reporterName: r.reporter_name,
        targetStudentName: r.target_student_name, reason: r.reason, details: r.details,
        status: r.status, adminResponse: r.admin_response,
      })),
      suggestions: sugR.rows.map((r) => ({
        id: r.id, studentId: r.student_id, studentName: r.student_name, title: r.title,
        details: r.details, status: r.status, adminResponse: r.admin_response,
      })),
    });
  } catch {
    res.status(500).json({ error: 'تعذر تحميل البيانات' });
  }
});

app.post('/api/users', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const actor = req.user;
    if (!hasAllSixPerms(actor)) {
      return res.status(403).json({ error: 'الوصول إلى الأفراد والصلاحيات يتطلب امتلاك الصلاحيات الست كاملة' });
    }
    const { fullName, loginCode, role, unit, phone, gradeOrDept, permissions } = req.body || {};
    const targetRole = ALLOWED_ROLES.includes(role) ? role : 'member';

    if (targetRole === 'president' && !isSupremePresident(actor)) {
      return res.status(403).json({ error: 'منح رتبة رئيس النشاط مخصص للرئيس عبدالرحمن نسيم فقط' });
    }
    if (!String(fullName || '').trim() || !String(loginCode || '').trim() || !String(phone || '').trim()) {
      return res.status(400).json({ error: 'يرجى إدخال الاسم الكامل ورقم الجوال ورمز الدخول' });
    }

    const cleanCode = String(loginCode).trim();
    const rand = Math.floor(1000 + Math.random() * 9000);
    const memberCode = `${targetRole === 'member' ? 'STD' : 'ADM'}-${rand}`;
    const username = `user_${cleanCode}`.toLowerCase();
    const hash = bcrypt.hashSync(cleanCode, 10);
    const targetUnit = unit || 'activity_1';
    const parsedPerms = sanitizePermissions(permissions) || DEFAULT_ROLE_PERMISSIONS[targetRole];

    if (!isNeon) {
      const db = readLocal();
      if (db.users.some((u) => u.loginCode === cleanCode)) {
        return res.status(400).json({ error: 'رمز الدخول مستخدم مسبقاً' });
      }
      db.counters.users += 1;
      const created = {
        id: db.counters.users,
        memberCode,
        loginCode: cleanCode,
        username,
        fullName: fullName.trim(),
        passwordHash: hash,
        role: targetRole,
        unit: targetUnit,
        phone: phone.trim(),
        gradeOrDept: String(gradeOrDept || '').trim(),
        points: targetRole === 'member' ? 0 : 90,
        isActive: true,
        permissions: parsedPerms,
        createdAt: new Date().toISOString(),
      };
      db.users.push(created);
      writeLocal(db);
      return res.status(201).json({ user: sanitizeUser(created) });
    }

    const exists = await getPool().query('SELECT 1 FROM users WHERE login_code=$1', [cleanCode]);
    if (exists.rowCount > 0) return res.status(400).json({ error: 'رمز الدخول مستخدم مسبقاً' });

    const r = await getPool().query(
      `INSERT INTO users (member_code, login_code, username, full_name, password_hash, role, unit, phone, grade_or_dept, points, is_active, permissions)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,$11::jsonb) RETURNING *`,
      [
        memberCode, cleanCode, username, fullName.trim(), hash, targetRole, targetUnit,
        phone.trim(), String(gradeOrDept || '').trim(), targetRole === 'member' ? 0 : 90,
        JSON.stringify(parsedPerms),
      ]
    );
    res.status(201).json({ user: sanitizeUser(mapUser(r.rows[0])) });
  } catch (e) {
    res.status(400).json({ error: e.message || 'تعذر إضافة الحساب' });
  }
});

app.patch('/api/users/:id', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const actor = req.user;
    if (!hasAllSixPerms(actor)) {
      return res.status(403).json({ error: 'تعديل الأفراد والصلاحيات يتطلب امتلاك الصلاحيات الست كاملة' });
    }

    const id = Number(req.params.id);
    const target = await findUserById(id);
    if (!target) return res.status(404).json({ error: 'المستخدم غير موجود' });

    const { fullName, loginCode, role, unit, phone, gradeOrDept, points, isActive, permissions } = req.body || {};
    const actorIsSupreme = isSupremePresident(actor);
    const targetIsSupreme = isSupremePresident(target);

    if (targetIsSupreme) {
      if (!actorIsSupreme) {
        return res.status(403).json({ error: 'حساب الرئيس عبدالرحمن نسيم محمي ولا يمكن لأي رئيس أو مستخدم آخر تعديله' });
      }
      if ((role !== undefined && role !== 'president') || (unit !== undefined && unit !== target.unit) || isActive === false) {
        return res.status(403).json({ error: 'رتبة الرئيس عبدالرحمن نسيم ثابتة ولا يمكن خفضها أو إيقافها' });
      }
    }

    if (target.role === 'president' && !targetIsSupreme && !actorIsSupreme) {
      return res.status(403).json({ error: 'تعديل حسابات رؤساء النشاط مخصص للرئيس عبدالرحمن نسيم فقط' });
    }

    if (role === 'president' && !actorIsSupreme) {
      return res.status(403).json({ error: 'منح رتبة رئيس النشاط مخصص للرئيس عبدالرحمن نسيم فقط' });
    }
    if (role && !ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ error: 'رتبة غير صالحة' });
    }

    let cleanCode;
    if (loginCode !== undefined) {
      cleanCode = String(loginCode).trim();
      if (!cleanCode) return res.status(400).json({ error: 'رمز الدخول لا يمكن أن يكون فارغاً' });
      const existingCode = await findUserByLoginCode(cleanCode);
      if (existingCode && existingCode.id !== id) {
        return res.status(400).json({ error: 'رمز الدخول مستخدم لحساب آخر بالفعل' });
      }
    }
    if (phone !== undefined && !String(phone).trim()) {
      return res.status(400).json({ error: 'رقم الجوال مطلوب' });
    }

    const parsedPerms = targetIsSupreme ? [...ALL_PERMISSIONS] : sanitizePermissions(permissions);
    const safePoints = points !== undefined && Number.isFinite(Number(points))
      ? Math.max(0, Math.round(Number(points)))
      : undefined;

    if (!isNeon) {
      const db = readLocal();
      const idx = db.users.findIndex((u) => u.id === id);
      if (idx === -1) return res.status(404).json({ error: 'المستخدم غير موجود' });
      const u = db.users[idx];
      if (fullName !== undefined && String(fullName).trim()) u.fullName = String(fullName).trim();
      if (cleanCode !== undefined) u.loginCode = cleanCode;
      if (phone !== undefined) u.phone = String(phone).trim();
      if (gradeOrDept !== undefined) u.gradeOrDept = String(gradeOrDept).trim();
      if (safePoints !== undefined) u.points = safePoints;
      if (!targetIsSupreme) {
        if (role !== undefined) u.role = role;
        if (unit !== undefined) u.unit = unit;
        if (isActive !== undefined) u.isActive = Boolean(isActive);
        if (parsedPerms !== undefined) u.permissions = parsedPerms;
      } else {
        u.permissions = [...ALL_PERMISSIONS];
      }
      writeLocal(db);
      return res.json({ user: sanitizeUser(u) });
    }

    const r = await getPool().query(
      `UPDATE users SET
        full_name = COALESCE($1, full_name),
        login_code = COALESCE($2, login_code),
        role = COALESCE($3, role),
        unit = COALESCE($4, unit),
        phone = COALESCE($5, phone),
        grade_or_dept = COALESCE($6, grade_or_dept),
        points = COALESCE($7, points),
        is_active = COALESCE($8, is_active),
        permissions = COALESCE($9::jsonb, permissions)
       WHERE id = $10 RETURNING *`,
      [
        fullName !== undefined && String(fullName).trim() ? String(fullName).trim() : null,
        cleanCode ?? null,
        !targetIsSupreme && role !== undefined ? role : null,
        !targetIsSupreme && unit !== undefined ? unit : null,
        phone !== undefined ? String(phone).trim() : null,
        gradeOrDept !== undefined ? String(gradeOrDept).trim() : null,
        safePoints ?? null,
        !targetIsSupreme && isActive !== undefined ? Boolean(isActive) : null,
        !targetIsSupreme && parsedPerms !== undefined ? JSON.stringify(parsedPerms) : null,
        id,
      ]
    );
    res.json({ user: sanitizeUser(mapUser(r.rows[0])) });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث الحساب' });
  }
});

app.delete('/api/users/:id', requireAuth, async (req, res) => {
  try {
    const actor = req.user;
    const actorIsSupreme = isSupremePresident(actor);
    if (!hasAllSixPerms(actor) || (!actorIsSupreme && actor.role !== 'president')) {
      return res.status(403).json({ error: 'الحذف مخصص لرئيس النشاط المكتمل الصلاحيات فقط' });
    }
    const id = Number(req.params.id);
    if (id === actor.id) return res.status(400).json({ error: 'لا يمكن حذف الحساب المسجل حالياً' });
    const target = await findUserById(id);
    if (!target) return res.status(404).json({ error: 'الحساب غير موجود' });
    if (isSupremePresident(target)) {
      return res.status(403).json({ error: 'حساب الرئيس عبدالرحمن نسيم محمي ولا يمكن حذفه' });
    }
    if (target.role === 'president' && !actorIsSupreme) {
      return res.status(403).json({ error: 'حذف رئيس نشاط آخر مخصص للرئيس عبدالرحمن نسيم فقط' });
    }
    if (!isNeon) {
      const db = readLocal();
      db.users = db.users.filter((u) => u.id !== id);
      writeLocal(db);
      return res.json({ ok: true });
    }
    await getPool().query('DELETE FROM users WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف الحساب' });
  }
});

app.post('/api/submissions', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const { title, details, unit } = req.body || {};
    if (!String(title || '').trim()) return res.status(400).json({ error: 'يرجى كتابة عنوان الإنجاز' });
    const activityDate = new Date().toISOString().slice(0, 10);
    const subUnit = unit || u.unit || 'activity_1';

    if (!isNeon) {
      const db = readLocal();
      db.counters.submissions += 1;
      const item = {
        id: db.counters.submissions, studentId: u.id, studentName: u.fullName, studentCode: u.memberCode,
        unit: subUnit, title: title.trim(), details: String(details || '').trim(), activityDate,
        status: 'pending', awardedPoints: 0, adminNote: '', reviewedByName: null,
      };
      db.submissions.unshift(item);
      writeLocal(db);
      return res.status(201).json({ submission: item });
    }
    const r = await getPool().query(
      `INSERT INTO submissions (student_id, student_name, student_code, unit, title, details, activity_date)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [u.id, u.fullName, u.memberCode, subUnit, title.trim(), String(details || '').trim(), activityDate]
    );
    const row = r.rows[0];
    res.status(201).json({
      submission: {
        id: row.id, studentId: row.student_id, studentName: row.student_name, studentCode: row.student_code,
        unit: row.unit, title: row.title, details: row.details, activityDate: row.activity_date,
        status: row.status, awardedPoints: row.awarded_points, adminNote: row.admin_note, reviewedByName: row.reviewed_by_name,
      },
    });
  } catch {
    res.status(500).json({ error: 'تعذر إرسال الإنجاز' });
  }
});

app.patch('/api/submissions/:id', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'review_submissions')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية اعتماد الإنجازات' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    const { decision, awardedPoints, adminNote } = req.body || {};
    if (decision !== 'approved' && decision !== 'rejected') {
      return res.status(400).json({ error: 'يرجى اختيار قبول أو رفض' });
    }
    const pts = decision === 'approved' ? Math.max(0, Number(awardedPoints || 0)) : 0;
    const note = String(adminNote || '').trim();

    if (!isNeon) {
      const db = readLocal();
      const sub = db.submissions.find((s) => s.id === id);
      if (!sub) return res.status(404).json({ error: 'التقديم غير موجود' });
      const prevPts = sub.status === 'approved' ? Number(sub.awardedPoints || 0) : 0;
      const diff = pts - prevPts;
      sub.status = decision;
      sub.awardedPoints = pts;
      sub.adminNote = note;
      sub.reviewedByName = req.user.fullName;
      const st = db.users.find((u) => u.id === sub.studentId);
      if (st) st.points = Math.max(0, Number(st.points || 0) + diff);
      writeLocal(db);
      return res.json({ submission: sub });
    }

    const p = getPool();
    const prevR = await p.query('SELECT * FROM submissions WHERE id=$1', [id]);
    if (prevR.rowCount === 0) return res.status(404).json({ error: 'التقديم غير موجود' });
    const prev = prevR.rows[0];
    const diff = pts - (prev.status === 'approved' ? Number(prev.awarded_points || 0) : 0);
    const r = await p.query(
      'UPDATE submissions SET status=$1, awarded_points=$2, admin_note=$3, reviewed_by_name=$4 WHERE id=$5 RETURNING *',
      [decision, pts, note, req.user.fullName, id]
    );
    if (diff !== 0) {
      await p.query('UPDATE users SET points = GREATEST(0, points + $1) WHERE id=$2', [diff, prev.student_id]);
    }
    const row = r.rows[0];
    res.json({
      submission: {
        id: row.id, studentId: row.student_id, studentName: row.student_name, studentCode: row.student_code,
        unit: row.unit, title: row.title, details: row.details, activityDate: row.activity_date,
        status: row.status, awardedPoints: row.awarded_points, adminNote: row.admin_note, reviewedByName: row.reviewed_by_name,
      },
    });
  } catch {
    res.status(500).json({ error: 'تعذر مراجعة الإنجاز' });
  }
});

app.post('/api/complaints', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const { targetStudentName, reason, details } = req.body || {};
    if (!String(targetStudentName || '').trim() || !String(reason || '').trim()) {
      return res.status(400).json({ error: 'يرجى كتابة اسم الطالب والسبب' });
    }
    if (!isNeon) {
      const db = readLocal();
      db.counters.complaints += 1;
      const item = {
        id: db.counters.complaints, reporterId: u.id, reporterName: u.fullName,
        targetStudentName: targetStudentName.trim(), reason: reason.trim(),
        details: String(details || '').trim(), status: 'new', adminResponse: '',
      };
      db.complaints.unshift(item);
      writeLocal(db);
      return res.status(201).json({ complaint: item });
    }
    const r = await getPool().query(
      `INSERT INTO complaints (reporter_id, reporter_name, target_student_name, reason, details)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [u.id, u.fullName, targetStudentName.trim(), reason.trim(), String(details || '').trim()]
    );
    res.status(201).json({ complaint: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر إرسال الشكوى' });
  }
});

app.patch('/api/complaints/:id', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'review_submissions')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية مراجعة الشكاوى' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    const { status, adminResponse } = req.body || {};
    if (!isNeon) {
      const db = readLocal();
      const item = db.complaints.find((c) => c.id === id);
      if (!item) return res.status(404).json({ error: 'الشكوى غير موجودة' });
      item.status = status || 'resolved';
      item.adminResponse = String(adminResponse || '').trim();
      writeLocal(db);
      return res.json({ complaint: item });
    }
    const r = await getPool().query(
      'UPDATE complaints SET status=$1, admin_response=$2 WHERE id=$3 RETURNING *',
      [status || 'resolved', String(adminResponse || '').trim(), id]
    );
    res.json({ complaint: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث الشكوى' });
  }
});

app.post('/api/suggestions', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const { title, details } = req.body || {};
    if (!String(title || '').trim()) return res.status(400).json({ error: 'يرجى كتابة الاقتراح' });
    if (!isNeon) {
      const db = readLocal();
      db.counters.suggestions += 1;
      const item = {
        id: db.counters.suggestions, studentId: u.id, studentName: u.fullName,
        title: title.trim(), details: String(details || '').trim(), status: 'new', adminResponse: '',
      };
      db.suggestions.unshift(item);
      writeLocal(db);
      return res.status(201).json({ suggestion: item });
    }
    const r = await getPool().query(
      'INSERT INTO suggestions (student_id, student_name, title, details) VALUES ($1,$2,$3,$4) RETURNING *',
      [u.id, u.fullName, title.trim(), String(details || '').trim()]
    );
    res.status(201).json({ suggestion: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر إرسال الاقتراح' });
  }
});

app.patch('/api/suggestions/:id', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'review_submissions')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية مراجعة الاقتراحات' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    const { status, adminResponse } = req.body || {};
    if (!isNeon) {
      const db = readLocal();
      const item = db.suggestions.find((s) => s.id === id);
      if (!item) return res.status(404).json({ error: 'الاقتراح غير موجود' });
      item.status = status || 'reviewed';
      item.adminResponse = String(adminResponse || '').trim();
      writeLocal(db);
      return res.json({ suggestion: item });
    }
    const r = await getPool().query(
      'UPDATE suggestions SET status=$1, admin_response=$2 WHERE id=$3 RETURNING *',
      [status || 'reviewed', String(adminResponse || '').trim(), id]
    );
    res.json({ suggestion: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث الاقتراح' });
  }
});

app.post('/api/broadcasts/generate', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_broadcasts')) {
      return res.status(403).json({ error: 'توليد الإذاعات مخصص لأصحاب صلاحية الإذاعة فقط' });
    }
    const topic = String(req.body?.title || '').trim();
    if (!topic) return res.status(400).json({ error: 'يرجى كتابة عنوان الإذاعة أولاً' });

    const apiKey = (process.env.GROQ_API_KEY || '').trim();
    if (!apiKey) {
      return res.status(400).json({ error: 'مفتاح GROQ_API_KEY غير مضاف في متغيرات البيئة' });
    }

    const prompt = `اكتب إذاعة مدرسية كاملة للمرحلة المتوسطة بعنوان/موضوع: "${topic}"
بنفس الأسلوب والترتيب التالي بالضبط:
1- المقدمة: تبدأ بـ "بسم الله الرحمن الرحيم، والصلاة والسلام على أشرف الأنبياء والمرسلين. مديرنا الفاضل، معلمينا الكرام، زملائي الطلاب، السلام عليكم ورحمة الله وبركاته." ثم تعريف جميل وواضح بموضوع الإذاعة.
2- القرآن الكريم: تبدأ بـ "خير ما نبدأ به إذاعتنا آيات عطرة من القرآن الكريم، يتلوها على مسامعكم الطالب............" ثم آية قرآنية مناسبة وصحيحة للموضوع بين ﴿...﴾.
3- الحديث الشريف: تبدأ بـ "والآن مع الحديث الشريف، يقدمه الطالب..........." ثم حديث نبوي صحيح أو مشهور مناسب للموضوع بين «...».
4- كلمة الصباح: تبدأ بـ "والآن مع كلمة الصباح يقدمها الطالب............" ثم كلمة مفيدة ومبسطة لطلاب المرحلة المتوسطة عن الموضوع.
5- هل تعلم؟: تبدأ بـ "والآن مع فقرة هل تعلم، يقدمها الطالب: (........)." ثم 3 نقاط تبدأ كل نقطة بـ "• هل تعلم أن ...؟".
6- الخاتمة: تبدأ بـ "وفي ختام إذاعتنا المدرسية، ..." مع خلاصة وتوصية وتنتهي بـ "والسلام عليكم ورحمة الله وبركاته."

أعد النتيجة بصيغة JSON فقط بهذا الشكل الدقيق دون أي كلام قبله أو بعده:
{
  "title": "إذاعة مدرسية عن ...",
  "theme": "موضوع مختصر",
  "segments": {
    "intro": "...",
    "quran": "...",
    "hadith": "...",
    "morningWord": "...",
    "didYouKnow": "...",
    "closing": "..."
  }
}`;

    const preferredModels = [
      process.env.GROQ_MODEL?.trim(),
      'llama-3.3-70b-versatile',
      'openai/gpt-oss-120b',
      'meta-llama/llama-4-scout-17b-16e-instruct',
      'llama-3.1-8b-instant',
      'openai/gpt-oss-20b',
      'allam-2-7b',
    ].filter(Boolean);

    let availableIds = [];
    try {
      const modelsRes = await fetch('https://api.groq.com/openai/v1/models', {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      if (modelsRes.ok) {
        const modelsJson = await modelsRes.json();
        availableIds = (modelsJson.data || [])
          .map((m) => m.id)
          .filter((id) => !/whisper|guard|safeguard|orpheus|tts|embed|vision-preview/i.test(id));
      }
    } catch {}

    const candidates = availableIds.length > 0
      ? [...preferredModels.filter((m) => availableIds.includes(m)), ...availableIds.filter((id) => !preferredModels.includes(id))]
      : preferredModels;

    if (candidates.length === 0) {
      return res.status(502).json({ error: 'لا توجد نماذج نصية متاحة في حساب Groq الحالي' });
    }

    let rawContent = '';
    let lastError = 'تعذر الاتصال بخدمة Groq';

    for (const modelId of candidates) {
      for (const useJsonMode of [true, false]) {
        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: modelId,
            temperature: 0.6,
            ...(useJsonMode ? { response_format: { type: 'json_object' } } : {}),
            messages: [
              {
                role: 'system',
                content: 'أنت معد إذاعات مدرسية للمرحلة المتوسطة باللغة العربية الفصحى السليمة. تلتزم بدقة الآيات والأحاديث وتعيد الإخراج بصيغة JSON فقط.',
              },
              { role: 'user', content: prompt },
            ],
          }),
        });
        const data = await groqRes.json().catch(() => ({}));
        if (groqRes.ok && data?.choices?.[0]?.message?.content) {
          rawContent = data.choices[0].message.content;
          break;
        }
        lastError = data?.error?.message || lastError;
        const msg = lastError.toLowerCase();
        if (msg.includes('does not exist') || msg.includes('do not have access') || groqRes.status === 404) break;
      }
      if (rawContent) break;
    }

    if (!rawContent) {
      return res.status(502).json({ error: lastError });
    }
    const jsonMatch = rawContent.match(/\{[\s\S]*\}/);
    const parsed = JSON.parse(jsonMatch ? jsonMatch[0] : rawContent);
    res.json({
      title: parsed.title || `إذاعة مدرسية عن ${topic}`,
      theme: parsed.theme || topic,
      segments: {
        intro: parsed.segments?.intro || '',
        quran: parsed.segments?.quran || '',
        hadith: parsed.segments?.hadith || '',
        morningWord: parsed.segments?.morningWord || '',
        didYouKnow: parsed.segments?.didYouKnow || '',
        closing: parsed.segments?.closing || '',
      },
    });
  } catch {
    res.status(500).json({ error: 'تعذر توليد الإذاعة حالياً' });
  }
});

app.post('/api/broadcasts', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_broadcasts')) {
      return res.status(403).json({ error: 'إضافة الإذاعات مخصصة لأصحاب صلاحية الإذاعة فقط' });
      }
    await ensureReady();
    const { title, airDate, airTime, theme, presenters, segments } = req.body || {};
    if (!title || !airDate || !airTime) return res.status(400).json({ error: 'يرجى إدخال عنوان الإذاعة والتاريخ والوقت' });
    const status = (req.user.role === 'president' || req.user.role === 'vice_president') ? 'approved' : 'pending_approval';
    const segs = {
      intro: segments?.intro || 'بسم الله الرحمن الرحيم، نبدأ معكم إذاعتنا الصباحية.',
      quran: segments?.quran || 'آيات عطرة من القرآن الكريم.',
      hadith: segments?.hadith || 'الحديث الشريف.',
      morningWord: segments?.morningWord || 'كلمة الصباح.',
      didYouKnow: segments?.didYouKnow || 'فقرة هل تعلم.',
      closing: segments?.closing || 'شكراً لحسن استماعكم.',
    };
    if (!isNeon) {
      const db = readLocal();
      db.counters.broadcasts += 1;
      const item = {
        id: db.counters.broadcasts, title: title.trim(), airDate, airTime,
        theme: theme || 'عام', presenters: presenters || req.user.fullName,
        supervisorName: 'الإدارة', status, officerChecked: false, segments: segs,
      };
      db.broadcasts.unshift(item);
      writeLocal(db);
      return res.status(201).json({ broadcast: item });
    }
    const r = await getPool().query(
      `INSERT INTO broadcasts (title, air_date, air_time, theme, presenters, supervisor_name, status, segments)
       VALUES ($1,$2,$3,$4,$5,'الإدارة',$6,$7::jsonb) RETURNING *`,
      [title.trim(), airDate, airTime, theme || 'عام', presenters || req.user.fullName, status, JSON.stringify(segs)]
    );
    res.status(201).json({ broadcast: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر حفظ الإذاعة' });
  }
});

app.patch('/api/broadcasts/:id', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const user = req.user;
    if (!hasPerm(user, 'manage_broadcasts')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية تعديل الإذاعة' });
    }
    const id = Number(req.params.id);
    const { title, airDate, airTime, theme, presenters, status, officerChecked, segments } = req.body || {};

    if (!isNeon) {
      const db = readLocal();
      const item = db.broadcasts.find((b) => b.id === id);
      if (!item) return res.status(404).json({ error: 'الإذاعة غير موجودة' });
      if (title !== undefined) item.title = String(title).trim();
      if (airDate !== undefined) item.airDate = airDate;
      if (airTime !== undefined) item.airTime = airTime;
      if (theme !== undefined) item.theme = String(theme).trim();
      if (presenters !== undefined) item.presenters = String(presenters).trim();
      if (status !== undefined) item.status = status;
      if (officerChecked !== undefined) item.officerChecked = Boolean(officerChecked);
      if (segments && typeof segments === 'object') {
        item.segments = { ...(item.segments || {}), ...segments };
      }
      writeLocal(db);
      return res.json({ broadcast: item });
    }
    const prevR = await getPool().query('SELECT segments FROM broadcasts WHERE id=$1', [id]);
    if (prevR.rowCount === 0) return res.status(404).json({ error: 'الإذاعة غير موجودة' });
    const mergedSegs = segments && typeof segments === 'object'
      ? { ...(prevR.rows[0].segments || {}), ...segments }
      : null;

    const r = await getPool().query(
      `UPDATE broadcasts SET
        title = COALESCE($1, title),
        air_date = COALESCE($2, air_date),
        air_time = COALESCE($3, air_time),
        theme = COALESCE($4, theme),
        presenters = COALESCE($5, presenters),
        status = COALESCE($6, status),
        officer_checked = COALESCE($7, officer_checked),
        segments = COALESCE($8::jsonb, segments)
       WHERE id=$9 RETURNING *`,
      [
        title !== undefined ? String(title).trim() : null,
        airDate ?? null,
        airTime ?? null,
        theme !== undefined ? String(theme).trim() : null,
        presenters !== undefined ? String(presenters).trim() : null,
        status ?? null,
        officerChecked !== undefined ? Boolean(officerChecked) : null,
        mergedSegs ? JSON.stringify(mergedSegs) : null,
        id,
      ]
    );
    res.json({ broadcast: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث الإذاعة' });
  }
});

app.delete('/api/broadcasts/:id', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_broadcasts')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية حذف الإذاعة' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    if (!isNeon) {
      const db = readLocal();
      db.broadcasts = db.broadcasts.filter((b) => b.id !== id);
      writeLocal(db);
      return res.json({ ok: true });
    }
    await getPool().query('DELETE FROM broadcasts WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف الإذاعة' });
  }
});

app.post('/api/activities', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_activities')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية إضافة البرامج والأنشطة' });
    }
    await ensureReady();
    const { title, unit, category, description, eventDate, eventTime, location } = req.body || {};
    if (!title || !unit || !eventDate) return res.status(400).json({ error: 'يرجى إكمال بيانات البرنامج' });
    if (!isNeon) {
      const db = readLocal();
      db.counters.activities += 1;
      const item = {
        id: db.counters.activities, title: title.trim(), unit, category: category || 'عام',
        description: description || '', eventDate, eventTime: eventTime || '09:30',
        location: location || 'المدرسة', status: 'approved', officerReady: true, createdByName: req.user.fullName,
      };
      db.activities.unshift(item);
      writeLocal(db);
      return res.status(201).json({ activity: item });
    }
    const r = await getPool().query(
      `INSERT INTO activities (title, unit, category, description, event_date, event_time, location, status, officer_ready, created_by_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'approved',TRUE,$8) RETURNING *`,
      [title.trim(), unit, category || 'عام', description || '', eventDate, eventTime || '09:30', location || 'المدرسة', req.user.fullName]
    );
    res.status(201).json({ activity: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر إضافة البرنامج' });
  }
});

app.delete('/api/activities/:id', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_activities')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية حذف البرامج والأنشطة' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    if (!isNeon) {
      const db = readLocal();
      db.activities = db.activities.filter((a) => a.id !== id);
      writeLocal(db);
      return res.json({ ok: true });
    }
    await getPool().query('DELETE FROM activities WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف البرنامج' });
  }
});

app.post('/api/discipline', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_discipline')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية تسجيل الانضباط والنقاط' });
    }
    await ensureReady();
    const { userId, category, pointsDelta, note } = req.body || {};
    const target = await findUserById(userId);
    if (!target || !note) return res.status(400).json({ error: 'يرجى اختيار الطالب وكتابة الملاحظة' });
    const delta = Number(pointsDelta || 0);
    const logDate = new Date().toISOString().slice(0, 10);

    if (!isNeon) {
      const db = readLocal();
      db.counters.discipline += 1;
      const item = {
        id: db.counters.discipline, userId: target.id, userName: target.fullName, userCode: target.memberCode,
        unit: target.unit, category: category || 'commendation', pointsDelta: delta, note: note.trim(),
        recordedByName: req.user.fullName, logDate,
      };
      db.disciplineLogs.unshift(item);
      const u = db.users.find((x) => x.id === target.id);
      if (u) u.points = Math.max(0, Number(u.points || 0) + delta);
      writeLocal(db);
      return res.status(201).json({ log: item });
    }
    const p = getPool();
    const r = await p.query(
      `INSERT INTO discipline_logs (user_id, user_name, user_code, unit, category, points_delta, note, recorded_by_name, log_date)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [target.id, target.fullName, target.memberCode, target.unit, category || 'commendation', delta, note.trim(), req.user.fullName, logDate]
    );
    await p.query('UPDATE users SET points = GREATEST(0, points + $1) WHERE id=$2', [delta, target.id]);
    res.status(201).json({ log: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر تسجيل الملاحظة' });
  }
});

app.delete('/api/discipline/:id', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_discipline')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية حذف سجلات الانضباط' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    if (!isNeon) {
      const db = readLocal();
      const target = db.disciplineLogs.find((l) => l.id === id);
      if (!target) return res.status(404).json({ error: 'السجل غير موجود' });
      const u = db.users.find((x) => x.id === target.userId);
      if (u) u.points = Math.max(0, Number(u.points || 0) - Number(target.pointsDelta || 0));
      db.disciplineLogs = db.disciplineLogs.filter((l) => l.id !== id);
      writeLocal(db);
      return res.json({ ok: true });
    }
    const p = getPool();
    const prev = await p.query('SELECT user_id, points_delta FROM discipline_logs WHERE id=$1', [id]);
    if (prev.rowCount === 0) return res.status(404).json({ error: 'السجل غير موجود' });
    await p.query('DELETE FROM discipline_logs WHERE id=$1', [id]);
    await p.query('UPDATE users SET points = GREATEST(0, points - $1) WHERE id=$2', [prev.rows[0].points_delta, prev.rows[0].user_id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف السجل' });
  }
});

app.post('/api/directives', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'issue_directives')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية إصدار التوجيهات' });
    }
    await ensureReady();
    const { title, content, priority } = req.body || {};
    if (!title || !content) return res.status(400).json({ error: 'يرجى كتابة العنوان والنص' });
    if (!isNeon) {
      const db = readLocal();
      db.counters.directives += 1;
      const item = {
        id: db.counters.directives, title: title.trim(), content: content.trim(), targetUnit: 'all',
        priority: priority || 'normal', issuedByName: req.user.fullName, issuedByRole: req.user.role,
      };
      db.directives.unshift(item);
      writeLocal(db);
      return res.status(201).json({ directive: item });
    }
    const r = await getPool().query(
      `INSERT INTO directives (title, content, target_unit, priority, issued_by_name, issued_by_role)
       VALUES ($1,$2,'all',$3,$4,$5) RETURNING *`,
      [title.trim(), content.trim(), priority || 'normal', req.user.fullName, req.user.role]
    );
    res.status(201).json({ directive: r.rows[0] });
  } catch {
    res.status(500).json({ error: 'تعذر نشر التوجيه' });
  }
});

app.delete('/api/directives/:id', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'issue_directives')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية حذف التوجيهات' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    if (!isNeon) {
      const db = readLocal();
      db.directives = db.directives.filter((d) => d.id !== id);
      writeLocal(db);
      return res.json({ ok: true });
    }
    await getPool().query('DELETE FROM directives WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف التوجيه' });
  }
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Student Activity System running on port ${PORT}`);
});
