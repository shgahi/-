import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { WebSocketServer, WebSocket } from 'ws';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'student-activity-dev-secret-change-in-prod';
const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const isNeon = Boolean(DATABASE_URL);
const DB_FILE = path.join(__dirname, 'activity-db.json');

const MANAGEMENT_ROLES = ['president', 'vice_president'];
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
  officer: [],
  member: [],
};

const isMgmt = (role) => MANAGEMENT_ROLES.includes(role);
const isSupremePresident = (user) => Boolean(user && user.username === 'president');
const canModerateChat = (user) =>
  Boolean(user && (isSupremePresident(user) || user.role === 'vice_president'));
const CHAT_RETENTION_HOURS = 48;
const CHAT_RETENTION_MS = CHAT_RETENTION_HOURS * 60 * 60 * 1000;
const MAX_CHAT_IMAGE_CHARS = 2_000_000;
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

const ALLOWED_BADGE_TONES = ['emerald', 'gold', 'sky', 'indigo', 'teal', 'rose'];
const ALLOWED_BADGE_ICONS = ['star', 'heart', 'sparkles', 'mic', 'crown', 'shield', 'book'];
function parseBadgesJson(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}
function computeLeaderboard(users, submissions) {
  const approvedCounts = new Map();
  for (const s of submissions || []) {
    if (s.status === 'approved') {
      const sid = Number(s.studentId ?? s.student_id);
      approvedCounts.set(sid, (approvedCounts.get(sid) || 0) + 1);
    }
  }
  const ranked = (users || [])
    .filter((u) => !isMgmt(u.role) && Boolean(u.isActive ?? u.is_active ?? true))
    .sort((a, b) => {
      const ptsDiff = Number(b.points || 0) - Number(a.points || 0);
      if (ptsDiff !== 0) return ptsDiff;
      const appDiff = (approvedCounts.get(b.id) || 0) - (approvedCounts.get(a.id) || 0);
      if (appDiff !== 0) return appDiff;
      return a.id - b.id;
    });
  return ranked.map((u, idx) => ({
    id: u.id,
    rank: idx + 1,
    fullName: u.fullName ?? u.full_name,
    memberCode: u.memberCode ?? u.member_code,
    role: u.role,
    unit: u.unit,
    gradeOrDept: u.gradeOrDept ?? u.grade_or_dept ?? '',
    points: Number(u.points || 0),
    approvedCount: approvedCounts.get(u.id) || 0,
    badges: parseBadgesJson(u.badges ?? u.badges_json),
  }));
}

// ===== الشهادات — الدوال والمسارات =====
const ALLOWED_CERT_TEMPLATES = ['emerald_gold', 'royal_navy', 'classic_brass'];
const mapCertificate = (r) => ({
  id: r.id,
  studentId: r.student_id !== undefined ? r.student_id : (r.studentId ?? null),
  recipientName: r.recipient_name || r.recipientName || '',
  gradeOrTitle: r.grade_or_title || r.gradeOrTitle || '',
  certificateType: r.certificate_type || r.certificateType || 'شهادة شكر وتقدير',
  reason: r.reason || '',
  schoolName: r.school_name || r.schoolName || 'مدرسة الحديبية المتوسطة',
  issuerTitle: r.issuer_title || r.issuerTitle || 'رئيس النشاط الطلابي',
  issuerName: r.issuer_name || r.issuerName || '',
  principalName: r.principal_name || r.principalName || '',
  issueDate: r.issue_date || r.issueDate || '',
  templateStyle: ALLOWED_CERT_TEMPLATES.includes(r.template_style || r.templateStyle)
    ? (r.template_style || r.templateStyle)
    : 'emerald_gold',
  createdById: Number(r.created_by_id || r.createdById || 0),
  createdByName: r.created_by_name || r.createdByName || '',
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : (r.createdAt || undefined),
});

function formatBroadcastSegmentSpacing(text) {
  const normalized = String(text ?? '').replace(/\r\n/g, '\n').trim();
  if (!normalized) return '';
  const splitInline = normalized.replace(
    /(الطالب[^\n]*?(?:\.{2,}|\([^\)]*\)|\.|:))[ \t]+([^\n]+)/g,
    '$1\n\n$2'
  );
  const lines = splitInline.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    out.push(lines[i]);
    const hasNextNonEmpty = i + 1 < lines.length && lines[i + 1].trim() !== '';
    if (/الطالب/.test(lines[i]) && hasNextNonEmpty) {
      out.push('');
    }
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim();
}

function buildFallbackReportContent(title, executors) {
  const cleanTitle = String(title || '').trim();
  const cleanExec = String(executors || '').trim() || 'إدارة النشاط الطلابي';
  const t = cleanTitle;

  if (/بركان|براكين|تفاعل|كيمياء|فيزياء|مختبر|تجرب|محلول|علوم|ذرة|كهرباء/.test(t)) {
    return {
      field: 'المختبر',
      beneficiaries: 'الطلاب',
      beneficiariesCount: 'اقل من 70 طالب',
      steps: [
        `1- تجهيز أدوات وتجارب برنامج «${cleanTitle}» داخل المختبر ومراعاة وسائل السلامة بإشراف ${cleanExec}.`,
        `2- شرح المفهوم العلمي لـ«${cleanTitle}» وربطه بالظواهر الواقعية للطلاب.`,
        `3- تنفيذ التطبيق العملي أمام الطلاب وإتاحة الفرصة للمجموعات للمشاركة والملاحظة.`,
        `4- مناقشة النتائج العلمية وتدوين الاستنتاجات وتوثيق التجربة بالشواهد.`,
      ],
      objectives: [
        `1- فهم واستيعاب المفاهيم والظواهر المرتبطة بـ«${cleanTitle}» بصورة عملية.`,
        `2- تطبيق المنهج العلمي والتعلم بالتجربة والملاحظة المباشرة.`,
        `3- تنمية مهارات التفكير العلمي وطرح التساؤلات لدى الطلاب.`,
        `4- تعزيز العمل الجماعي والفضول العلمي وحب الاستكشاف.`,
      ],
    };
  }
  if (/قرآن|حديث|صلاة|أخلاق|قيم|سيرة|توعية إسلام|مصلى|رمضان|حج|فقه|عقيدة/.test(t)) {
    return {
      field: 'القيمي والإسلامي',
      beneficiaries: 'الطلاب',
      beneficiariesCount: 'اقل من 70 طالب',
      steps: [
        `1- الإعداد التربوي لبرنامج «${cleanTitle}» وتجهيز المحتوى القيمي بإشراف ${cleanExec}.`,
        `2- افتتاح اللقاء بتلاوة عطرة وتقديم محاور «${cleanTitle}» بأسلوب مؤثر وقريب من الطلاب.`,
        `3- إشراك الطلاب في قراءة النصوص والمواقف التربوية وتطبيقها في السلوك اليومي.`,
        `4- تلخيص الرسائل القيمية وتكريم الطلاب المتميزين وتوثيق التنفيذ.`,
      ],
      objectives: [
        `1- ترسيخ القيم الإسلامية والأخلاقية المستفادة من «${cleanTitle}» في نفوس الطلاب.`,
        `2- تعزيز الوعي الديني والانضباط السلوكي داخل المدرسة وخارجها.`,
        `3- تنمية الاعتزاز بالهوية الإسلامية والاقتداء بالهدي النبوي.`,
        `4- تشجيع المبادرات الإيجابية والعمل الصالح بين طلاب المدرسة.`,
      ],
    };
  }
  if (/رياض|قدم|سلة|طائرة|تنس|بطولة|دوري|لياقة|ماراثون|مشي|جري|سباق/.test(t)) {
    return {
      field: 'الرياضي',
      beneficiaries: 'الطلاب',
      beneficiariesCount: 'اقل من 70 طالب',
      steps: [
        `1- الإعلان عن برنامج «${cleanTitle}» وتجهيز الملعب والأدوات الرياضية بإشراف ${cleanExec}.`,
        `2- تقسيم الفرق المشاركة وتوضيح القوانين واللوائح التنظيمية للطلاب.`,
        `3- إجراء التمارين التحضيرية وانطلاق منافسات «${cleanTitle}» بروح رياضية.`,
        `4- حصر النتائج النهائية وتشجيع الفائزين وتوثيق الفعالية بالشواهد.`,
      ],
      objectives: [
        `1- تعزيز اللياقة البدنية والاهتمام بالصحة العامة لدى الطلاب عبر «${cleanTitle}».`,
        `2- غرس قيم التنافس الشريف والروح الرياضية واحترام الأنظمة.`,
        `3- اكتشاف المواهب الرياضية الطلابية وصقل قدراتها داخل المدرسة.`,
        `4- تنمية روح الفريق والتعاون الإيجابي بين طلاب الفصول.`,
      ],
    };
  }
  if (/صحة|سمنة|تغذية|أسنان|نظافة|إسعاف|دم|سلامة|مرور|وقاية|مكافحة|تدخين|أمن/.test(t)) {
    return {
      field: 'التوعوي والصحي',
      beneficiaries: 'الطلاب',
      beneficiariesCount: 'اقل من 70 طالب',
      steps: [
        `1- إعداد المادة التوعوية والوسائل الإيضاحية لبرنامج «${cleanTitle}» بقيادة ${cleanExec}.`,
        `2- تنفيذ اللقاء التوعوي وتوضيح أبرز المخاطر والسلوكيات الوقائية المرتبطة بـ«${cleanTitle}».`,
        `3- فتح باب النقاش والإجابة عن استفسارات الطلاب وعرض نماذج إرشادية.`,
        `4- توزيع التوصيات التوعوية وتوثيق أثر البرنامج بالشواهد المصورة.`,
      ],
      objectives: [
        `1- رفع مستوى الوعي الصحي والوقائي لدى الطلاب حول موضوع «${cleanTitle}».`,
        `2- إكساب الطلاب عادات وسلوكيات سليمة تحافظ على سلامتهم اليومية.`,
        `3- تعزيز المسؤولية الفردية تجاه الصحة والسلامة المدرسية.`,
        `4- تمكين الطلاب من نقل الرسائل الإيجابية لزملائهم وأسرهم.`,
      ],
    };
  }
  if (/برمجة|تقنية|روبوت|حاسب|ذكاء|رقمي|أمن سيبراني|تصميم|تطبيق/.test(t)) {
    return {
      field: 'التقني والرقمي',
      beneficiaries: 'الطلاب',
      beneficiariesCount: 'اقل من 70 طالب',
      steps: [
        `1- تجهيز معمل الحاسب والأدوات الرقمية اللازمة لتنفيذ «${cleanTitle}» بإشراف ${cleanExec}.`,
        `2- تقديم شرح تطبيقي لأساسيات ومهارات «${cleanTitle}» بخطوات مبسطة.`,
        `3- تطبيق الطلاب للتدريبات العملية وبناء نماذج أولية وتبادل الخبرات.`,
        `4- استعراض منجزات الطلاب وتقديم التغذية الراجعة وتوثيق الشواهد.`,
      ],
      objectives: [
        `1- تنمية المهارات الرقمية والتقنية الحديثة لدى الطلاب في مجال «${cleanTitle}».`,
        `2- تعزيز التفكير الإبداعي وحل المشكلات بأسلوب تقني منظم.`,
        `3- تهيئة الطلاب للتعامل الواعي والآمن مع التقنية المعاصرة.`,
        `4- تشجيع الابتكار وبناء المشاريع الطلابية التطبيقية.`,
      ],
    };
  }
  return {
    field: /كشف|انضباط|وطن|بيئة|تطوع|شراكة|أسر/.test(t) ? 'الاجتماعي والوطني' : 'الثقافي',
    beneficiaries: 'الطلاب',
    beneficiariesCount: 'اقل من 70 طالب',
    steps: [
      `1- التخطيط المسبق لبرنامج «${cleanTitle}» وتحديد الأدوار ومحاور العرض بإشراف ${cleanExec}.`,
      `2- تهيئة مقر التنفيذ وتجهيز الوسائل واللوحات الداعمة لموضوع «${cleanTitle}».`,
      `3- تقديم فقرات البرنامج وتفعيل مشاركة الطلاب من خلال الحوار والتطبيق العملي.`,
      `4- تلخيص أبرز المخرجات وتكريم المشاركين وتوثيق الفعالية بالصور.`,
    ],
    objectives: [
      `1- تعزيز معرفة الطلاب ووعيهم بمحاور برنامج «${cleanTitle}».`,
      `2- تنمية مهارات الإلقاء والتفاعل الإيجابي والمشاركة الطلابية الفاعلة.`,
      `3- إثراء البيئة المدرسية ببرامج ثقافية وتربوية جاذبة ومنظمة.`,
      `4- دعم بناء شخصية الطالب المتوازنة وتعزيز الانتماء للمدرسة والمجتمع.`,
    ],
  };
}

async function generateProgramReportWithAI(title, executors, executionDate) {
  const cleanTitle = String(title || '').trim();
  const cleanExec = String(executors || '').trim() || 'إدارة النشاط الطلابي';
  const fallback = buildFallbackReportContent(cleanTitle, cleanExec);

  if (!(process.env.GROQ_API_KEY || '').trim()) {
    return { ...fallback, source: 'template' };
  }
  try {
    const prompt = `بصفتك خبير نشاط طلابي في وزارة التعليم السعودية، أنشئ بيانات تقرير لبرنامج مدرسي بعنوان: "${cleanTitle}"
المنفذون: "${cleanExec}"
تاريخ التنفيذ: "${String(executionDate || '').trim() || 'اليوم'}"

المطلوب استنتاج التالي بدقة عالية من اسم البرنامج "${cleanTitle}" فقط:
1) مجال البرنامج ("field"): اختر المجال التربوي الأدق لهذا العنوان من كلمة أو كلمتين مثل: (المختبر، العلمي، الثقافي، الرياضي، التوعوي والصحي، القيمي والإسلامي، التقني والرقمي، الكشفي، الاجتماعي، الفني).
2) خطوات التنفيذ ("steps"): اكتب 4 إلى 6 خطوات واقعية ومحددة جداً لطريقة تنفيذ "${cleanTitle}" نفسه ولا تكتب خطوات عامة مكررة.
3) الأهداف ("objectives"): اكتب 4 أهداف تربوية دقيقة مرتبطة مباشرة بـ "${cleanTitle}".

أعد JSON فقط دون أي نص قبله أو بعده:
{
  "field": "مجال البرنامج المناسب للعنوان",
  "beneficiaries": "الطلاب",
  "beneficiariesCount": "اقل من 70 طالب",
  "steps": ["1- ...", "2- ...", "3- ...", "4- ..."],
  "objectives": ["1- ...", "2- ...", "3- ...", "4- ..."]
}`;
    const parsed = await runGroqJsonPrompt(
      'أنت منسق نشاط طلابي في وزارة التعليم السعودية وتعد تقارير البرامج والشواهد الرسمية بصيغة JSON فقط.',
      prompt
    );
    return {
      field: String(parsed.field || '').trim() || fallback.field,
      beneficiaries: String(parsed.beneficiaries || '').trim() || fallback.beneficiaries,
      beneficiariesCount: String(parsed.beneficiariesCount || '').trim() || fallback.beneficiariesCount,
      steps: Array.isArray(parsed.steps) && parsed.steps.length ? parsed.steps.map((s) => String(s).trim()).filter(Boolean) : fallback.steps,
      objectives: Array.isArray(parsed.objectives) && parsed.objectives.length ? parsed.objectives.map((o) => String(o).trim()).filter(Boolean) : fallback.objectives,
      source: 'groq',
    };
  } catch {
    return { ...fallback, source: 'template' };
  }
}


async function runGroqJsonPrompt(systemPrompt, userPrompt) {
  const apiKey = (process.env.GROQ_API_KEY || '').trim();
  if (!apiKey) throw new Error('NO_GROQ_KEY');

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

  if (candidates.length === 0) throw new Error('لا توجد نماذج نصية متاحة في حساب Groq الحالي');

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
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
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

  if (!rawContent) throw new Error(lastError);
  const jsonMatch = rawContent.match(/\{[\s\S]*\}/);
  return JSON.parse(jsonMatch ? jsonMatch[0] : rawContent);
}

function normalizeLoginCode(raw) {
  return String(raw ?? '')
    .replace(/[٠-٩]/g, (d) => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
    .replace(/[۰-۹]/g, (d) => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d)))
    .replace(/\s+/g, '')
    .trim();
}

function buildPgPoolConfig(rawUrl) {
  const cleaned = String(rawUrl || '')
    .trim()
    .replace(/^psql\s+/i, '')
    .replace(/^['"]|['"]$/g, '')
    .trim();
  try {
    const parsed = new URL(cleaned);
    const sslmode = (parsed.searchParams.get('sslmode') || '').toLowerCase();
    const isLocalHost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    parsed.searchParams.delete('sslmode');
    parsed.searchParams.delete('uselibpqcompat');
    parsed.searchParams.delete('channel_binding');
    const ssl =
      sslmode === 'disable' || isLocalHost
        ? false
        : sslmode === 'verify-full'
          ? { rejectUnauthorized: true }
          : { rejectUnauthorized: false };
    return {
      connectionString: parsed.toString(),
      ssl,
      max: 10,
      connectionTimeoutMillis: 15000,
    };
  } catch {
    const disableSsl = cleaned.includes('sslmode=disable');
    return {
      connectionString: cleaned,
      ssl: disableSsl ? false : { rejectUnauthorized: false },
      max: 10,
      connectionTimeoutMillis: 15000,
    };
  }
}

let pool = null;
function getPool() {
  if (!pool && DATABASE_URL) {
    pool = new Pool(buildPgPoolConfig(DATABASE_URL));
    pool.on('error', (err) => {
      console.error('Unexpected PostgreSQL pool error:', err);
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
      tasks: 0,
      broadcasts: 1,
      discipline: 0,
      directives: 1,
      submissions: 0,
      complaints: 0,
      suggestions: 0,
      programReports: 0,
      certificates: 0,
      chatMessages: 0,
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
        title: 'رئيس النشاط الطلابي',
        phone: '0551001001',
        gradeOrDept: 'الإدارة العليا',
        points: 100,
        isActive: true,
        permissions: [...ALL_PERMISSIONS],
        badges: [],
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
        title: 'نائب رئيس النشاط الطلابي',
        phone: '0551001002',
        gradeOrDept: 'الإدارة العليا',
        points: 96,
        isActive: true,
        permissions: [...ALL_PERMISSIONS],
        badges: [],
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
        targetAudience: 'جميع الطلاب',
        status: 'approved',
        officerReady: true,
        officerNote: '',
        createdById: 1,
        createdByName: 'عبدالرحمن نسيم',
        approvedByName: 'عبدالرحمن نسيم',
        participantsCount: 0,
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
        targetAudience: 'جميع الطلاب',
        status: 'approved',
        officerReady: true,
        officerNote: '',
        createdById: 2,
        createdByName: 'خالد رحيم',
        approvedByName: 'عبدالرحمن نسيم',
        participantsCount: 0,
        createdAt: now,
      },
    ],
    tasks: [],
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
        reviewNote: 'معتمدة مباشرة',
        segments: {
          intro: 'بسم الله الرحمن الرحيم، والصلاة والسلام على أشرف الأنبياء والمرسلين.\nمديرنا الفاضل، معلمينا الكرام، زملائي الطلاب، السلام عليكم ورحمة الله وبركاته.\nأهلاً بكم في إذاعتنا الصباحية عن الانضباط والهمة العالية.',
          quran: 'خير ما نبدأ به إذاعتنا آيات عطرة من القرآن الكريم، يتلوها على مسامعكم الطالب............\n\n﴿وَالْعَصْرِ * إِنَّ الْإِنسَانَ لَفِي خُسْرٍ * إِلَّا الَّذِينَ آمَنُوا وَعَمِلُوا الصَّالِحَاتِ وَتَوَاصَوْا بِالْحَقِّ وَتَوَاصَوْا بِالصَّبْرِ﴾.',
          hadith: 'والآن مع الحديث الشريف، يقدمه الطالب............\n\nقال رسول الله ﷺ: «كُلُّكُمْ رَاعٍ وَكُلُّكُمْ مَسْؤُولٌ عَنْ رَعِيَّتِهِ».',
          morningWord: 'والآن مع كلمة الصباح، يقدمها الطالب............\n\nالالتزام بالوقت والمحافظة على النظام سر تميز الطالب المتفوق، وبناء مستقبل مشرق بالعلم والعمل.',
          didYouKnow: 'والآن مع فقرة هل تعلم، يقدمها الطالب............\n\n• هل تعلم أن الاستيقاظ المبكر ينشط الذاكرة ويزيد التركيز في الحصص؟\n• هل تعلم أن تنظيم الوقت يرفع التحصيل الدراسي؟\n• هل تعلم أن الانضباط المدرسي يعكس وعي الطالب واحترامه لنفسه؟',
          closing: 'وفي ختام إذاعتنا المدرسية، نشكركم على حسن استماعكم، ونتمنى لكم يوماً دراسياً سعيداً.\nوالسلام عليكم ورحمة الله وبركاته.',
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
        issuedById: 1,
        issuedByName: 'عبدالرحمن نسيم',
        issuedByRole: 'president',
        acknowledgedByIds: [1],
        createdAt: now,
      },
    ],
    submissions: [],
    complaints: [],
    suggestions: [],
    programReports: [],
    certificates: [],
    chatMessages: [],
    chatSettings: {
      mutedAll: false,
      mutedByName: null,
      updatedAt: now,
    },
  };
}

function readLocal() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = createInitialData();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  parsed.counters = {
    users: 0,
    activities: 0,
    tasks: 0,
    broadcasts: 0,
    discipline: 0,
    directives: 0,
    submissions: 0,
    complaints: 0,
    suggestions: 0,
    programReports: 0,
    certificates: 0,
    chatMessages: 0,
    ...(parsed.counters || {}),
  };
  parsed.users = (parsed.users || []).map((u) => ({
    title: '',
    ...u,
    badges: parseBadgesJson(u.badges),
  }));
  parsed.activities = (parsed.activities || []).map((a) => ({
    targetAudience: '',
    officerNote: '',
    createdById: 1,
    approvedByName: null,
    participantsCount: 0,
    ...a,
  }));
  parsed.tasks = parsed.tasks || [];
  parsed.broadcasts = (parsed.broadcasts || []).map((b) => ({
    reviewNote: '',
    ...b,
  }));
  parsed.disciplineLogs = (parsed.disciplineLogs || []).map((d) => ({
    recordedById: 1,
    ...d,
  }));
  parsed.directives = (parsed.directives || []).map((d) => ({
    issuedById: 1,
    ...d,
    acknowledgedByIds: Array.isArray(d.acknowledgedByIds) ? d.acknowledgedByIds : [],
  }));
  parsed.submissions = parsed.submissions || [];
  parsed.complaints = parsed.complaints || [];
  parsed.suggestions = parsed.suggestions || [];
  parsed.programReports = (parsed.programReports || []).map((r) => ({
    ...r,
    departmentName: r.departmentName || 'النشاط الطلابي',
  }));
  parsed.certificates = parsed.certificates || [];
  parsed.chatMessages = Array.isArray(parsed.chatMessages) ? parsed.chatMessages : [];
  parsed.chatSettings = parsed.chatSettings || {
    mutedAll: false,
    mutedByName: null,
    updatedAt: new Date().toISOString(),
  };
  return parsed;
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
          title TEXT NOT NULL DEFAULT '',
          phone TEXT NOT NULL DEFAULT '',
          grade_or_dept TEXT NOT NULL DEFAULT '',
          points INTEGER NOT NULL DEFAULT 0,
          is_active BOOLEAN NOT NULL DEFAULT TRUE,
          permissions JSONB,
          badges_json TEXT NOT NULL DEFAULT '[]',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE users ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '';
        ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS badges_json TEXT NOT NULL DEFAULT '[]';
        CREATE TABLE IF NOT EXISTS activities (
          id SERIAL PRIMARY KEY,
          title TEXT NOT NULL,
          unit TEXT NOT NULL,
          category TEXT NOT NULL DEFAULT 'عام',
          description TEXT NOT NULL DEFAULT '',
          event_date TEXT NOT NULL,
          event_time TEXT NOT NULL,
          location TEXT NOT NULL DEFAULT '',
          target_audience TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'approved',
          officer_ready BOOLEAN NOT NULL DEFAULT FALSE,
          officer_note TEXT NOT NULL DEFAULT '',
          created_by_id INTEGER NOT NULL DEFAULT 1,
          created_by_name TEXT NOT NULL DEFAULT '',
          approved_by_name TEXT,
          participants_count INTEGER NOT NULL DEFAULT 0,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE activities ADD COLUMN IF NOT EXISTS target_audience TEXT NOT NULL DEFAULT '';
        ALTER TABLE activities ADD COLUMN IF NOT EXISTS officer_note TEXT NOT NULL DEFAULT '';
        ALTER TABLE activities ADD COLUMN IF NOT EXISTS created_by_id INTEGER NOT NULL DEFAULT 1;
        ALTER TABLE activities ADD COLUMN IF NOT EXISTS approved_by_name TEXT;
        ALTER TABLE activities ADD COLUMN IF NOT EXISTS participants_count INTEGER NOT NULL DEFAULT 0;
        CREATE TABLE IF NOT EXISTS tasks (
          id SERIAL PRIMARY KEY,
          title TEXT NOT NULL,
          unit TEXT NOT NULL,
          activity_id INTEGER,
          assigned_to_id INTEGER,
          assigned_to_name TEXT NOT NULL DEFAULT '',
          created_by_name TEXT NOT NULL,
          due_date TEXT NOT NULL,
          priority TEXT NOT NULL DEFAULT 'normal',
          status TEXT NOT NULL DEFAULT 'pending',
          notes TEXT NOT NULL DEFAULT '',
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
          review_note TEXT NOT NULL DEFAULT '',
          segments JSONB NOT NULL DEFAULT '{}'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE broadcasts ADD COLUMN IF NOT EXISTS review_note TEXT NOT NULL DEFAULT '';
        CREATE TABLE IF NOT EXISTS discipline_logs (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          user_name TEXT NOT NULL,
          user_code TEXT NOT NULL,
          unit TEXT NOT NULL,
          category TEXT NOT NULL,
          points_delta INTEGER NOT NULL DEFAULT 0,
          note TEXT NOT NULL,
          recorded_by_id INTEGER NOT NULL DEFAULT 1,
          recorded_by_name TEXT NOT NULL,
          log_date TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE discipline_logs ADD COLUMN IF NOT EXISTS recorded_by_id INTEGER NOT NULL DEFAULT 1;
        CREATE TABLE IF NOT EXISTS directives (
          id SERIAL PRIMARY KEY,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          target_unit TEXT NOT NULL DEFAULT 'all',
          priority TEXT NOT NULL DEFAULT 'normal',
          issued_by_id INTEGER NOT NULL DEFAULT 1,
          issued_by_name TEXT NOT NULL,
          issued_by_role TEXT NOT NULL,
          acknowledged_by_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE directives ADD COLUMN IF NOT EXISTS issued_by_id INTEGER NOT NULL DEFAULT 1;
        ALTER TABLE directives ADD COLUMN IF NOT EXISTS acknowledged_by_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
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
        CREATE TABLE IF NOT EXISTS program_reports (
          id SERIAL PRIMARY KEY,
          school_name TEXT NOT NULL DEFAULT 'مدرسة الحديبية المتوسطة',
          department_name TEXT NOT NULL DEFAULT 'النشاط الطلابي',
          title TEXT NOT NULL,
          field TEXT NOT NULL DEFAULT 'النشاط الطلابي',
          executors TEXT NOT NULL,
          execution_date TEXT NOT NULL,
          beneficiaries TEXT NOT NULL DEFAULT 'الطلاب',
          beneficiaries_count TEXT NOT NULL DEFAULT '',
          steps JSONB NOT NULL DEFAULT '[]'::jsonb,
          objectives JSONB NOT NULL DEFAULT '[]'::jsonb,
          images JSONB NOT NULL DEFAULT '[]'::jsonb,
          created_by_id INTEGER NOT NULL,
          created_by_name TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE program_reports ADD COLUMN IF NOT EXISTS department_name TEXT NOT NULL DEFAULT 'النشاط الطلابي';
        CREATE TABLE IF NOT EXISTS certificates (
          id SERIAL PRIMARY KEY,
          student_id INTEGER,
          recipient_name TEXT NOT NULL,
          grade_or_title TEXT NOT NULL DEFAULT '',
          certificate_type TEXT NOT NULL DEFAULT 'شهادة شكر وتقدير',
          reason TEXT NOT NULL DEFAULT '',
          school_name TEXT NOT NULL DEFAULT 'مدرسة الحديبية المتوسطة',
          issuer_title TEXT NOT NULL DEFAULT 'رئيس النشاط الطلابي',
          issuer_name TEXT NOT NULL DEFAULT '',
          principal_name TEXT NOT NULL DEFAULT '',
          issue_date TEXT NOT NULL,
          template_style TEXT NOT NULL DEFAULT 'emerald_gold',
          created_by_id INTEGER NOT NULL,
          created_by_name TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS chat_messages (
          id SERIAL PRIMARY KEY,
          sender_id INTEGER NOT NULL,
          sender_name TEXT NOT NULL,
          sender_role TEXT NOT NULL,
          sender_unit TEXT NOT NULL,
          sender_is_supreme BOOLEAN NOT NULL DEFAULT FALSE,
          text_content TEXT NOT NULL DEFAULT '',
          image_data TEXT,
          reply_to JSONB,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '2 days')
        );
        CREATE INDEX IF NOT EXISTS idx_chat_messages_expires_at ON chat_messages (expires_at);
        CREATE TABLE IF NOT EXISTS chat_settings (
          id INTEGER PRIMARY KEY,
          muted_all BOOLEAN NOT NULL DEFAULT FALSE,
          muted_by_name TEXT,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        INSERT INTO chat_settings (id, muted_all, muted_by_name)
        VALUES (1, FALSE, NULL)
        ON CONFLICT (id) DO NOTHING;
      `);
      const countRes = await p.query('SELECT COUNT(*)::int AS cnt FROM users');
      if (countRes.rows[0].cnt === 0) {
        const seed = createInitialData();
        for (const u of seed.users) {
          await p.query(
            `INSERT INTO users (member_code, login_code, username, full_name, password_hash, role, unit, title, phone, grade_or_dept, points, is_active, permissions)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)`,
            [u.memberCode, u.loginCode, u.username, u.fullName, u.passwordHash, u.role, u.unit, u.title || '', u.phone, u.gradeOrDept, u.points, u.isActive, JSON.stringify(u.permissions)]
          );
        }
        for (const a of seed.activities) {
          await p.query(
            `INSERT INTO activities (title, unit, category, description, event_date, event_time, location, target_audience, status, officer_ready, officer_note, created_by_id, created_by_name, approved_by_name, participants_count)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
            [a.title, a.unit, a.category, a.description, a.eventDate, a.eventTime, a.location, a.targetAudience, a.status, a.officerReady, a.officerNote, a.createdById, a.createdByName, a.approvedByName, a.participantsCount]
          );
        }
        for (const b of seed.broadcasts) {
          await p.query(
            `INSERT INTO broadcasts (title, air_date, air_time, theme, presenters, supervisor_name, status, officer_checked, review_note, segments)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
            [b.title, b.airDate, b.airTime, b.theme, b.presenters, b.supervisorName, b.status, b.officerChecked, b.reviewNote || '', JSON.stringify(b.segments)]
          );
        }
        for (const d of seed.directives) {
          await p.query(
            `INSERT INTO directives (title, content, target_unit, priority, issued_by_id, issued_by_name, issued_by_role, acknowledged_by_ids)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
            [d.title, d.content, d.targetUnit, d.priority, d.issuedById || 1, d.issuedByName, d.issuedByRole, JSON.stringify(d.acknowledgedByIds || [1])]
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
  title: r.title || '',
  phone: r.phone,
  gradeOrDept: r.grade_or_dept,
  points: Number(r.points || 0),
  isActive: Boolean(r.is_active),
  permissions: Array.isArray(r.permissions)
    ? r.permissions
    : DEFAULT_ROLE_PERMISSIONS[r.role] || [],
  badges: parseBadgesJson(r.badges_json ?? r.badges),
  createdAt: new Date(r.created_at).toISOString(),
});

const mapActivity = (r) => ({
  id: r.id,
  title: r.title,
  unit: r.unit,
  category: r.category,
  description: r.description || '',
  eventDate: r.event_date,
  eventTime: r.event_time,
  location: r.location || '',
  targetAudience: r.target_audience || '',
  status: r.status,
  officerReady: Boolean(r.officer_ready),
  officerNote: r.officer_note || '',
  createdById: Number(r.created_by_id || 0),
  createdByName: r.created_by_name || '',
  approvedByName: r.approved_by_name || null,
  participantsCount: Number(r.participants_count || 0),
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
});

const mapTask = (r) => ({
  id: r.id,
  title: r.title,
  unit: r.unit,
  activityId: r.activity_id !== null && r.activity_id !== undefined ? Number(r.activity_id) : null,
  assignedToId: r.assigned_to_id !== null && r.assigned_to_id !== undefined ? Number(r.assigned_to_id) : null,
  assignedToName: r.assigned_to_name || '',
  createdByName: r.created_by_name || '',
  dueDate: r.due_date,
  priority: r.priority || 'normal',
  status: r.status || 'pending',
  notes: r.notes || '',
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
});

const mapBroadcast = (r) => ({
  id: r.id,
  title: r.title,
  airDate: r.air_date,
  airTime: r.air_time,
  theme: r.theme || '',
  presenters: r.presenters || '',
  supervisorName: r.supervisor_name || '',
  status: r.status,
  officerChecked: Boolean(r.officer_checked),
  reviewNote: r.review_note || '',
  segments: r.segments || {},
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
});

const mapDiscipline = (r) => ({
  id: r.id,
  userId: r.user_id,
  userName: r.user_name,
  userCode: r.user_code,
  unit: r.unit,
  category: r.category,
  pointsDelta: Number(r.points_delta || 0),
  note: r.note || '',
  recordedById: Number(r.recorded_by_id || 0),
  recordedByName: r.recorded_by_name || '',
  logDate: r.log_date,
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
});

const mapDirective = (r) => {
  let ack = r.acknowledged_by_ids;
  if (typeof ack === 'string') {
    try { ack = JSON.parse(ack); } catch { ack = []; }
  }
  return {
    id: r.id,
    title: r.title,
    content: r.content,
    targetUnit: r.target_unit || 'all',
    priority: r.priority || 'normal',
    issuedById: Number(r.issued_by_id || 0),
    issuedByName: r.issued_by_name || '',
    issuedByRole: r.issued_by_role || 'president',
    acknowledgedByIds: Array.isArray(ack) ? ack : [],
    createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
  };
};

const mapSubmission = (r) => ({
  id: r.id,
  studentId: r.student_id,
  studentName: r.student_name,
  studentCode: r.student_code,
  unit: r.unit,
  title: r.title,
  details: r.details || '',
  activityDate: r.activity_date,
  status: r.status,
  awardedPoints: Number(r.awarded_points || 0),
  adminNote: r.admin_note || '',
  reviewedByName: r.reviewed_by_name || null,
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
});

const mapComplaint = (r) => ({
  id: r.id,
  reporterId: r.reporter_id,
  reporterName: r.reporter_name,
  targetStudentName: r.target_student_name,
  reason: r.reason,
  details: r.details || '',
  status: r.status,
  adminResponse: r.admin_response || '',
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
});

const mapSuggestion = (r) => ({
  id: r.id,
  studentId: r.student_id,
  studentName: r.student_name,
  title: r.title,
  details: r.details || '',
  status: r.status,
  adminResponse: r.admin_response || '',
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
});

const mapProgramReport = (r) => ({
  id: r.id,
  schoolName: r.school_name,
  departmentName: r.department_name || 'النشاط الطلابي',
  title: r.title,
  field: r.field,
  executors: r.executors,
  executionDate: r.execution_date,
  beneficiaries: r.beneficiaries,
  beneficiariesCount: r.beneficiaries_count,
  steps: Array.isArray(r.steps) ? r.steps : [],
  objectives: Array.isArray(r.objectives) ? r.objectives : [],
  images: Array.isArray(r.images) ? r.images : [],
  createdById: Number(r.created_by_id || 0),
  createdByName: r.created_by_name || '',
  createdAt: r.created_at ? new Date(r.created_at).toISOString() : undefined,
});

const sanitizeUser = (u, viewer = null) => {
  const { passwordHash: _, ...rest } = u;
  const pub = {
    ...rest,
    badges: parseBadgesJson(u.badges),
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
  const clean = normalizeLoginCode(code);
  if (!clean) return null;
  if (!isNeon) {
    return (
      readLocal().users.find(
        (u) =>
          normalizeLoginCode(u.loginCode) === clean ||
          String(u.memberCode || '').toLowerCase() === clean.toLowerCase()
      ) || null
    );
  }
  const r = await getPool().query(
    'SELECT * FROM users WHERE TRIM(login_code) = $1 OR LOWER(TRIM(member_code)) = LOWER($1) LIMIT 1',
    [clean]
  );
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

function requireMgmt(req, res, next) {
  if (!req.user || !isMgmt(req.user.role)) return res.status(403).json({ error: 'صلاحية للإدارة فقط' });
  next();
}

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

    const canSeeReports = isMgmt(viewer.role) || hasPerm(viewer, 'manage_activities');

    if (!isNeon) {
      const db = readLocal();
      const visibleUsers = canSeeUsers ? db.users : db.users.filter((u) => u.id === viewer.id);
      const leaderboard = computeLeaderboard(db.users, db.submissions || []);
      const myRank = leaderboard.find((e) => e.id === viewer.id)?.rank ?? null;
      return res.json({
        users: visibleUsers.map((u) => sanitizeUser(u, viewer)),
        activities: db.activities,
        broadcasts: canSeeBroadcasts ? db.broadcasts : [],
        disciplineLogs: canSeeDiscipline ? db.disciplineLogs : db.disciplineLogs.filter((d) => d.userId === viewer.id),
        directives: db.directives,
        submissions: canReviewSubs ? db.submissions : db.submissions.filter((s) => s.studentId === viewer.id),
        complaints: canReviewSubs ? db.complaints : db.complaints.filter((c) => c.reporterId === viewer.id),
        suggestions: canReviewSubs ? db.suggestions : db.suggestions.filter((s) => s.studentId === viewer.id),
        programReports: canSeeReports ? (db.programReports || []) : [],
        certificates: isMgmt(viewer.role) ? (db.certificates || []) : (db.certificates || []).filter((c) => c.studentId === viewer.id),
        leaderboard: { entries: leaderboard, myRank, totalRanked: leaderboard.length, updatedAt: new Date().toISOString() },
      });
    }
    const p = getPool();
    const [uR, aR, bR, disR, dirR, subR, cmpR, sugR, repR, certR, lbUR, lbSubR] = await Promise.all([
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
      canSeeReports ? p.query('SELECT * FROM program_reports ORDER BY id DESC') : Promise.resolve({ rows: [] }),
      isMgmt(viewer.role)
        ? p.query('SELECT * FROM certificates ORDER BY id DESC')
        : p.query('SELECT * FROM certificates WHERE student_id=$1 ORDER BY id DESC', [viewer.id]),
      p.query('SELECT id, member_code, full_name, role, unit, grade_or_dept, points, is_active, badges_json FROM users ORDER BY id ASC'),
      p.query("SELECT student_id, status FROM submissions WHERE status = 'approved'"),
    ]);
    const leaderboard = computeLeaderboard(lbUR.rows, lbSubR.rows);
    const myRank = leaderboard.find((e) => e.id === viewer.id)?.rank ?? null;
    res.json({
      users: uR.rows.map((r) => sanitizeUser(mapUser(r), viewer)),
      activities: aR.rows.map(mapActivity),
      broadcasts: bR.rows.map(mapBroadcast),
      disciplineLogs: disR.rows.map(mapDiscipline),
      directives: dirR.rows.map(mapDirective),
      submissions: subR.rows.map(mapSubmission),
      complaints: cmpR.rows.map(mapComplaint),
      suggestions: sugR.rows.map(mapSuggestion),
      programReports: repR.rows.map(mapProgramReport),
      certificates: certR.rows.map(mapCertificate),
      leaderboard: { entries: leaderboard, myRank, totalRanked: leaderboard.length, updatedAt: new Date().toISOString() },
    });
  } catch {
    res.status(500).json({ error: 'تعذر تحميل البيانات' });
  }
});

app.get('/api/dashboard/overview', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const viewer = req.user;
    const canSeeBroadcasts = hasPerm(viewer, 'manage_broadcasts');
    let users, activities, tasks, broadcasts, disciplineLogs, directives, submissions, complaints, suggestions;

    if (!isNeon) {
      const db = readLocal();
      users = db.users;
      activities = db.activities;
      tasks = db.tasks || [];
      broadcasts = db.broadcasts;
      disciplineLogs = db.disciplineLogs;
      directives = db.directives;
      submissions = db.submissions;
      complaints = db.complaints;
      suggestions = db.suggestions;
    } else {
      const p = getPool();
      const [uR, aR, tR, bR, disR, dirR, subR, cmpR, sugR] = await Promise.all([
        p.query('SELECT * FROM users ORDER BY id ASC'),
        p.query('SELECT * FROM activities ORDER BY event_date ASC, id DESC'),
        p.query('SELECT * FROM tasks ORDER BY id DESC'),
        canSeeBroadcasts ? p.query('SELECT * FROM broadcasts ORDER BY air_date ASC, id DESC') : Promise.resolve({ rows: [] }),
        p.query('SELECT * FROM discipline_logs ORDER BY id DESC'),
        p.query('SELECT * FROM directives ORDER BY id DESC'),
        p.query('SELECT * FROM submissions ORDER BY id DESC'),
        p.query('SELECT * FROM complaints ORDER BY id DESC'),
        p.query('SELECT * FROM suggestions ORDER BY id DESC'),
      ]);
      users = uR.rows.map(mapUser);
      activities = aR.rows.map(mapActivity);
      tasks = tR.rows.map(mapTask);
      broadcasts = bR.rows.map(mapBroadcast);
      disciplineLogs = disR.rows.map(mapDiscipline);
      directives = dirR.rows.map(mapDirective);
      submissions = subR.rows.map(mapSubmission);
      complaints = cmpR.rows.map(mapComplaint);
      suggestions = sugR.rows.map(mapSuggestion);
    }

    const activeMembersCount = users.filter((u) => u.isActive && !isMgmt(u.role)).length;
    const managementCount = users.filter((u) => u.isActive && isMgmt(u.role)).length;
    const pendingActivities = activities.filter((a) => a.status === 'pending_approval');
    const pendingBroadcasts = canSeeBroadcasts
      ? broadcasts.filter((b) => b.status === 'pending_approval')
      : [];

    res.json({
      stats: {
        totalUsers: users.length,
        activeMembersCount,
        managementCount,
        activity1Count: activities.filter((a) => a.unit === 'activity_1').length,
        activity2Count: activities.filter((a) => a.unit === 'activity_2').length,
        broadcastsCount: canSeeBroadcasts ? broadcasts.length : 0,
        pendingApprovalsCount: pendingActivities.length + pendingBroadcasts.length,
        openTasksCount: tasks.filter((t) => t.status !== 'completed').length,
        pendingSubmissionsCount: submissions.filter((s) => s.status === 'pending').length,
        openComplaintsCount: complaints.filter((c) => c.status !== 'resolved').length,
        newSuggestionsCount: suggestions.filter((s) => s.status === 'new').length,
      },
      pendingActivities,
      pendingBroadcasts,
      upcomingBroadcasts: canSeeBroadcasts ? broadcasts.slice(0, 4) : [],
      recentDirectives: directives.slice(0, 5),
      myTasks: tasks.filter((t) => t.assignedToId === viewer.id || t.unit === viewer.unit).slice(0, 6),
      recentDiscipline: !isMgmt(viewer.role)
        ? disciplineLogs.filter((d) => d.userId === viewer.id).slice(0, 5)
        : disciplineLogs.slice(0, 6),
    });
  } catch {
    res.status(500).json({ error: 'تعذر تحميل ملخص المنظومة' });
  }
});

app.get('/api/users', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const viewer = req.user;
    const canSeeUsers =
      hasAllSixPerms(viewer) ||
      isMgmt(viewer.role) ||
      hasPerm(viewer, 'manage_activities') ||
      hasPerm(viewer, 'manage_discipline');

    if (!isNeon) {
      const db = readLocal();
      const visibleUsers = canSeeUsers ? db.users : db.users.filter((u) => u.id === viewer.id);
      return res.json({ users: visibleUsers.map((u) => sanitizeUser(u, viewer)) });
    }
    const p = getPool();
    const r = canSeeUsers
      ? await p.query('SELECT * FROM users ORDER BY id ASC')
      : await p.query('SELECT * FROM users WHERE id=$1', [viewer.id]);
    res.json({ users: r.rows.map((row) => sanitizeUser(mapUser(row), viewer)) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب قائمة الأفراد والقيادات' });
  }
});

app.post('/api/users', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const actor = req.user;
    if (!hasAllSixPerms(actor)) {
      return res.status(403).json({ error: 'الوصول إلى الأفراد والصلاحيات يتطلب امتلاك الصلاحيات الست كاملة' });
    }
    const { fullName, loginCode, role, unit, title, phone, gradeOrDept, memberCode, username: requestedUsername, permissions } = req.body || {};
    const targetRole = ALLOWED_ROLES.includes(role) ? role : 'member';

    if (targetRole === 'president' && !isSupremePresident(actor)) {
      return res.status(403).json({ error: 'منح رتبة رئيس النشاط مخصص للرئيس عبدالرحمن نسيم فقط' });
    }
    if (!String(fullName || '').trim() || !String(loginCode || '').trim() || !String(phone || '').trim()) {
      return res.status(400).json({ error: 'يرجى إدخال الاسم الكامل ورقم الجوال ورمز الدخول' });
    }

    const cleanCode = normalizeLoginCode(loginCode);
    if (!cleanCode) return res.status(400).json({ error: 'يرجى إدخال رمز دخول صالح' });
    const rand = Math.floor(1000 + Math.random() * 9000);
    const code = String(memberCode || '').trim() || `${isMgmt(targetRole) ? 'ADM' : 'STD'}-${rand}`;
    const reqUser = String(requestedUsername || '').trim().toLowerCase();
    const username = (reqUser && reqUser !== 'president') ? reqUser : `user_${cleanCode}`.toLowerCase();
    const hash = bcrypt.hashSync(cleanCode, 10);
    const targetUnit = unit || 'activity_1';
    const parsedPerms = sanitizePermissions(permissions) || DEFAULT_ROLE_PERMISSIONS[targetRole];

    if (!isNeon) {
      const db = readLocal();
      if (db.users.some((u) => normalizeLoginCode(u.loginCode) === cleanCode)) {
        return res.status(400).json({ error: 'رمز الدخول مستخدم مسبقاً' });
      }
      db.counters.users += 1;
      const created = {
        id: db.counters.users,
        memberCode: code,
        loginCode: cleanCode,
        username,
        fullName: fullName.trim(),
        passwordHash: hash,
        role: targetRole,
        unit: targetUnit,
        title: String(title || '').trim(),
        phone: phone.trim(),
        gradeOrDept: String(gradeOrDept || '').trim(),
        points: isMgmt(targetRole) ? 90 : 0,
        isActive: true,
        permissions: parsedPerms,
        badges: [],
        createdAt: new Date().toISOString(),
      };
      db.users.push(created);
      writeLocal(db);
      return res.status(201).json({ user: sanitizeUser(created) });
    }

    const exists = await getPool().query('SELECT 1 FROM users WHERE TRIM(login_code)=$1', [cleanCode]);
    if (exists.rowCount > 0) return res.status(400).json({ error: 'رمز الدخول مستخدم مسبقاً' });

    const r = await getPool().query(
      `INSERT INTO users (member_code, login_code, username, full_name, password_hash, role, unit, title, phone, grade_or_dept, points, is_active, permissions, badges_json)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,TRUE,$12::jsonb,'[]') RETURNING *`,
      [
        code, cleanCode, username, fullName.trim(), hash, targetRole, targetUnit,
        String(title || '').trim(), phone.trim(), String(gradeOrDept || '').trim(),
        isMgmt(targetRole) ? 90 : 0, JSON.stringify(parsedPerms),
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

    const { fullName, loginCode, role, unit, title, phone, gradeOrDept, points, isActive, permissions } = req.body || {};
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
      cleanCode = normalizeLoginCode(loginCode);
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
      if (title !== undefined) u.title = String(title).trim();
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
        title = COALESCE($5, title),
        phone = COALESCE($6, phone),
        grade_or_dept = COALESCE($7, grade_or_dept),
        points = COALESCE($8, points),
        is_active = COALESCE($9, is_active),
        permissions = COALESCE($10::jsonb, permissions)
       WHERE id = $11 RETURNING *`,
      [
        fullName !== undefined && String(fullName).trim() ? String(fullName).trim() : null,
        cleanCode ?? null,
        !targetIsSupreme && role !== undefined ? role : null,
        !targetIsSupreme && unit !== undefined ? unit : null,
        title !== undefined ? String(title).trim() : null,
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

app.get('/api/submissions', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const canReviewSubs = isMgmt(u.role) || hasPerm(u, 'review_submissions');
    if (!isNeon) {
      const db = readLocal();
      const list = canReviewSubs ? db.submissions : db.submissions.filter((s) => s.studentId === u.id);
      return res.json({ submissions: list });
    }
    const r = canReviewSubs
      ? await getPool().query('SELECT * FROM submissions ORDER BY id DESC')
      : await getPool().query('SELECT * FROM submissions WHERE student_id=$1 ORDER BY id DESC', [u.id]);
    res.json({ submissions: r.rows.map(mapSubmission) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب تقديمات الطلاب' });
  }
});

app.post('/api/submissions', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const { title, details, unit, activityDate: rawActivityDate } = req.body || {};
    if (!String(title || '').trim()) return res.status(400).json({ error: 'يرجى كتابة عنوان الإنجاز' });
    const activityDate = String(rawActivityDate || '').trim() || new Date().toISOString().slice(0, 10);
    const subUnit = unit || u.unit || 'activity_1';

    if (!isNeon) {
      const db = readLocal();
      db.counters.submissions += 1;
      const item = {
        id: db.counters.submissions, studentId: u.id, studentName: u.fullName, studentCode: u.memberCode,
        unit: subUnit, title: title.trim(), details: String(details || '').trim(), activityDate,
        status: 'pending', awardedPoints: 0, adminNote: '', reviewedByName: null,
        createdAt: new Date().toISOString(),
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
    res.status(201).json({ submission: mapSubmission(r.rows[0]) });
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
    res.json({ submission: mapSubmission(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر مراجعة الإنجاز' });
  }
});

app.get('/api/complaints', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const canReview = isMgmt(u.role) || hasPerm(u, 'review_submissions');
    if (!isNeon) {
      const db = readLocal();
      const list = canReview ? db.complaints : db.complaints.filter((c) => c.reporterId === u.id);
      return res.json({ complaints: list });
    }
    const r = canReview
      ? await getPool().query('SELECT * FROM complaints ORDER BY id DESC')
      : await getPool().query('SELECT * FROM complaints WHERE reporter_id=$1 ORDER BY id DESC', [u.id]);
    res.json({ complaints: r.rows.map(mapComplaint) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب الشكاوى' });
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
        createdAt: new Date().toISOString(),
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
    res.status(201).json({ complaint: mapComplaint(r.rows[0]) });
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
    if (r.rowCount === 0) return res.status(404).json({ error: 'الشكوى غير موجودة' });
    res.json({ complaint: mapComplaint(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث الشكوى' });
  }
});

app.get('/api/suggestions', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const canReview = isMgmt(u.role) || hasPerm(u, 'review_submissions');
    if (!isNeon) {
      const db = readLocal();
      const list = canReview ? db.suggestions : db.suggestions.filter((s) => s.studentId === u.id);
      return res.json({ suggestions: list });
    }
    const r = canReview
      ? await getPool().query('SELECT * FROM suggestions ORDER BY id DESC')
      : await getPool().query('SELECT * FROM suggestions WHERE student_id=$1 ORDER BY id DESC', [u.id]);
    res.json({ suggestions: r.rows.map(mapSuggestion) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب الاقتراحات' });
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
        createdAt: new Date().toISOString(),
      };
      db.suggestions.unshift(item);
      writeLocal(db);
      return res.status(201).json({ suggestion: item });
    }
    const r = await getPool().query(
      'INSERT INTO suggestions (student_id, student_name, title, details) VALUES ($1,$2,$3,$4) RETURNING *',
      [u.id, u.fullName, title.trim(), String(details || '').trim()]
    );
    res.status(201).json({ suggestion: mapSuggestion(r.rows[0]) });
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
    if (r.rowCount === 0) return res.status(404).json({ error: 'الاقتراح غير موجود' });
    res.json({ suggestion: mapSuggestion(r.rows[0]) });
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

    const prompt = `اكتب إذاعة مدرسية كاملة للمرحلة المتوسطة بعنوان/موضوع: "${topic}"
بنفس الأسلوب والترتيب التالي بالضبط، مع التزام حتمي بترك سطر فاضي (سطرين \\n\\n) مباشرة بعد كل عبارة تذكر اسم الطالب (الطالب.........) قبل بدء الآية أو الحديث أو الكلمة أو النقاط:
1- المقدمة: تبدأ بـ "بسم الله الرحمن الرحيم، والصلاة والسلام على أشرف الأنبياء والمرسلين.\nمديرنا الفاضل، معلمينا الكرام، زملائي الطلاب، السلام عليكم ورحمة الله وبركاته." ثم تعريف جميل وواضح بموضوع الإذاعة.
2- القرآن الكريم: السطر الأول "خير ما نبدأ به إذاعتنا آيات عطرة من القرآن الكريم، يتلوها على مسامعكم الطالب............" ثم سطر فاضي (\\n\\n) ثم آية قرآنية مناسبة وصحيحة للموضوع بين ﴿...﴾.
3- الحديث الشريف: السطر الأول "والآن مع الحديث الشريف والطالب............" ثم سطر فاضي (\\n\\n) ثم "قال رسول الله ﷺ: «...»." بحديث نبوي صحيح أو مشهور مناسب للموضوع.
4- كلمة الصباح: السطر الأول "والآن مع كلمة الصباح والطالب............" ثم سطر فاضي (\\n\\n) ثم كلمة مفيدة ومبسطة لطلاب المرحلة المتوسطة عن الموضوع.
5- هل تعلم؟: السطر الأول "والآن مع فقرة هل تعلم والطالب............" ثم سطر فاضي (\\n\\n) ثم 3 نقاط تبدأ كل نقطة بـ "• هل تعلم أن ...؟".
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

    const parsed = await runGroqJsonPrompt(
      'أنت معد إذاعات مدرسية للمرحلة المتوسطة باللغة العربية الفصحى السليمة. تلتزم بدقة الآيات والأحاديث وتترك دائماً سطراً فاضياً بعد كل سطر يذكر فيه الطالب، وتعيد الإخراج بصيغة JSON فقط.',
      prompt
    );
    res.json({
      title: parsed.title || `إذاعة مدرسية عن ${topic}`,
      theme: parsed.theme || topic,
      segments: {
        intro: formatBroadcastSegmentSpacing(parsed.segments?.intro || ''),
        quran: formatBroadcastSegmentSpacing(parsed.segments?.quran || ''),
        hadith: formatBroadcastSegmentSpacing(parsed.segments?.hadith || ''),
        morningWord: formatBroadcastSegmentSpacing(parsed.segments?.morningWord || ''),
        didYouKnow: formatBroadcastSegmentSpacing(parsed.segments?.didYouKnow || ''),
        closing: formatBroadcastSegmentSpacing(parsed.segments?.closing || ''),
      },
    });
  } catch (err) {
    if (err?.message === 'NO_GROQ_KEY') {
      return res.status(400).json({ error: 'مفتاح GROQ_API_KEY غير مضاف في متغيرات البيئة' });
    }
    res.status(502).json({ error: err?.message || 'تعذر توليد الإذاعة حالياً' });
  }
});

app.get('/api/broadcasts', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_broadcasts')) {
      return res.status(403).json({ error: 'الاطلاع على الإذاعات مخصص لأصحاب صلاحية الإذاعة فقط' });
    }
    await ensureReady();
    if (!isNeon) {
      return res.json({ broadcasts: readLocal().broadcasts });
    }
    const r = await getPool().query('SELECT * FROM broadcasts ORDER BY air_date ASC, id DESC');
    res.json({ broadcasts: r.rows.map(mapBroadcast) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب جدول الإذاعات' });
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
    const autoApprove = req.user.role === 'president' || req.user.role === 'vice_president';
    const status = autoApprove ? 'approved' : 'pending_approval';
    const reviewNote = autoApprove ? 'معتمدة مباشرة' : 'بانتظار مراجعة واعتماد القيادة';
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
        supervisorName: isMgmt(req.user.role) ? req.user.fullName : 'الإدارة',
        status, officerChecked: false, reviewNote, segments: segs,
        createdAt: new Date().toISOString(),
      };
      db.broadcasts.unshift(item);
      writeLocal(db);
      return res.status(201).json({ broadcast: item });
    }
    const r = await getPool().query(
      `INSERT INTO broadcasts (title, air_date, air_time, theme, presenters, supervisor_name, status, review_note, segments)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) RETURNING *`,
      [title.trim(), airDate, airTime, theme || 'عام', presenters || req.user.fullName, isMgmt(req.user.role) ? req.user.fullName : 'الإدارة', status, reviewNote, JSON.stringify(segs)]
    );
    res.status(201).json({ broadcast: mapBroadcast(r.rows[0]) });
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
    const { title, airDate, airTime, theme, presenters, status, officerChecked, reviewNote, segments } = req.body || {};

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
      if (reviewNote !== undefined) item.reviewNote = String(reviewNote).trim();
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
        review_note = COALESCE($8, review_note),
        segments = COALESCE($9::jsonb, segments)
       WHERE id=$10 RETURNING *`,
      [
        title !== undefined ? String(title).trim() : null,
        airDate ?? null,
        airTime ?? null,
        theme !== undefined ? String(theme).trim() : null,
        presenters !== undefined ? String(presenters).trim() : null,
        status ?? null,
        officerChecked !== undefined ? Boolean(officerChecked) : null,
        reviewNote !== undefined ? String(reviewNote).trim() : null,
        mergedSegs ? JSON.stringify(mergedSegs) : null,
        id,
      ]
    );
    res.json({ broadcast: mapBroadcast(r.rows[0]) });
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

app.get('/api/activities', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const unit = req.query.unit === 'activity_1' || req.query.unit === 'activity_2' ? req.query.unit : undefined;
    if (!isNeon) {
      const list = readLocal().activities;
      return res.json({ activities: unit ? list.filter((a) => a.unit === unit) : list });
    }
    const r = unit
      ? await getPool().query('SELECT * FROM activities WHERE unit=$1 ORDER BY event_date ASC, id DESC', [unit])
      : await getPool().query('SELECT * FROM activities ORDER BY event_date ASC, id DESC');
    res.json({ activities: r.rows.map(mapActivity) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب الأنشطة' });
  }
});

app.post('/api/activities', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_activities') && !isMgmt(req.user.role)) {
      return res.status(403).json({ error: 'ليس لديك صلاحية إضافة البرامج والأنشطة' });
    }
    await ensureReady();
    const { title, unit, category, description, eventDate, eventTime, location, targetAudience, participantsCount } = req.body || {};
    if (!title || !unit || !eventDate) return res.status(400).json({ error: 'يرجى إكمال بيانات البرنامج' });
    const autoApprove = isMgmt(req.user.role);
    const status = autoApprove ? 'approved' : 'pending_approval';
    const safeTime = eventTime || '09:30';
    const safeLoc = location || 'المدرسة';
    const safeAud = targetAudience || 'جميع الطلاب';
    const safeCnt = Number(participantsCount || 0);
    const approvedBy = autoApprove ? req.user.fullName : null;

    if (!isNeon) {
      const db = readLocal();
      db.counters.activities += 1;
      const item = {
        id: db.counters.activities, title: title.trim(), unit, category: category || 'عام',
        description: description || '', eventDate, eventTime: safeTime,
        location: safeLoc, targetAudience: safeAud, status,
        officerReady: autoApprove, officerNote: '', createdById: req.user.id,
        createdByName: req.user.fullName, approvedByName: approvedBy,
        participantsCount: safeCnt, createdAt: new Date().toISOString(),
      };
      db.activities.unshift(item);
      writeLocal(db);
      return res.status(201).json({ activity: item });
    }
    const r = await getPool().query(
      `INSERT INTO activities (title, unit, category, description, event_date, event_time, location, target_audience, status, officer_ready, officer_note, created_by_id, created_by_name, approved_by_name, participants_count)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'',$11,$12,$13,$14) RETURNING *`,
      [title.trim(), unit, category || 'عام', description || '', eventDate, safeTime, safeLoc, safeAud, status, autoApprove, req.user.id, req.user.fullName, approvedBy, safeCnt]
    );
    res.status(201).json({ activity: mapActivity(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر إضافة البرنامج' });
  }
});

app.patch('/api/activities/:id', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    if (!isMgmt(user.role) && !hasPerm(user, 'manage_activities')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية تعديل هذا البرنامج' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    const body = req.body || {};

    if (!isNeon) {
      const db = readLocal();
      const idx = db.activities.findIndex((a) => a.id === id);
      if (idx === -1) return res.status(404).json({ error: 'البرنامج غير موجود' });
      const item = { ...db.activities[idx] };
      if (body.title !== undefined) item.title = String(body.title).trim();
      if (body.category !== undefined) item.category = String(body.category).trim();
      if (body.description !== undefined) item.description = String(body.description).trim();
      if (body.eventDate !== undefined) item.eventDate = body.eventDate;
      if (body.eventTime !== undefined) item.eventTime = body.eventTime;
      if (body.location !== undefined) item.location = String(body.location).trim();
      if (body.targetAudience !== undefined) item.targetAudience = String(body.targetAudience).trim();
      if (body.status !== undefined) {
        item.status = body.status;
        if (body.status === 'approved') item.approvedByName = user.fullName;
      }
      if (body.officerReady !== undefined) item.officerReady = Boolean(body.officerReady);
      if (body.officerNote !== undefined) item.officerNote = String(body.officerNote).trim();
      if (body.participantsCount !== undefined) item.participantsCount = Number(body.participantsCount || 0);
      db.activities[idx] = item;
      writeLocal(db);
      return res.json({ activity: item });
    }

    const r = await getPool().query(
      `UPDATE activities SET
        title = COALESCE($1, title),
        category = COALESCE($2, category),
        description = COALESCE($3, description),
        event_date = COALESCE($4, event_date),
        event_time = COALESCE($5, event_time),
        location = COALESCE($6, location),
        target_audience = COALESCE($7, target_audience),
        status = COALESCE($8, status),
        officer_ready = COALESCE($9, officer_ready),
        officer_note = COALESCE($10, officer_note),
        approved_by_name = COALESCE($11, approved_by_name),
        participants_count = COALESCE($12, participants_count)
       WHERE id=$13 RETURNING *`,
      [
        body.title !== undefined ? String(body.title).trim() : null,
        body.category !== undefined ? String(body.category).trim() : null,
        body.description !== undefined ? String(body.description).trim() : null,
        body.eventDate ?? null,
        body.eventTime ?? null,
        body.location !== undefined ? String(body.location).trim() : null,
        body.targetAudience !== undefined ? String(body.targetAudience).trim() : null,
        body.status ?? null,
        body.officerReady !== undefined ? Boolean(body.officerReady) : null,
        body.officerNote !== undefined ? String(body.officerNote).trim() : null,
        body.status === 'approved' ? user.fullName : null,
        body.participantsCount !== undefined ? Number(body.participantsCount || 0) : null,
        id,
      ]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'البرنامج غير موجود' });
    res.json({ activity: mapActivity(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث البرنامج' });
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

app.get('/api/tasks', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const unit = req.query.unit ? String(req.query.unit) : undefined;
    if (!isNeon) {
      const list = readLocal().tasks || [];
      return res.json({ tasks: unit ? list.filter((t) => t.unit === unit) : list });
    }
    const r = unit
      ? await getPool().query('SELECT * FROM tasks WHERE unit=$1 ORDER BY id DESC', [unit])
      : await getPool().query('SELECT * FROM tasks ORDER BY id DESC');
    res.json({ tasks: r.rows.map(mapTask) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب المهام' });
  }
});

app.post('/api/tasks', requireAuth, requireMgmt, async (req, res) => {
  try {
    await ensureReady();
    const { title, unit, activityId, assignedToId, dueDate, priority, notes } = req.body || {};
    if (!title || !unit || !dueDate) return res.status(400).json({ error: 'يرجى كتابة عنوان المهمة والقسم وتاريخ التسليم' });
    let assignedToName = 'غير محدد';
    if (assignedToId) {
      const assignee = await findUserById(Number(assignedToId));
      if (assignee) assignedToName = assignee.fullName;
    }
    if (!isNeon) {
      const db = readLocal();
      db.counters.tasks = (db.counters.tasks || 0) + 1;
      db.tasks = db.tasks || [];
      const task = {
        id: db.counters.tasks,
        title: String(title).trim(),
        unit,
        activityId: activityId ?? null,
        assignedToId: assignedToId ? Number(assignedToId) : null,
        assignedToName,
        createdByName: req.user.fullName,
        dueDate,
        priority: priority || 'normal',
        status: 'pending',
        notes: String(notes || '').trim(),
        createdAt: new Date().toISOString(),
      };
      db.tasks.unshift(task);
      writeLocal(db);
      return res.status(201).json({ task });
    }
    const r = await getPool().query(
      `INSERT INTO tasks (title, unit, activity_id, assigned_to_id, assigned_to_name, created_by_name, due_date, priority, status, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9) RETURNING *`,
      [String(title).trim(), unit, activityId ?? null, assignedToId ? Number(assignedToId) : null, assignedToName, req.user.fullName, dueDate, priority || 'normal', String(notes || '').trim()]
    );
    res.status(201).json({ task: mapTask(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر إنشاء المهمة' });
  }
});

app.patch('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const user = req.user;
    const id = Number(req.params.id);
    const { status, title, dueDate, priority, notes } = req.body || {};

    if (!isNeon) {
      const db = readLocal();
      const idx = (db.tasks || []).findIndex((t) => t.id === id);
      if (idx === -1) return res.status(404).json({ error: 'المهمة غير موجودة' });
      const existing = db.tasks[idx];
      if (!isMgmt(user.role)) {
        if (existing.assignedToId !== user.id && existing.unit !== user.unit) {
          return res.status(403).json({ error: 'هذه المهمة غير مسندة إليك' });
        }
        existing.status = status || existing.status;
      } else {
        if (status) existing.status = status;
        if (title) existing.title = String(title).trim();
        if (dueDate) existing.dueDate = dueDate;
        if (priority) existing.priority = priority;
        if (notes !== undefined) existing.notes = String(notes).trim();
      }
      writeLocal(db);
      return res.json({ task: existing });
    }

    const p = getPool();
    const curR = await p.query('SELECT * FROM tasks WHERE id=$1', [id]);
    if (curR.rowCount === 0) return res.status(404).json({ error: 'المهمة غير موجودة' });
    const existing = mapTask(curR.rows[0]);
    if (!isMgmt(user.role)) {
      if (existing.assignedToId !== user.id && existing.unit !== user.unit) {
        return res.status(403).json({ error: 'هذه المهمة غير مسندة إليك' });
      }
      const r = await p.query('UPDATE tasks SET status=$1 WHERE id=$2 RETURNING *', [status || existing.status, id]);
      return res.json({ task: mapTask(r.rows[0]) });
    }
    const r = await p.query(
      `UPDATE tasks SET
        status = COALESCE($1, status),
        title = COALESCE($2, title),
        due_date = COALESCE($3, due_date),
        priority = COALESCE($4, priority),
        notes = COALESCE($5, notes)
       WHERE id=$6 RETURNING *`,
      [status ?? null, title ? String(title).trim() : null, dueDate ?? null, priority ?? null, notes !== undefined ? String(notes).trim() : null, id]
    );
    res.json({ task: mapTask(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث المهمة' });
  }
});

app.delete('/api/tasks/:id', requireAuth, requireMgmt, async (req, res) => {
  try {
    await ensureReady();
    const id = Number(req.params.id);
    if (!isNeon) {
      const db = readLocal();
      const before = (db.tasks || []).length;
      db.tasks = (db.tasks || []).filter((t) => t.id !== id);
      if (db.tasks.length === before) return res.status(404).json({ error: 'المهمة غير موجودة' });
      writeLocal(db);
      return res.json({ ok: true });
    }
    const r = await getPool().query('DELETE FROM tasks WHERE id=$1', [id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'المهمة غير موجودة' });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف المهمة' });
  }
});

app.get('/api/discipline', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const canSeeAll = isMgmt(u.role) || hasPerm(u, 'manage_discipline');
    if (!isNeon) {
      const logs = readLocal().disciplineLogs;
      return res.json({ logs: canSeeAll ? logs : logs.filter((d) => d.userId === u.id) });
    }
    const r = canSeeAll
      ? await getPool().query('SELECT * FROM discipline_logs ORDER BY id DESC')
      : await getPool().query('SELECT * FROM discipline_logs WHERE user_id=$1 ORDER BY id DESC', [u.id]);
    res.json({ logs: r.rows.map(mapDiscipline) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب سجلات الانضباط' });
  }
});

app.post('/api/discipline', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'manage_discipline')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية تسجيل الانضباط والنقاط' });
    }
    await ensureReady();
    const { userId, category, pointsDelta, note, logDate: rawLogDate } = req.body || {};
    const target = await findUserById(userId);
    if (!target || !note) return res.status(400).json({ error: 'يرجى اختيار الطالب وكتابة الملاحظة' });
    const delta = Number(pointsDelta || 0);
    const logDate = String(rawLogDate || '').trim() || new Date().toISOString().slice(0, 10);

    if (!isNeon) {
      const db = readLocal();
      db.counters.discipline += 1;
      const item = {
        id: db.counters.discipline, userId: target.id, userName: target.fullName, userCode: target.memberCode,
        unit: target.unit, category: category || 'commendation', pointsDelta: delta, note: note.trim(),
        recordedById: req.user.id, recordedByName: req.user.fullName, logDate, createdAt: new Date().toISOString(),
      };
      db.disciplineLogs.unshift(item);
      const u = db.users.find((x) => x.id === target.id);
      if (u) u.points = Math.max(0, Number(u.points || 0) + delta);
      writeLocal(db);
      return res.status(201).json({ log: item });
    }
    const p = getPool();
    const r = await p.query(
      `INSERT INTO discipline_logs (user_id, user_name, user_code, unit, category, points_delta, note, recorded_by_id, recorded_by_name, log_date)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [target.id, target.fullName, target.memberCode, target.unit, category || 'commendation', delta, note.trim(), req.user.id, req.user.fullName, logDate]
    );
    await p.query('UPDATE users SET points = GREATEST(0, points + $1) WHERE id=$2', [delta, target.id]);
    res.status(201).json({ log: mapDiscipline(r.rows[0]) });
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

app.get('/api/directives', requireAuth, async (_req, res) => {
  try {
    await ensureReady();
    if (!isNeon) {
      return res.json({ directives: readLocal().directives });
    }
    const r = await getPool().query('SELECT * FROM directives ORDER BY id DESC');
    res.json({ directives: r.rows.map(mapDirective) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب التوجيهات' });
  }
});

app.post('/api/directives', requireAuth, async (req, res) => {
  try {
    if (!hasPerm(req.user, 'issue_directives')) {
      return res.status(403).json({ error: 'ليس لديك صلاحية إصدار التوجيهات' });
    }
    await ensureReady();
    const { title, content, targetUnit, priority } = req.body || {};
    if (!title || !content) return res.status(400).json({ error: 'يرجى كتابة العنوان والنص' });
    const safeUnit = targetUnit || 'all';
    const ack = [req.user.id];
    if (!isNeon) {
      const db = readLocal();
      db.counters.directives += 1;
      const item = {
        id: db.counters.directives, title: title.trim(), content: content.trim(), targetUnit: safeUnit,
        priority: priority || 'normal', issuedById: req.user.id, issuedByName: req.user.fullName,
        issuedByRole: req.user.role, acknowledgedByIds: ack, createdAt: new Date().toISOString(),
      };
      db.directives.unshift(item);
      writeLocal(db);
      return res.status(201).json({ directive: item });
    }
    const r = await getPool().query(
      `INSERT INTO directives (title, content, target_unit, priority, issued_by_id, issued_by_name, issued_by_role, acknowledged_by_ids)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb) RETURNING *`,
      [title.trim(), content.trim(), safeUnit, priority || 'normal', req.user.id, req.user.fullName, req.user.role, JSON.stringify(ack)]
    );
    res.status(201).json({ directive: mapDirective(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر نشر التوجيه' });
  }
});

app.post('/api/directives/:id/ack', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const id = Number(req.params.id);
    const uid = req.user.id;
    if (!isNeon) {
      const db = readLocal();
      const dir = db.directives.find((d) => d.id === id);
      if (!dir) return res.status(404).json({ error: 'التوجيه غير موجود' });
      dir.acknowledgedByIds = Array.isArray(dir.acknowledgedByIds) ? dir.acknowledgedByIds : [];
      if (!dir.acknowledgedByIds.includes(uid)) dir.acknowledgedByIds.push(uid);
      writeLocal(db);
      return res.json({ directive: dir });
    }
    const p = getPool();
    const curR = await p.query('SELECT * FROM directives WHERE id=$1', [id]);
    if (curR.rowCount === 0) return res.status(404).json({ error: 'التوجيه غير موجود' });
    const mapped = mapDirective(curR.rows[0]);
    const nextAck = mapped.acknowledgedByIds.includes(uid) ? mapped.acknowledgedByIds : [...mapped.acknowledgedByIds, uid];
    const r = await p.query('UPDATE directives SET acknowledged_by_ids=$1::jsonb WHERE id=$2 RETURNING *', [JSON.stringify(nextAck), id]);
    res.json({ directive: mapDirective(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر تأكيد الاطلاع' });
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

app.get('/api/reports', requireAuth, async (req, res) => {
  try {
    if (!isMgmt(req.user.role) && !hasPerm(req.user, 'manage_activities')) {
      return res.status(403).json({ error: 'الاطلاع على تقارير البرامج مخصص للإدارة فقط' });
    }
    await ensureReady();
    if (!isNeon) {
      return res.json({ reports: readLocal().programReports || [] });
    }
    const r = await getPool().query('SELECT * FROM program_reports ORDER BY id DESC');
    res.json({ reports: r.rows.map(mapProgramReport) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب تقارير البرامج' });
  }
});

app.post('/api/reports/generate', requireAuth, async (req, res) => {
  try {
    if (!isMgmt(req.user.role) && !hasPerm(req.user, 'manage_activities')) {
      return res.status(403).json({ error: 'إعداد تقارير البرامج مخصص للإدارة فقط' });
    }
    const cleanTitle = String(req.body?.title || '').trim();
    if (!cleanTitle) return res.status(400).json({ error: 'يرجى كتابة عنوان البرنامج أولاً' });
    const cleanExec = String(req.body?.executors || req.user.fullName).trim();
    const generated = await generateProgramReportWithAI(cleanTitle, cleanExec, req.body?.executionDate);
    return res.json(generated);
  } catch {
    res.status(500).json({ error: 'تعذر توليد تفاصيل التقرير' });
  }
});

app.post('/api/reports', requireAuth, async (req, res) => {
  try {
    if (!isMgmt(req.user.role) && !hasPerm(req.user, 'manage_activities')) {
      return res.status(403).json({ error: 'إضافة تقارير البرامج مخصصة للإدارة فقط' });
    }
    await ensureReady();
    const { schoolName, departmentName, title, field, executors, executionDate, beneficiaries, beneficiariesCount, steps, objectives, images } = req.body || {};
    const cleanTitle = String(title || '').trim();
    const cleanExec = String(executors || '').trim();
    const cleanDate = String(executionDate || '').trim();
    if (!cleanTitle || !cleanExec || !cleanDate) {
      return res.status(400).json({ error: 'يرجى إدخال عنوان البرنامج والمنفذين وتاريخ التنفيذ' });
    }
    const safeStepsInput = Array.isArray(steps) ? steps.map((s) => String(s).trim()).filter(Boolean) : [];
    const safeObjsInput = Array.isArray(objectives) ? objectives.map((o) => String(o).trim()).filter(Boolean) : [];
    const needAI = !String(field || '').trim() || !safeStepsInput.length || !safeObjsInput.length;
    const aiData = needAI
      ? await generateProgramReportWithAI(cleanTitle, cleanExec, cleanDate)
      : buildFallbackReportContent(cleanTitle, cleanExec);

    const safeSteps = safeStepsInput.length ? safeStepsInput : aiData.steps;
    const safeObjs = safeObjsInput.length ? safeObjsInput : aiData.objectives;
    const safeImgs = Array.isArray(images) ? images.map(String).filter((x) => x.startsWith('data:image/')).slice(0, 4) : [];
    const safeSchool = String(schoolName || '').trim() || 'مدرسة الحديبية المتوسطة';
    const safeDept = String(departmentName || '').trim() || 'النشاط الطلابي';
    const safeField = String(field || '').trim() || aiData.field;
    const safeBen = String(beneficiaries || '').trim() || aiData.beneficiaries;
    const safeCnt = String(beneficiariesCount || '').trim() || aiData.beneficiariesCount;

    if (!isNeon) {
      const db = readLocal();
      db.counters.programReports = (db.counters.programReports || 0) + 1;
      db.programReports = db.programReports || [];
      const item = {
        id: db.counters.programReports, schoolName: safeSchool, departmentName: safeDept, title: cleanTitle, field: safeField,
        executors: cleanExec, executionDate: cleanDate, beneficiaries: safeBen, beneficiariesCount: safeCnt,
        steps: safeSteps, objectives: safeObjs, images: safeImgs,
        createdById: req.user.id, createdByName: req.user.fullName, createdAt: new Date().toISOString(),
      };
      db.programReports.unshift(item);
      writeLocal(db);
      return res.status(201).json({ report: item });
    }

    const r = await getPool().query(
      `INSERT INTO program_reports
        (school_name, department_name, title, field, executors, execution_date, beneficiaries, beneficiaries_count, steps, objectives, images, created_by_id, created_by_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb,$12,$13) RETURNING *`,
      [safeSchool, safeDept, cleanTitle, safeField, cleanExec, cleanDate, safeBen, safeCnt, JSON.stringify(safeSteps), JSON.stringify(safeObjs), JSON.stringify(safeImgs), req.user.id, req.user.fullName]
    );
    const row = r.rows[0];
    res.status(201).json({
      report: {
        id: row.id, schoolName: row.school_name, departmentName: row.department_name || 'النشاط الطلابي',
        title: row.title, field: row.field, executors: row.executors,
        executionDate: row.execution_date, beneficiaries: row.beneficiaries, beneficiariesCount: row.beneficiaries_count,
        steps: row.steps || [], objectives: row.objectives || [], images: row.images || [],
        createdById: row.created_by_id, createdByName: row.created_by_name,
      },
    });
  } catch {
    res.status(500).json({ error: 'تعذر حفظ التقرير' });
  }
});

app.patch('/api/reports/:id', requireAuth, async (req, res) => {
  try {
    if (!isMgmt(req.user.role) && !hasPerm(req.user, 'manage_activities')) {
      return res.status(403).json({ error: 'تعديل التقارير مخصص للإدارة فقط' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    const body = req.body || {};

    if (!isNeon) {
      const db = readLocal();
      db.programReports = db.programReports || [];
      const item = db.programReports.find((r) => r.id === id);
      if (!item) return res.status(404).json({ error: 'التقرير غير موجود' });
      if (body.schoolName !== undefined) item.schoolName = String(body.schoolName).trim() || 'مدرسة الحديبية المتوسطة';
      if (body.departmentName !== undefined) item.departmentName = String(body.departmentName).trim() || 'النشاط الطلابي';
      if (body.title !== undefined && String(body.title).trim()) item.title = String(body.title).trim();
      if (body.field !== undefined) item.field = String(body.field).trim();
      if (body.executors !== undefined && String(body.executors).trim()) item.executors = String(body.executors).trim();
      if (body.executionDate !== undefined && String(body.executionDate).trim()) item.executionDate = String(body.executionDate).trim();
      if (body.beneficiaries !== undefined) item.beneficiaries = String(body.beneficiaries).trim();
      if (body.beneficiariesCount !== undefined) item.beneficiariesCount = String(body.beneficiariesCount).trim();
      if (Array.isArray(body.steps)) item.steps = body.steps.map((s) => String(s).trim()).filter(Boolean);
      if (Array.isArray(body.objectives)) item.objectives = body.objectives.map((o) => String(o).trim()).filter(Boolean);
      if (Array.isArray(body.images)) item.images = body.images.map(String).filter((x) => x.startsWith('data:image/')).slice(0, 4);
      writeLocal(db);
      return res.json({ report: item });
    }

    const r = await getPool().query(
      `UPDATE program_reports SET
        school_name = COALESCE($1, school_name),
        department_name = COALESCE($2, department_name),
        title = COALESCE($3, title),
        field = COALESCE($4, field),
        executors = COALESCE($5, executors),
        execution_date = COALESCE($6, execution_date),
        beneficiaries = COALESCE($7, beneficiaries),
        beneficiaries_count = COALESCE($8, beneficiaries_count),
        steps = COALESCE($9::jsonb, steps),
        objectives = COALESCE($10::jsonb, objectives),
        images = COALESCE($11::jsonb, images)
       WHERE id=$12 RETURNING *`,
      [
        body.schoolName !== undefined ? (String(body.schoolName).trim() || 'مدرسة الحديبية المتوسطة') : null,
        body.departmentName !== undefined ? (String(body.departmentName).trim() || 'النشاط الطلابي') : null,
        body.title !== undefined && String(body.title).trim() ? String(body.title).trim() : null,
        body.field !== undefined ? String(body.field).trim() : null,
        body.executors !== undefined && String(body.executors).trim() ? String(body.executors).trim() : null,
        body.executionDate !== undefined && String(body.executionDate).trim() ? String(body.executionDate).trim() : null,
        body.beneficiaries !== undefined ? String(body.beneficiaries).trim() : null,
        body.beneficiariesCount !== undefined ? String(body.beneficiariesCount).trim() : null,
        Array.isArray(body.steps) ? JSON.stringify(body.steps.map((s) => String(s).trim()).filter(Boolean)) : null,
        Array.isArray(body.objectives) ? JSON.stringify(body.objectives.map((o) => String(o).trim()).filter(Boolean)) : null,
        Array.isArray(body.images) ? JSON.stringify(body.images.map(String).filter((x) => x.startsWith('data:image/')).slice(0, 4)) : null,
        id,
      ]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'التقرير غير موجود' });
    const row = r.rows[0];
    res.json({
      report: {
        id: row.id, schoolName: row.school_name, departmentName: row.department_name || 'النشاط الطلابي',
        title: row.title, field: row.field, executors: row.executors,
        executionDate: row.execution_date, beneficiaries: row.beneficiaries, beneficiariesCount: row.beneficiaries_count,
        steps: row.steps || [], objectives: row.objectives || [], images: row.images || [],
        createdById: row.created_by_id, createdByName: row.created_by_name,
      },
    });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث التقرير' });
  }
});

app.delete('/api/reports/:id', requireAuth, async (req, res) => {
  try {
    if (!isMgmt(req.user.role) && !hasPerm(req.user, 'manage_activities')) {
      return res.status(403).json({ error: 'حذف التقارير مخصص للإدارة فقط' });
    }
    await ensureReady();
    const id = Number(req.params.id);
    if (!isNeon) {
      const db = readLocal();
      db.programReports = (db.programReports || []).filter((r) => r.id !== id);
      writeLocal(db);
      return res.json({ ok: true });
    }
    await getPool().query('DELETE FROM program_reports WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف التقرير' });
  }
});

app.get('/api/certificates', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const viewer = req.user;
    if (!isNeon) {
      const list = readLocal().certificates || [];
      return res.json({
        certificates: isMgmt(viewer.role) ? list : list.filter((c) => c.studentId === viewer.id),
      });
    }
    const p = getPool();
    const r = isMgmt(viewer.role)
      ? await p.query('SELECT * FROM certificates ORDER BY id DESC')
      : await p.query('SELECT * FROM certificates WHERE student_id=$1 ORDER BY id DESC', [viewer.id]);
    res.json({ certificates: r.rows.map(mapCertificate) });
  } catch {
    res.status(500).json({ error: 'تعذر جلب الشهادات' });
  }
});

app.post('/api/certificates', requireAuth, requireMgmt, async (req, res) => {
  try {
    await ensureReady();
    const u = req.user;
    const b = req.body || {};
    const recipientName = String(b.recipientName || '').trim();
    const reason = String(b.reason || '').trim();
    const issueDate = String(b.issueDate || '').trim();
    if (!recipientName || !reason || !issueDate) {
      return res.status(400).json({ error: 'يرجى إدخال اسم المكرّم ونص الشهادة وتاريخ الإصدار' });
    }
    const tpl = ALLOWED_CERT_TEMPLATES.includes(b.templateStyle) ? b.templateStyle : 'emerald_gold';
    const itemInput = {
      studentId: b.studentId ? Number(b.studentId) : null,
      recipientName,
      gradeOrTitle: String(b.gradeOrTitle || '').trim(),
      certificateType: String(b.certificateType || '').trim() || 'شهادة شكر وتقدير',
      reason,
      schoolName: String(b.schoolName || '').trim() || 'مدرسة الحديبية المتوسطة',
      issuerTitle: String(b.issuerTitle || '').trim() || 'رئيس النشاط الطلابي',
      issuerName: String(b.issuerName || '').trim() || u.fullName,
      principalName: String(b.principalName || '').trim(),
      issueDate,
      templateStyle: tpl,
      createdById: u.id,
      createdByName: u.fullName,
    };
    if (!isNeon) {
      const db = readLocal();
      db.counters = db.counters || {};
      db.counters.certificates = (db.counters.certificates || 0) + 1;
      db.certificates = db.certificates || [];
      const created = { id: db.counters.certificates, ...itemInput, createdAt: new Date().toISOString() };
      db.certificates.unshift(created);
      writeLocal(db);
      return res.status(201).json({ certificate: created });
    }
    const r = await getPool().query(
      `INSERT INTO certificates (student_id, recipient_name, grade_or_title, certificate_type, reason, school_name, issuer_title, issuer_name, principal_name, issue_date, template_style, created_by_id, created_by_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [
        itemInput.studentId, itemInput.recipientName, itemInput.gradeOrTitle, itemInput.certificateType,
        itemInput.reason, itemInput.schoolName, itemInput.issuerTitle, itemInput.issuerName,
        itemInput.principalName, itemInput.issueDate, itemInput.templateStyle, itemInput.createdById, itemInput.createdByName,
      ]
    );
    res.status(201).json({ certificate: mapCertificate(r.rows[0]) });
  } catch (e) {
    res.status(500).json({ error: e.message || 'تعذر إصدار الشهادة' });
  }
});

app.patch('/api/certificates/:id', requireAuth, requireMgmt, async (req, res) => {
  try {
    await ensureReady();
    const id = Number(req.params.id);
    const b = req.body || {};
    if (!isNeon) {
      const db = readLocal();
      const idx = (db.certificates || []).findIndex((c) => c.id === id);
      if (idx === -1) return res.status(404).json({ error: 'الشهادة غير موجودة' });
      const cur = db.certificates[idx];
      db.certificates[idx] = {
        ...cur,
        ...(b.studentId !== undefined ? { studentId: b.studentId ? Number(b.studentId) : null } : {}),
        ...(b.recipientName !== undefined && String(b.recipientName).trim() ? { recipientName: String(b.recipientName).trim() } : {}),
        ...(b.gradeOrTitle !== undefined ? { gradeOrTitle: String(b.gradeOrTitle).trim() } : {}),
        ...(b.certificateType !== undefined && String(b.certificateType).trim() ? { certificateType: String(b.certificateType).trim() } : {}),
        ...(b.reason !== undefined && String(b.reason).trim() ? { reason: String(b.reason).trim() } : {}),
        ...(b.schoolName !== undefined ? { schoolName: String(b.schoolName).trim() || 'مدرسة الحديبية المتوسطة' } : {}),
        ...(b.issuerTitle !== undefined ? { issuerTitle: String(b.issuerTitle).trim() || 'رئيس النشاط الطلابي' } : {}),
        ...(b.issuerName !== undefined ? { issuerName: String(b.issuerName).trim() } : {}),
        ...(b.principalName !== undefined ? { principalName: String(b.principalName).trim() } : {}),
        ...(b.issueDate !== undefined && String(b.issueDate).trim() ? { issueDate: String(b.issueDate).trim() } : {}),
        ...(ALLOWED_CERT_TEMPLATES.includes(b.templateStyle) ? { templateStyle: b.templateStyle } : {}),
      };
      writeLocal(db);
      return res.json({ certificate: db.certificates[idx] });
    }
    const p = getPool();
    const curRes = await p.query('SELECT * FROM certificates WHERE id=$1', [id]);
    if (curRes.rowCount === 0) return res.status(404).json({ error: 'الشهادة غير موجودة' });
    const cur = mapCertificate(curRes.rows[0]);
    const next = {
      ...cur,
      ...(b.studentId !== undefined ? { studentId: b.studentId ? Number(b.studentId) : null } : {}),
      ...(b.recipientName !== undefined && String(b.recipientName).trim() ? { recipientName: String(b.recipientName).trim() } : {}),
      ...(b.gradeOrTitle !== undefined ? { gradeOrTitle: String(b.gradeOrTitle).trim() } : {}),
      ...(b.certificateType !== undefined && String(b.certificateType).trim() ? { certificateType: String(b.certificateType).trim() } : {}),
      ...(b.reason !== undefined && String(b.reason).trim() ? { reason: String(b.reason).trim() } : {}),
      ...(b.schoolName !== undefined ? { schoolName: String(b.schoolName).trim() || 'مدرسة الحديبية المتوسطة' } : {}),
      ...(b.issuerTitle !== undefined ? { issuerTitle: String(b.issuerTitle).trim() || 'رئيس النشاط الطلابي' } : {}),
      ...(b.issuerName !== undefined ? { issuerName: String(b.issuerName).trim() } : {}),
      ...(b.principalName !== undefined ? { principalName: String(b.principalName).trim() } : {}),
      ...(b.issueDate !== undefined && String(b.issueDate).trim() ? { issueDate: String(b.issueDate).trim() } : {}),
      ...(ALLOWED_CERT_TEMPLATES.includes(b.templateStyle) ? { templateStyle: b.templateStyle } : {}),
    };
    const r = await p.query(
      `UPDATE certificates SET student_id=$1, recipient_name=$2, grade_or_title=$3, certificate_type=$4, reason=$5, school_name=$6, issuer_title=$7, issuer_name=$8, principal_name=$9, issue_date=$10, template_style=$11 WHERE id=$12 RETURNING *`,
      [
        next.studentId, next.recipientName, next.gradeOrTitle, next.certificateType,
        next.reason, next.schoolName, next.issuerTitle, next.issuerName,
        next.principalName, next.issueDate, next.templateStyle, id,
      ]
    );
    res.json({ certificate: mapCertificate(r.rows[0]) });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث الشهادة' });
  }
});

app.delete('/api/certificates/:id', requireAuth, requireMgmt, async (req, res) => {
  try {
    await ensureReady();
    const id = Number(req.params.id);
    if (!isNeon) {
      const db = readLocal();
      const before = (db.certificates || []).length;
      db.certificates = (db.certificates || []).filter((c) => c.id !== id);
      if (db.certificates.length === before) return res.status(404).json({ error: 'الشهادة غير موجودة' });
      writeLocal(db);
      return res.json({ ok: true });
    }
    const r = await getPool().query('DELETE FROM certificates WHERE id=$1 RETURNING id', [id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'الشهادة غير موجودة' });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف الشهادة' });
  }
});

app.get('/api/leaderboard', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    let entries;
    if (!isNeon) {
      const db = readLocal();
      entries = computeLeaderboard(db.users, db.submissions || []);
    } else {
      const p = getPool();
      const [lbUR, lbSubR] = await Promise.all([
        p.query('SELECT id, member_code, full_name, role, unit, grade_or_dept, points, is_active, badges_json FROM users ORDER BY id ASC'),
        p.query("SELECT student_id, status FROM submissions WHERE status = 'approved'"),
      ]);
      entries = computeLeaderboard(lbUR.rows, lbSubR.rows);
    }
    const myRank = entries.find((e) => e.id === req.user.id)?.rank ?? null;
    res.json({ entries, myRank, totalRanked: entries.length, updatedAt: new Date().toISOString() });
  } catch {
    res.status(500).json({ error: 'تعذر جلب لوحة الترتيب' });
  }
});

app.post('/api/users/:id/badges', requireAuth, requireMgmt, async (req, res) => {
  try {
    await ensureReady();
    const id = Number(req.params.id);
    const { key, label, tone, icon } = req.body || {};
    const cleanLabel = String(label || '').trim();
    if (!cleanLabel) return res.status(400).json({ error: 'يرجى كتابة اسم الشارة' });
    const target = await findUserById(id);
    if (!target) return res.status(404).json({ error: 'الطالب غير موجود' });

    const safeTone = ALLOWED_BADGE_TONES.includes(tone) ? tone : 'emerald';
    const safeIcon = ALLOWED_BADGE_ICONS.includes(icon) ? icon : 'star';
    const cleanKey = String(key || '').trim() || `custom_${Date.now()}`;
    const currentBadges = parseBadgesJson(target.badges);

    if (currentBadges.some((b) => (key && b.key === key) || b.label === cleanLabel)) {
      return res.status(400).json({ error: 'هذه الشارة ممنوحة للطالب مسبقاً' });
    }

    const badge = {
      id: `bdg_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      key: cleanKey,
      label: cleanLabel,
      tone: safeTone,
      icon: safeIcon,
      awardedAt: new Date().toISOString().slice(0, 10),
      awardedByName: req.user.fullName,
    };
    const nextBadges = [...currentBadges, badge];

    if (!isNeon) {
      const db = readLocal();
      const idx = db.users.findIndex((u) => u.id === id);
      if (idx === -1) return res.status(404).json({ error: 'الطالب غير موجود' });
      db.users[idx].badges = nextBadges;
      writeLocal(db);
      return res.status(201).json({ user: sanitizeUser(db.users[idx], req.user), badge });
    }

    const r = await getPool().query('UPDATE users SET badges_json=$1 WHERE id=$2 RETURNING *', [JSON.stringify(nextBadges), id]);
    res.status(201).json({ user: sanitizeUser(mapUser(r.rows[0]), req.user), badge });
  } catch {
    res.status(500).json({ error: 'تعذر منح الشارة' });
  }
});

app.delete('/api/users/:id/badges/:badgeId', requireAuth, requireMgmt, async (req, res) => {
  try {
    await ensureReady();
    const id = Number(req.params.id);
    const badgeId = String(req.params.badgeId || '').trim();
    const target = await findUserById(id);
    if (!target) return res.status(404).json({ error: 'الطالب غير موجود' });
    const nextBadges = parseBadgesJson(target.badges).filter((b) => b.id !== badgeId);

    if (!isNeon) {
      const db = readLocal();
      const idx = db.users.findIndex((u) => u.id === id);
      if (idx === -1) return res.status(404).json({ error: 'الطالب غير موجود' });
      db.users[idx].badges = nextBadges;
      writeLocal(db);
      return res.json({ user: sanitizeUser(db.users[idx], req.user) });
    }

    const r = await getPool().query('UPDATE users SET badges_json=$1 WHERE id=$2 RETURNING *', [JSON.stringify(nextBadges), id]);
    res.json({ user: sanitizeUser(mapUser(r.rows[0]), req.user) });
  } catch {
    res.status(500).json({ error: 'تعذر إزالة الشارة' });
  }
});

// ===== الدردشة العامة — البث المباشر والحذف التلقائي بعد يومين =====
const mapPgChatMessage = (r) => {
  let replyTo = r.reply_to;
  if (typeof replyTo === 'string') {
    try { replyTo = JSON.parse(replyTo); } catch { replyTo = null; }
  }
  return {
    id: r.id,
    senderId: Number(r.sender_id),
    senderName: r.sender_name || '',
    senderRole: r.sender_role || 'member',
    senderUnit: r.sender_unit || 'activity_1',
    senderIsSupreme: Boolean(r.sender_is_supreme),
    text: r.text_content || '',
    imageData: r.image_data || null,
    replyTo: replyTo || null,
    createdAt: new Date(r.created_at).toISOString(),
    expiresAt: new Date(r.expires_at).toISOString(),
  };
};

const mapPgChatSettings = (r) => ({
  mutedAll: Boolean(r?.muted_all),
  mutedByName: r?.muted_by_name || null,
  updatedAt: r?.updated_at ? new Date(r.updated_at).toISOString() : new Date().toISOString(),
});

async function purgeExpiredChatMessages() {
  await ensureReady();
  if (!isNeon) {
    const db = readLocal();
    const nowMs = Date.now();
    const prevLen = db.chatMessages.length;
    db.chatMessages = db.chatMessages.filter((m) => {
      const expMs = Date.parse(m.expiresAt || '');
      const createdMs = Date.parse(m.createdAt || '');
      if (Number.isFinite(expMs)) return expMs > nowMs;
      if (Number.isFinite(createdMs)) return nowMs - createdMs < CHAT_RETENTION_MS;
      return true;
    });
    const removed = prevLen - db.chatMessages.length;
    if (removed > 0) writeLocal(db);
    return removed;
  }
  const r = await getPool().query(
    "DELETE FROM chat_messages WHERE expires_at <= NOW() OR created_at <= NOW() - INTERVAL '2 days'"
  );
  return r.rowCount ?? 0;
}

async function getChatSettings() {
  await ensureReady();
  if (!isNeon) return readLocal().chatSettings;
  const r = await getPool().query('SELECT * FROM chat_settings WHERE id = 1 LIMIT 1');
  return mapPgChatSettings(r.rows[0]);
}

async function setChatMute(mutedAll, actorName) {
  await ensureReady();
  const mutedByName = mutedAll ? actorName : null;
  if (!isNeon) {
    const db = readLocal();
    db.chatSettings = { mutedAll, mutedByName, updatedAt: new Date().toISOString() };
    writeLocal(db);
    return db.chatSettings;
  }
  const r = await getPool().query(
    `INSERT INTO chat_settings (id, muted_all, muted_by_name, updated_at)
     VALUES (1, $1, $2, NOW())
     ON CONFLICT (id) DO UPDATE SET muted_all = $1, muted_by_name = $2, updated_at = NOW()
     RETURNING *`,
    [mutedAll, mutedByName]
  );
  return mapPgChatSettings(r.rows[0]);
}

async function listChatMessages(limit = 150) {
  await purgeExpiredChatMessages();
  if (!isNeon) {
    return readLocal().chatMessages.slice(-limit);
  }
  const r = await getPool().query(
    'SELECT * FROM (SELECT * FROM chat_messages ORDER BY id DESC LIMIT $1) sub ORDER BY id ASC',
    [limit]
  );
  return r.rows.map(mapPgChatMessage);
}

const chatClients = new Set();

function getOnlineChatUsers() {
  const byId = new Map();
  for (const c of chatClients) {
    if (c.ws.readyState !== WebSocket.OPEN) continue;
    if (!byId.has(c.user.id)) {
      byId.set(c.user.id, {
        id: c.user.id,
        fullName: c.user.fullName,
        role: c.user.role,
        isSupreme: isSupremePresident(c.user),
      });
    }
  }
  const roleWeight = (u) => {
    if (u.isSupreme) return 0;
    if (u.role === 'president') return 1;
    if (u.role === 'vice_president') return 2;
    if (u.role === 'officer') return 3;
    return 4;
  };
  return Array.from(byId.values()).sort((a, b) => {
    const d = roleWeight(a) - roleWeight(b);
    return d !== 0 ? d : a.fullName.localeCompare(b.fullName, 'ar');
  });
}

function broadcastChatEvent(payload) {
  const raw = JSON.stringify(payload);
  for (const c of chatClients) {
    if (c.ws.readyState === WebSocket.OPEN) {
      try { c.ws.send(raw); } catch { /* ignore */ }
    }
  }
}

function broadcastChatPresence() {
  broadcastChatEvent({ type: 'chat:presence', onlineUsers: getOnlineChatUsers() });
}

app.get('/api/chat/state', requireAuth, async (_req, res) => {
  try {
    const [messages, settings] = await Promise.all([listChatMessages(150), getChatSettings()]);
    res.json({
      messages,
      settings,
      onlineUsers: getOnlineChatUsers(),
      retentionHours: CHAT_RETENTION_HOURS,
    });
  } catch {
    res.status(500).json({ error: 'تعذر تحميل بيانات الدردشة' });
  }
});

app.post('/api/chat/messages', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const settings = await getChatSettings();
    if (settings.mutedAll && !canModerateChat(user)) {
      return res.status(403).json({
        error: settings.mutedByName
          ? `الدردشة مكتومة حالياً من قِبل ${settings.mutedByName}`
          : 'الدردشة مكتومة حالياً من قِبل القيادة',
      });
    }

    const body = req.body || {};
    const text = String(body.text || '').trim().slice(0, 1500);
    let imageData = null;
    if (typeof body.imageData === 'string' && body.imageData.trim()) {
      const candidate = body.imageData.trim();
      if (!/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(candidate)) {
        return res.status(400).json({ error: 'صيغة الصورة غير مدعومة (يرجى رفع PNG أو JPG أو WebP)' });
      }
      if (candidate.length > MAX_CHAT_IMAGE_CHARS) {
        return res.status(400).json({ error: 'حجم الصورة كبير جداً بعد الضغط، يرجى اختيار صورة أصغر' });
      }
      imageData = candidate;
    }

    if (!text && !imageData) {
      return res.status(400).json({ error: 'يرجى كتابة رسالة أو إرفاق صورة قبل الإرسال' });
    }

    let replyTo = null;
    if (body.replyTo && Number.isFinite(Number(body.replyTo.id))) {
      replyTo = {
        id: Number(body.replyTo.id),
        senderName: String(body.replyTo.senderName || '').trim().slice(0, 80) || 'عضو',
        snippet: String(body.replyTo.snippet || '').trim().slice(0, 140) || 'صورة مرفقة',
      };
    }

    await purgeExpiredChatMessages();
    let message;
    if (!isNeon) {
      const db = readLocal();
      db.counters.chatMessages += 1;
      const nowMs = Date.now();
      message = {
        id: db.counters.chatMessages,
        senderId: user.id,
        senderName: user.fullName,
        senderRole: user.role,
        senderUnit: user.unit,
        senderIsSupreme: isSupremePresident(user),
        text,
        imageData,
        replyTo,
        createdAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(nowMs + CHAT_RETENTION_MS).toISOString(),
      };
      db.chatMessages.push(message);
      writeLocal(db);
    } else {
      const r = await getPool().query(
        `INSERT INTO chat_messages
          (sender_id, sender_name, sender_role, sender_unit, sender_is_supreme, text_content, image_data, reply_to, created_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb, NOW(), NOW() + INTERVAL '2 days') RETURNING *`,
        [
          user.id,
          user.fullName,
          user.role,
          user.unit,
          isSupremePresident(user),
          text,
          imageData,
          replyTo ? JSON.stringify(replyTo) : null,
        ]
      );
      message = mapPgChatMessage(r.rows[0]);
    }

    broadcastChatEvent({ type: 'chat:message:created', message });
    res.status(201).json({ message });
  } catch {
    res.status(500).json({ error: 'تعذر إرسال الرسالة' });
  }
});

app.delete('/api/chat/messages/:id', requireAuth, async (req, res) => {
  try {
    await ensureReady();
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'معرف الرسالة غير صالح' });
    let existing = null;
    if (!isNeon) {
      existing = readLocal().chatMessages.find((m) => m.id === id) || null;
    } else {
      const r = await getPool().query('SELECT * FROM chat_messages WHERE id = $1 LIMIT 1', [id]);
      existing = r.rows[0] ? mapPgChatMessage(r.rows[0]) : null;
    }
    if (!existing) return res.status(404).json({ error: 'الرسالة غير موجودة أو انتهت صلاحيتها' });
    if (existing.senderId !== req.user.id && !canModerateChat(req.user)) {
      return res.status(403).json({ error: 'لا يمكنك حذف رسائل الآخرين' });
    }
    if (!isNeon) {
      const db = readLocal();
      db.chatMessages = db.chatMessages.filter((m) => m.id !== id);
      writeLocal(db);
    } else {
      await getPool().query('DELETE FROM chat_messages WHERE id = $1', [id]);
    }
    broadcastChatEvent({ type: 'chat:message:deleted', id });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر حذف الرسالة' });
  }
});

app.post('/api/chat/clear', requireAuth, async (req, res) => {
  try {
    if (!canModerateChat(req.user)) {
      return res.status(403).json({ error: 'مسح الدردشة مخصص للرئيس المؤسس ونائب الرئيس فقط' });
    }
    await ensureReady();
    if (!isNeon) {
      const db = readLocal();
      db.chatMessages = [];
      writeLocal(db);
    } else {
      await getPool().query('DELETE FROM chat_messages');
    }
    broadcastChatEvent({ type: 'chat:cleared', clearedByName: req.user.fullName });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'تعذر مسح المحادثة' });
  }
});

app.patch('/api/chat/mute', requireAuth, async (req, res) => {
  try {
    if (!canModerateChat(req.user)) {
      return res.status(403).json({ error: 'التحكم بإسكات الدردشة مخصص للرئيس المؤسس ونائب الرئيس فقط' });
    }
    const mutedAll = Boolean(req.body?.mutedAll);
    const settings = await setChatMute(mutedAll, req.user.fullName);
    broadcastChatEvent({ type: 'chat:mute:updated', settings });
    res.json({ settings });
  } catch {
    res.status(500).json({ error: 'تعذر تحديث حالة إسكات الدردشة' });
  }
});

app.get(['/app.js', '/assets/app.js'], (_req, res) => {
  res.sendFile(path.join(__dirname, 'app.js'));
});

app.get(['/app.css', '/assets/app.css'], (_req, res) => {
  res.sendFile(path.join(__dirname, 'app.css'));
});

app.get(['/moe-logo.png', '/assets/moe-logo.png'], (_req, res) => {
  res.sendFile(path.join(__dirname, 'moe-logo.png'));
});

app.get(['/portal_hero_scene_1794824065167.jpg', '/src/assets/images/portal_hero_scene_1794824065167.jpg'], (_req, res) => {
  res.sendFile(path.join(__dirname, 'portal_hero_scene_1794824065167.jpg'));
});

app.use('/assets', express.static(path.join(__dirname, 'assets'), {
  maxAge: '7d',
}));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

const httpServer = http.createServer(app);
const chatWss = new WebSocketServer({ noServer: true });

httpServer.on('upgrade', async (request, socket, head) => {
  try {
    const parsedUrl = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
    if (parsedUrl.pathname !== '/ws/chat') {
      socket.destroy();
      return;
    }
    const token = (parsedUrl.searchParams.get('token') || '').trim();
    if (!token) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    const payload = jwt.verify(token, JWT_SECRET);
    const rawUser = await findUserById(payload.userId);
    if (!rawUser || !rawUser.isActive) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    const user = sanitizeUser(rawUser);

    chatWss.handleUpgrade(request, socket, head, async (ws) => {
      const client = { ws, user, isAlive: true };
      chatClients.add(client);

      ws.on('pong', () => { client.isAlive = true; });
      ws.on('close', () => { chatClients.delete(client); broadcastChatPresence(); });
      ws.on('error', () => { chatClients.delete(client); broadcastChatPresence(); });

      try {
        const [messages, settings] = await Promise.all([listChatMessages(150), getChatSettings()]);
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: 'chat:init',
            messages,
            settings,
            onlineUsers: getOnlineChatUsers(),
            retentionHours: CHAT_RETENTION_HOURS,
          }));
        }
        broadcastChatPresence();
      } catch { /* ignore */ }
    });
  } catch {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
  }
});

const wsHeartbeat = setInterval(() => {
  let changed = false;
  for (const c of chatClients) {
    if (!c.isAlive) {
      chatClients.delete(c);
      c.ws.terminate();
      changed = true;
      continue;
    }
    c.isAlive = false;
    try { c.ws.ping(); } catch { chatClients.delete(c); changed = true; }
  }
  if (changed) broadcastChatPresence();
}, 30_000);
wsHeartbeat.unref?.();

const chatPurgeTimer = setInterval(async () => {
  try {
    const removed = await purgeExpiredChatMessages();
    if (removed > 0 && chatClients.size > 0) {
      const messages = await listChatMessages(150);
      broadcastChatEvent({ type: 'chat:purged', removedCount: removed, messages });
    }
  } catch { /* ignore */ }
}, 15 * 60 * 1000);
chatPurgeTimer.unref?.();

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Student Activity System running on port ${PORT}`);
});
