import 'dotenv/config';
import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { sendViaGmailRelay, verifyGmailRelay } from './gmailRelay';
import { buildProfessionalEmail } from './emailTemplate';
import { createServer as createViteServer } from 'vite';
import { INITIAL_USERS, INITIAL_STATIONS, INITIAL_SAMPLES, INITIAL_NOTIFICATION_CONFIG } from './src/data/initialData';
import { loadSupabaseState, persistSupabaseState, supabaseConfigured } from './supabaseStore';

// ============================================================
// AUTH: password hashing + signed session tokens
// ============================================================
// Uses only Node's built-in `crypto` module (scrypt for password hashing,
// HMAC-SHA256 for signing tokens) — no extra dependency needed.
//
// Password format stored in ServerState.users[].password:
//   "scrypt:<saltHex>:<hashHex>"
// Any value NOT in this format is treated as legacy plaintext (from before
// this fix) and is transparently upgraded to a hash the next time that user
// logs in successfully or is saved via the admin user-management screen.
// ============================================================

function hashPassword(plain: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function isHashedPassword(value: string | undefined | null): boolean {
  return typeof value === 'string' && value.startsWith('scrypt:') && value.split(':').length === 3;
}

function verifyPassword(plain: string, stored: string | undefined | null): boolean {
  if (!stored) return false;
  if (!isHashedPassword(stored)) {
    // Legacy plaintext password (pre-hash migration) — compare directly.
    return plain === stored;
  }
  const [, salt, hashHex] = stored.split(':');
  try {
    const candidate = crypto.scryptSync(plain, salt, 64);
    const expected = Buffer.from(hashHex, 'hex');
    if (candidate.length !== expected.length) return false;
    return crypto.timingSafeEqual(candidate, expected);
  } catch {
    return false;
  }
}

// Strip password before sending a user object to any client.
function sanitizeUser(u: any) {
  if (!u || typeof u !== 'object') return u;
  const { password, ...rest } = u;
  return rest;
}
function sanitizeUsers(list: any[]) {
  return (list || []).map(sanitizeUser);
}

// --- Session secret (used to sign tokens with HMAC) ---
// Prefer an explicit AUTH_SECRET env var (required for multi-instance /
// zero-downtime-restart deployments). Otherwise generate one on first boot
// and persist it to disk so tokens keep working across restarts on a single
// instance (e.g. Render's persistent disk).
const AUTH_SECRET_PATH = path.join(
  process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(process.cwd(), 'data'),
  'auth-secret.key'
);

function loadOrCreateAuthSecret(): string {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  try {
    if (fs.existsSync(AUTH_SECRET_PATH)) {
      const existing = fs.readFileSync(AUTH_SECRET_PATH, 'utf8').trim();
      if (existing) return existing;
    }
  } catch {}
  const generated = crypto.randomBytes(32).toString('hex');
  try {
    const dir = path.dirname(AUTH_SECRET_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(AUTH_SECRET_PATH, generated, { mode: 0o600 });
  } catch (e) {
    console.warn('Could not persist auth secret to disk (sessions will reset on restart):', e);
  }
  return generated;
}

const AUTH_SECRET = loadOrCreateAuthSecret();

const REMOVED_NOTIFICATION_KEYS = [
  'autoZaloEnabled', 'zaloWebhookUrl', 'zaloWebhookSecret', 'zaloBotToken',
  'zaloGroupId', 'zaloGroupChatId', 'zaloPersonalPhone', 'zaloPersonalChatId',
  'zaloPersonalPhones', 'zaloRecipientType',
];

function stripRemovedNotificationFields(value: any) {
  const cleaned = { ...(value || {}) };
  REMOVED_NOTIFICATION_KEYS.forEach(key => delete cleaned[key]);
  return cleaned;
}

function sanitizeConfig(config: any) {
  if (!config || typeof config !== 'object') return config;
  const emailConfig = stripRemovedNotificationFields(config);
  return {
    ...emailConfig,
    smtpPass: config.smtpPass ? '[PROTECTED]' : '',
  };
}

function mergeConfigPreservingSecrets(current: any, incoming: any) {
  const merged = {
    ...stripRemovedNotificationFields(current),
    ...stripRemovedNotificationFields(incoming),
  };
  if (!incoming || incoming.smtpPass === undefined || incoming.smtpPass === '' || incoming.smtpPass === '[PROTECTED]') {
    if (current?.smtpPass) merged.smtpPass = current.smtpPass;
    else delete merged.smtpPass;
  }
  return merged;
}
const TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days — field technicians may go long stretches offline

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(input: string): Buffer {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function signToken(payload: object): string {
  const body = base64url(JSON.stringify(payload));
  const sig = base64url(crypto.createHmac('sha256', AUTH_SECRET).update(body).digest());
  return `${body}.${sig}`;
}

function verifyToken(token: string | undefined | null): { userId: string; username: string } | null {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expectedSig = base64url(crypto.createHmac('sha256', AUTH_SECRET).update(body).digest());
  if (sig.length !== expectedSig.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
    return null;
  }
  try {
    const payload = JSON.parse(base64urlDecode(body).toString('utf8'));
    if (!payload.exp || Date.now() / 1000 > payload.exp) return null;
    return { userId: payload.sub, username: payload.username };
  } catch {
    return null;
  }
}

function issueToken(user: any): string {
  return signToken({
    sub: user.id,
    username: user.username,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
  });
}

// Server in-memory state for automated 7:00 AM Cron & Multi-user synchronization
interface ServerState {
  samples: any[];
  stations: any[];
  users: any[];
  config: {
    autoEmailEnabled?: boolean;
    emailRecipients?: string[];
    emailSender?: string;
    autoSendHour?: number;
    autoSendMinute?: number;
    smtpHost?: string;
    smtpPort?: number;
    smtpUser?: string;
    smtpPass?: string;
    smtpSecure?: boolean;
  };
  lastCronDate: string;
  lastCronLog: string;
  notificationLogs: any[];
}

// ============================================================
// DATA STORAGE
// ============================================================
// Có thể cấu hình thư mục lưu dữ liệu bằng biến môi trường:
// DATA_DIR=/var/lib/nenmau/data
//
// Nếu không cấu hình:
// - Development: ./data
// - Production: ./data
//
// LƯU Ý: Vercel filesystem không phải persistent database.
// ============================================================

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(process.cwd(), 'data');

const stateFilePath = path.join(DATA_DIR, 'server-state.json');
const tempStateFilePath = path.join(DATA_DIR, 'server-state.json.tmp');

function loadPersistedState(): ServerState {
  try {
    if (fs.existsSync(stateFilePath)) {
      const raw = fs.readFileSync(stateFilePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed.users)) {
        parsed.users = INITIAL_USERS;
      }
      if (!Array.isArray(parsed.stations)) {
        parsed.stations = INITIAL_STATIONS;
      }
      if (!Array.isArray(parsed.samples)) {
        parsed.samples = INITIAL_SAMPLES;
      }
      if (!Array.isArray(parsed.notificationLogs)) {
        parsed.notificationLogs = [];
      }
      if (!parsed.config || typeof parsed.config !== 'object') {
        parsed.config = INITIAL_NOTIFICATION_CONFIG;
      }
      return parsed;
    }
  } catch (e) {
    console.warn('Could not load server-state.json, using defaults:', e);
  }

  // Default initial server state
  const defaultState: ServerState = {
    samples: INITIAL_SAMPLES,
    stations: INITIAL_STATIONS,
    users: INITIAL_USERS,
    config: INITIAL_NOTIFICATION_CONFIG,
    lastCronDate: '',
    lastCronLog: 'Hệ thống vừa khởi động, sẵn sàng cho lịch phát 07:00 Sáng.',
    notificationLogs: []
  };

  try {
    const dir = path.dirname(stateFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(stateFilePath, JSON.stringify(defaultState, null, 2), 'utf8');
  } catch (e) {
    console.warn('Could not write default server-state.json:', e);
  }

  return defaultState;
}

// ============================================================
// SAFE PERSISTENCE
// ============================================================
// Supabase is the production source of truth. A local atomic JSON snapshot is
// retained only for development fallback and disaster recovery during startup.
// Writes are serialized so concurrent requests cannot overwrite each other.
// ============================================================

let saveQueue: Promise<void> = Promise.resolve();

function queuePersistedState(state: ServerState): Promise<void> {
  saveQueue = saveQueue
    .catch(() => undefined)
    .then(async () => {
      if (supabaseConfigured) {
        await persistSupabaseState(state);
        return;
      }

      if (process.env.NODE_ENV === 'production') {
        throw new Error('Thiếu SUPABASE_URL và SUPABASE_SERVICE_ROLE_KEY trong môi trường production.');
      }

      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      const json = JSON.stringify(state, null, 2);
      const fd = fs.openSync(tempStateFilePath, 'w');
      try {
        fs.writeSync(fd, json, 0, 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tempStateFilePath, stateFilePath);
    });

  return saveQueue;
}

// Giữ lại tên cũ để toàn bộ code hiện tại không phải sửa.
function savePersistedState(state: ServerState): Promise<void> {
  const snapshot = JSON.parse(JSON.stringify(state)) as ServerState;
  return queuePersistedState(snapshot);
}

let serverState: ServerState = loadPersistedState();

// One-time migration: hash any legacy plaintext passwords found in the
// loaded state (covers both a fresh INITIAL_USERS default and any existing
// data/server-state.json written before this fix).
(function migrateLegacyPasswords() {
  let changed = false;
  const users = (serverState as any).users || [];
  for (const u of users) {
    if (u && typeof u.password === 'string' && u.password && !isHashedPassword(u.password)) {
      u.password = hashPassword(u.password);
      changed = true;
    }
  }
  if (changed && !supabaseConfigured && process.env.NODE_ENV !== 'production') {
    console.log('[AUTH] Migrated legacy plaintext password(s) to hashed format.');
    void savePersistedState(serverState).catch(error => console.error('[AUTH MIGRATION SAVE ERROR]', error));
  }
})();

// Helper: Format Vietnamese Date
function formatDateVN(dateStr?: string): string {
  if (!dateStr) return '---';
  const parts = dateStr.split('-');
  if (parts.length === 3) {
    return `${parts[2]}/${parts[1]}/${parts[0]}`;
  }
  return dateStr;
}

function getVietnamDateIso(date = new Date()): string {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Ho_Chi_Minh',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(date);
  const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return `${values.year}-${values.month}-${values.day}`;
}

function refreshServerSampleStatus(sample: any): any {
  if (!sample || ['tested_passed', 'tested_failed', 'cancelled'].includes(sample.status)) return sample;
  const scheduled = typeof sample.scheduledTestDate === 'string' ? sample.scheduledTestDate : '';
  if (!scheduled) return sample;
  const today = getVietnamDateIso();
  const status = scheduled === today ? 'due_today' : scheduled < today ? 'overdue' : 'pending';
  return sample.status === status ? sample : { ...sample, status };
}

function getCurrentSamples(): any[] {
  return (serverState.samples || []).map(refreshServerSampleStatus);
}


// Shared professional HTML/plain-text template for automatic and manual reports.
async function sendConfiguredEmail(samples: any[], config: any, targetDate = getVietnamDateIso(), subject?: string) {
  const recipients = (Array.isArray(config?.emailRecipients) ? config.emailRecipients : [])
    .map((recipient: unknown) => String(recipient).trim())
    .filter((recipient: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient));
  if (recipients.length === 0) {
    return { success: false, message: 'Chưa cấu hình địa chỉ email người nhận hợp lệ.' };
  }

  const { html, text, urgentCount } = buildProfessionalEmail(samples, serverState.stations, {
    targetDate,
    title: 'BÁO CÁO LỊCH NÉN MẪU BÊ TÔNG',
    subtitle: 'Tự động nhắc nhở lịch kiểm định chất lượng bê tông',
  });
  const emailSubject = subject || `[TASAGO] Báo Cáo Lịch Nén Mẫu Bê Tông 07:00 Sáng - ${formatDateVN(targetDate)}`;
  const sender = String(config?.emailSender || 'Bê Tông Tasago').split('<')[0].trim() || 'Bê Tông Tasago';
  const result = await sendViaGmailRelay({
    recipients,
    subject: emailSubject,
    text,
    html,
    senderName: sender,
  });

  return {
    success: true,
    message: result.message || `Đã gửi email tới ${recipients.length} địa chỉ qua Gmail HTTPS relay.`,
    messageId: result.messageId,
    recipients,
    urgentCount,
  };
}

async function startServer() {
  try {
    if (supabaseConfigured) {
      serverState = await loadSupabaseState(serverState);
      let changed = false;
      for (const user of serverState.users || []) {
        if (user && typeof user.password === 'string' && user.password && !isHashedPassword(user.password)) {
          user.password = hashPassword(user.password);
          changed = true;
        }
      }
      if (changed) await persistSupabaseState(serverState);
    } else if (process.env.NODE_ENV === 'production') {
      throw new Error('Production yêu cầu SUPABASE_URL và SUPABASE_SERVICE_ROLE_KEY. Dữ liệu sẽ không được lưu vào filesystem ephemeral.');
    }
  } catch (error: any) {
    console.error('[STARTUP DATA STORE ERROR]', error?.message || error);
    process.exitCode = 1;
    return;
  }

  const app = express();
  // Render assigns the listening port through PORT. Keep 3000 as the local
  // development fallback, but never bind a fixed port in production.
  const configuredPort = Number(process.env.PORT || 3000);
  const PORT = Number.isInteger(configuredPort) && configuredPort > 0 ? configuredPort : 3000;

  // JSON & URL-encoded parsers
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // CORS headers for local APIs.
  // FRONTEND_ORIGIN was already declared as an env var in render.yaml but was
  // never actually read anywhere — the server always sent '*', which allows
  // ANY website to call these APIs from a user's browser. If FRONTEND_ORIGIN
  // is set, restrict to it; otherwise fall back to '*' to avoid breaking
  // existing local/dev setups that haven't configured it yet.
  const allowedOrigin = process.env.FRONTEND_ORIGIN || '*';
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    if (allowedOrigin !== '*') {
      res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  // ============================================================
  // AUTH MIDDLEWARE
  // ============================================================
  // Every route below that touches shared/sensitive data requires a valid
  // Bearer token (from the Authorization header, or ?token= for the SSE
  // stream, since EventSource can't set custom headers). Public endpoints:
  // /api/health and /api/auth/login.
  function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
    const header = req.headers['authorization'];
    const headerToken = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : undefined;
    const queryToken = typeof req.query?.token === 'string' ? req.query.token : undefined;
    const token = headerToken || queryToken;

    const claims = verifyToken(token);
    if (!claims) {
      return res.status(401).json({ success: false, message: 'Chưa đăng nhập hoặc phiên đã hết hạn. Vui lòng đăng nhập lại.' });
    }
    const user = ((serverState as any).users || []).find((u: any) => u.id === claims.userId);
    if (!user || user.active === false) {
      return res.status(401).json({ success: false, message: 'Tài khoản không tồn tại hoặc đã bị vô hiệu hóa.' });
    }
    (req as any).authUser = user;
    next();
  }

  function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
    if ((req as any).authUser?.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Bạn không có quyền quản trị thao tác này.' });
    }
    next();
  }

  function memberStationIds(user: any): Set<string> {
    const ids = new Set<string>();
    if (Array.isArray(user?.stationIds)) user.stationIds.forEach((id: unknown) => ids.add(String(id)));
    if (user?.stationId) ids.add(String(user.stationId));
    return ids;
  }

  function memberCanAccessStation(user: any, stationId: unknown): boolean {
    if (!user || user.role === 'admin') return true;
    const ids = memberStationIds(user);
    return Boolean(stationId) && (ids.has('all') || ids.has(String(stationId)));
  }

  function memberOwnsSample(user: any, sample: any): boolean {
    if (!user || user.role === 'admin') return true;
    const sameCreator = sample?.createdBy && sample.createdBy === user.username;
    const sameSampler = sample?.samplerName && user.fullName
      && sample.samplerName.trim().toLowerCase() === user.fullName.trim().toLowerCase();
    return Boolean(sameCreator || sameSampler);
  }

  function memberCanModifySample(user: any, sample: any): boolean {
    if (!user || user.role === 'admin') return true;
    return memberCanAccessStation(user, sample?.stationId) && memberOwnsSample(user, sample);
  }

  function memberOnlyChangesTestResult(existing: any, incoming: any): boolean {
    const hasTestResult = Object.prototype.hasOwnProperty.call(incoming || {}, 'testResult');
    return Object.keys(incoming || {}).every(key => {
      if (key === 'testResult') return true;
      if (key === 'status' || key === 'updatedAt') return hasTestResult;
      return JSON.stringify(incoming[key]) === JSON.stringify(existing?.[key]);
    });
  }

  function memberCanUpdateSample(user: any, existing: any, incoming: any): boolean {
    if (!user || user.role === 'admin') return true;
    if (existing?.stationId && incoming?.stationId && String(existing.stationId) !== String(incoming.stationId)) return false;
    if (memberCanModifySample(user, { ...(existing || {}), ...(incoming || {}) })) return true;
    return Boolean(existing) && memberCanAccessStation(user, existing.stationId) && memberOnlyChangesTestResult(existing, incoming);
  }

  // Login: the only write endpoint that stays public (it's how you get a token).
  app.post('/api/auth/login', (req, res) => {
    try {
      const { username, password } = req.body || {};
      if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập tên đăng nhập và mật khẩu.' });
      }
      const users = (serverState as any).users || [];
      const user = users.find((u: any) => u.username?.toLowerCase() === String(username).trim().toLowerCase());

      if (!user || !verifyPassword(password, user.password)) {
        return res.status(401).json({ success: false, message: 'Tên đăng nhập hoặc mật khẩu không chính xác.' });
      }
      if (user.active === false) {
        return res.status(403).json({ success: false, message: 'Tài khoản đã bị vô hiệu hóa.' });
      }

      // Upgrade legacy plaintext password to hashed form on successful login.
      if (!isHashedPassword(user.password)) {
        user.password = hashPassword(password);
        void savePersistedState(serverState).catch(error => console.error('[AUTH PASSWORD SAVE ERROR]', error));
      }

      const token = issueToken(user);
      return res.json({ success: true, token, user: sanitizeUser(user) });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // Lets the client silently check (when online) whether its cached token is
  // still valid, without forcing a full re-login. Also used to refresh the
  // cached user profile.
  app.get('/api/auth/verify', requireAuth, (req, res) => {
    return res.json({ success: true, user: sanitizeUser((req as any).authUser) });
  });

  // Self-service password change. The current password is always required;
  // the new password is stored only as a scrypt hash and never returned.
  app.post('/api/auth/change-password', requireAuth, async (req, res) => {
    try {
      const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
      const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
      const authUser = (req as any).authUser;

      if (!currentPassword || !newPassword) {
        return res.status(400).json({ success: false, message: 'Vui lòng nhập mật khẩu hiện tại và mật khẩu mới.' });
      }
      if (newPassword.length < 8) {
        return res.status(400).json({ success: false, message: 'Mật khẩu mới phải có ít nhất 8 ký tự.' });
      }
      if (currentPassword === newPassword) {
        return res.status(400).json({ success: false, message: 'Mật khẩu mới phải khác mật khẩu hiện tại.' });
      }

      const user = ((serverState as any).users || []).find((item: any) => item.id === authUser.id);
      if (!user || user.active === false) {
        return res.status(401).json({ success: false, message: 'Tài khoản không tồn tại hoặc đã bị vô hiệu hóa.' });
      }
      if (!verifyPassword(currentPassword, user.password)) {
        return res.status(401).json({ success: false, message: 'Mật khẩu hiện tại không chính xác.' });
      }

      user.password = hashPassword(newPassword);
      await savePersistedState(serverState);
      broadcastSseEvent({
        type: 'USERS_UPDATED',
        users: sanitizeUsers((serverState as any).users || []),
        timestamp: Date.now(),
      });

      return res.json({
        success: true,
        message: 'Đổi mật khẩu thành công.',
        token: issueToken(user),
        user: sanitizeUser(user),
      });
    } catch (e: any) {
      console.error('[AUTH CHANGE PASSWORD ERROR]', e);
      return res.status(500).json({ success: false, message: 'Không thể lưu mật khẩu mới. Vui lòng thử lại.' });
    }
  });

  // Set of active SSE (Server-Sent Events) clients for real-time instantaneous sync across all tabs & devices
  const sseClients = new Set<express.Response>();

  function broadcastSseEvent(eventData: any) {
    const payload = `data: ${JSON.stringify(eventData)}\n\n`;
    for (const client of sseClients) {
      try {
        client.write(payload);
      } catch {
        sseClients.delete(client);
      }
    }
  }

  // Health check endpoint
  app.get('/api/health', (req, res) => {
    const vnTime = new Date().toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' });
    res.json({ 
      status: 'ok', 
      service: 'Tasago Concrete Testing Portal Backend',
      vietnamTime: vnTime,
      nodeVersion: process.version,
      connectedClients: sseClients.size,
      cronStatus: {
        lastCronDate: serverState.lastCronDate,
        lastCronLog: serverState.lastCronLog,
        sampleCount: serverState.samples.length,
        recipients: serverState.config.emailRecipients
      }
    });
  });

  // Real-time Server-Sent Events (SSE) stream for instant zero-latency multi-user sync
  app.get('/api/events', requireAuth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    // Send initial handshake
    res.write(`data: ${JSON.stringify({ 
      type: 'INIT_HANDSHAKE', 
      timestamp: Date.now(), 
      totalSamples: (serverState.samples || []).length,
      totalStations: (serverState.stations || []).length,
      serverTime: new Date().toISOString()
    })}\n\n`);

    sseClients.add(res);

    const keepAlive = setInterval(() => {
      try {
        res.write(': ping\n\n');
      } catch {
        clearInterval(keepAlive);
        sseClients.delete(res);
      }
    }, 15000);

    req.on('close', () => {
      clearInterval(keepAlive);
      sseClients.delete(res);
    });
  });

  // 1. Sync & Data Endpoints
  // Get all users
  app.get('/api/users', requireAuth, (req, res) => {
    return res.json({ success: true, users: sanitizeUsers((serverState as any).users || []) });
  });

  // Save/Update users (atomic upsert or list).
  // Passwords are hashed here (never trust/store what the client sends as
  // plaintext), and a blank/omitted password on an EDIT means "keep the
  // existing password" — this matters because responses no longer include
  // the real password (see sanitizeUser), so the admin UI can't round-trip
  // it back to us anymore, and shouldn't need to.
  app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
      const { users, user } = req.body;
      let currentUsers = (serverState as any).users || [];

      const prepareIncomingUser = (incoming: any, existing: any) => {
        const merged = { ...(existing || {}), ...incoming };
        if (incoming.password && incoming.password.trim()) {
          merged.password = hashPassword(incoming.password.trim());
        } else {
          // No new password supplied — keep whatever was already stored.
          merged.password = existing?.password;
        }
        return merged;
      };

      if (user && typeof user === 'object' && user.id) {
        const existingIdx = currentUsers.findIndex((u: any) => u.id === user.id || (user.username && u.username === user.username));
        if (existingIdx >= 0) {
          currentUsers[existingIdx] = prepareIncomingUser(user, currentUsers[existingIdx]);
        } else {
          if (!user.password || !user.password.trim()) {
            return res.status(400).json({ success: false, message: 'Vui lòng đặt mật khẩu cho tài khoản mới.' });
          }
          currentUsers = [...currentUsers, prepareIncomingUser(user, null)];
        }
        (serverState as any).users = currentUsers;
      } else if (Array.isArray(users)) {
        const existingById = new Map(currentUsers.map((u: any) => [u.id, u]));
        (serverState as any).users = users.map((u: any) => prepareIncomingUser(u, existingById.get(u.id)));
      }

      await savePersistedState(serverState);
      broadcastSseEvent({
        type: 'USERS_UPDATED',
        users: sanitizeUsers((serverState as any).users),
        timestamp: Date.now()
      });
      return res.json({ success: true, users: sanitizeUsers((serverState as any).users) });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // Delete user endpoint
  app.post('/api/users/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.body;
      if (!id) return res.status(400).json({ success: false, message: 'Missing user ID' });
      let currentUsers = (serverState as any).users || [];

      const target = currentUsers.find((u: any) => u.id === id);
      if (!target) {
        return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
      }
      // Do not allow deleting the root 'admin' account, and never allow
      // deleting the last remaining admin account (previously this only
      // checked username === 'admin', so any OTHER admin account could be
      // deleted freely, potentially locking the system with zero admins).
      const remainingAdmins = currentUsers.filter((u: any) => u.role === 'admin' && u.id !== id);
      if (target.username === 'admin' || (target.role === 'admin' && remainingAdmins.length === 0)) {
        return res.status(400).json({ success: false, message: 'Không thể xóa tài khoản admin cuối cùng của hệ thống' });
      }

      currentUsers = currentUsers.filter((u: any) => u.id !== id);
      (serverState as any).users = currentUsers;
      await savePersistedState(serverState);
      broadcastSseEvent({
        type: 'USERS_UPDATED',
        users: sanitizeUsers(currentUsers),
        timestamp: Date.now()
      });
      return res.json({ success: true, users: sanitizeUsers(currentUsers) });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // Get all samples
  app.get('/api/samples', requireAuth, (req, res) => {
    return res.json({ success: true, samples: getCurrentSamples() });
  });

  // Save/Update a single sample or list of samples (Upsert without losing other users' data)
  app.post('/api/samples/save', requireAuth, async (req, res) => {
    try {
      const { sample, samples, actionBy } = req.body;
      const authUser = (req as any).authUser;
      let currentSamples = [...(serverState.samples || [])];
      let savedSampleResult: any = null;

      if (authUser?.role !== 'admin') {
        if (sample && typeof sample === 'object' && sample.id) {
          const existing = currentSamples.find((item: any) => item.id === sample.id);
          if (!memberCanUpdateSample(authUser, existing, sample)) {
            return res.status(403).json({ success: false, message: 'Member chỉ được nhập kết quả cho mẫu do mình phụ trách tại trạm được phân công.' });
          }
        } else if (Array.isArray(samples)) {
          const invalid = samples.find((item: any) => {
            const existing = currentSamples.find((current: any) => current.id === item?.id);
            return !item || !memberCanUpdateSample(authUser, existing, item);
          });
          if (invalid) {
            return res.status(403).json({ success: false, message: 'Member không được cập nhật mẫu hoặc kết quả của thành viên khác.' });
          }
        }
      }

      if (sample && typeof sample === 'object' && sample.id) {
        const idx = currentSamples.findIndex((s: any) => s.id === sample.id);
        if (idx >= 0) {
          currentSamples[idx] = { ...currentSamples[idx], ...sample, updatedAt: new Date().toISOString() };
          savedSampleResult = currentSamples[idx];
        } else {
          currentSamples = [sample, ...currentSamples];
          savedSampleResult = sample;
        }
        serverState.samples = currentSamples;
      } else if (Array.isArray(samples)) {
        // Upsert array of samples
        const sampleMap = new Map<string, any>();
        currentSamples.forEach((s: any) => sampleMap.set(s.id, s));
        samples.forEach((s: any) => {
          if (s && s.id) {
            sampleMap.set(s.id, s);
          }
        });
        serverState.samples = Array.from(sampleMap.values());
      } else {
        return res.status(400).json({ success: false, message: 'Invalid sample payload' });
      }

      await savePersistedState(serverState);

      // Instant Real-time Push to all connected Admin and Member screens
      broadcastSseEvent({
        type: 'SAMPLE_SAVED',
        sample: savedSampleResult || sample,
        samples: serverState.samples,
        actionBy: actionBy || sample?.createdByName || sample?.samplerName || 'Thành viên trạm',
        stationId: sample?.stationId,
        timestamp: Date.now()
      });

      return res.json({ 
        success: true, 
        message: 'Đã lưu mẫu bê tông lên máy chủ trung tâm thành công', 
        samples: serverState.samples,
        sample: savedSampleResult || sample
      });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // Delete sample endpoint
  app.post('/api/samples/delete', requireAuth, async (req, res) => {
    try {
      const { id } = req.body;
      if (!id) return res.status(400).json({ success: false, message: 'Missing sample ID' });
      const authUser = (req as any).authUser;
      const targetSample = (serverState.samples || []).find((item: any) => item.id === id);
      if (!targetSample) return res.status(404).json({ success: false, message: 'Không tìm thấy mẫu bê tông.' });
      if (!memberCanModifySample(authUser, targetSample)) {
        return res.status(403).json({ success: false, message: 'Member không được xóa mẫu của thành viên khác hoặc mẫu ngoài trạm được phân công.' });
      }
      serverState.samples = (serverState.samples || []).filter((s: any) => s.id !== id);
      await savePersistedState(serverState);

      broadcastSseEvent({
        type: 'SAMPLE_DELETED',
        sampleId: id,
        samples: serverState.samples,
        timestamp: Date.now()
      });

      return res.json({ 
        success: true, 
        message: 'Đã xóa mẫu bê tông khỏi máy chủ trung tâm', 
        samples: serverState.samples 
      });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // Save/Update samples (Legacy bulk replace support)
  app.post('/api/samples', requireAuth, async (req, res) => {
    try {
      const { samples } = req.body;
      const authUser = (req as any).authUser;
      if (Array.isArray(samples)) {
        if (authUser?.role !== 'admin') {
          const invalid = samples.find((item: any) => {
            const existing = (serverState.samples || []).find((current: any) => current.id === item?.id);
            return !item || !memberCanUpdateSample(authUser, existing, item);
          });
          if (invalid) {
            return res.status(403).json({ success: false, message: 'Member không được đồng bộ mẫu hoặc kết quả của thành viên khác.' });
          }
        }
        serverState.samples = samples;
        await savePersistedState(serverState);
        broadcastSseEvent({
          type: 'SAMPLES_SYNCED',
          samples: serverState.samples,
          timestamp: Date.now()
        });
        return res.json({ success: true, count: samples.length, samples: serverState.samples });
      }
      return res.status(400).json({ success: false, message: 'Invalid samples array' });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // Get all stations
  app.get('/api/stations', requireAuth, (req, res) => {
    return res.json({ success: true, stations: serverState.stations || [] });
  });

  // Save/Update stations
  app.post('/api/stations', requireAuth, requireAdmin, async (req, res) => {
    try {
      const { stations, station } = req.body;
      if (station && station.id) {
        let currentStations = [...(serverState.stations || [])];
        const idx = currentStations.findIndex((s: any) => s.id === station.id);
        if (idx >= 0) {
          currentStations[idx] = { ...currentStations[idx], ...station };
        } else {
          currentStations.push(station);
        }
        serverState.stations = currentStations;
      } else if (Array.isArray(stations)) {
        serverState.stations = stations;
      }
      await savePersistedState(serverState);
      broadcastSseEvent({
        type: 'STATIONS_UPDATED',
        stations: serverState.stations,
        timestamp: Date.now()
      });
      return res.json({ success: true, count: serverState.stations.length, stations: serverState.stations });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // State Fetch / Sync Endpoint
  app.get('/api/server-sync', requireAuth, (req, res) => {
    return res.json({
      success: true,
      users: sanitizeUsers((serverState as any).users || []),
      samples: serverState.samples || [],
      stations: serverState.stations || [],
      config: sanitizeConfig(serverState.config),
      notificationLogs: serverState.notificationLogs || [],
      lastCronDate: serverState.lastCronDate,
      lastCronLog: serverState.lastCronLog,
      timestamp: Date.now()
    });
  });

  // Persist notification history centrally instead of keeping it only in a browser.
  app.post('/api/notification-logs', requireAuth, async (req, res) => {
    try {
      const { log } = req.body || {};
      if (!log || typeof log !== 'object' || !log.id || log.channel !== 'email') {
        return res.status(400).json({ success: false, message: 'Chỉ hỗ trợ notification log của Email.' });
      }
      const logs = Array.isArray(serverState.notificationLogs) ? serverState.notificationLogs : [];
      serverState.notificationLogs = [log, ...logs.filter((item: any) => item.id !== log.id && item.channel === 'email')].slice(0, 100);
      await savePersistedState(serverState);
      return res.json({ success: true, notificationLogs: serverState.notificationLogs });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // Reconcile an incoming user object (from a client sync/restore payload)
  // against what's already stored, WITHOUT ever accepting a client-supplied
  // value as the final stored password unless it's a genuine new plaintext
  // password. This matters here specifically because:
  //  - normal sync payloads no longer carry a real password at all (GET
  //    responses are sanitized), so `incoming.password` will usually be absent
  //  - a restored backup file carries the literal string '[PROTECTED]' for
  //    password (see exportAllDataAsJsonString) — that string must never be
  //    written into the password field, or every restored account would
  //    literally have the password "[PROTECTED]".
  function reconcileIncomingUser(incoming: any, existing: any) {
    const merged = { ...(existing || {}), ...incoming };
    const supplied = typeof incoming.password === 'string' ? incoming.password.trim() : '';
    if (!supplied || supplied === '[PROTECTED]') {
      merged.password = existing?.password;
    } else if (!isHashedPassword(supplied)) {
      merged.password = hashPassword(supplied);
    } else {
      merged.password = supplied;
    }
    return merged;
  }

  // 1. Sync State from Frontend to Server (Smart merge or restore)
  app.post('/api/server-sync', requireAuth, async (req, res) => {
    try {
      const { samples, stations, config, users, notificationLogs, action } = req.body;
      const isAdmin = (req as any).authUser?.role === 'admin';
      if (!isAdmin && (config !== undefined || users !== undefined || stations !== undefined || action === 'restore_full_backup')) {
        return res.status(403).json({ success: false, message: 'Chỉ admin mới được thay đổi cấu hình, người dùng, trạm hoặc khôi phục backup.' });
      }
      if (!isAdmin && Array.isArray(samples)) {
        const invalid = samples.find((item: any) => {
          const existing = (serverState.samples || []).find((current: any) => current.id === item?.id);
          return !item || !memberCanUpdateSample((req as any).authUser, existing, item);
        });
        if (invalid) {
          return res.status(403).json({ success: false, message: 'Member không được đồng bộ mẫu hoặc kết quả của thành viên khác.' });
        }
      }

      if (action === 'restore_full_backup') {
        // Complete full overwrite on intentional backup restore
        if (Array.isArray(samples)) serverState.samples = samples;
        if (Array.isArray(stations)) serverState.stations = stations;
        if (Array.isArray(users)) {
          const existingById = new Map(((serverState as any).users || []).map((u: any) => [u.id, u]));
          (serverState as any).users = users.map((u: any) => reconcileIncomingUser(u, existingById.get(u.id)));
        }
        if (config && typeof config === 'object') {
          serverState.config = mergeConfigPreservingSecrets(serverState.config, config);
        }
        if (Array.isArray(notificationLogs)) {
          serverState.notificationLogs = notificationLogs.slice(0, 100);
        }
      } else {
        // Smart merge: merge incoming items by ID without destroying existing items
        if (Array.isArray(samples) && samples.length > 0) {
          const sampleMap = new Map<string, any>();
          // Existing server samples
          (serverState.samples || []).forEach((s: any) => sampleMap.set(s.id, s));
          // Incoming samples (update or insert)
          samples.forEach((s: any) => {
            if (s && s.id) {
              const existing = sampleMap.get(s.id);
              if (!existing) {
                sampleMap.set(s.id, s);
              } else {
                // If incoming has newer update, take it
                const existingTime = new Date(existing.updatedAt || existing.createdAt || 0).getTime();
                const incomingTime = new Date(s.updatedAt || s.createdAt || 0).getTime();
                if (incomingTime >= existingTime) {
                  sampleMap.set(s.id, { ...existing, ...s });
                }
              }
            }
          });
          serverState.samples = Array.from(sampleMap.values());
        }

        if (Array.isArray(users) && users.length > 0) {
          const userMap = new Map<string, any>();
          ((serverState as any).users || []).forEach((u: any) => userMap.set(u.id || u.username, u));
          users.forEach((u: any) => {
            if (u && (u.id || u.username)) {
              const key = u.id || u.username;
              userMap.set(key, reconcileIncomingUser(u, userMap.get(key)));
            }
          });
          (serverState as any).users = Array.from(userMap.values());
        }

        if (Array.isArray(stations) && stations.length > 0) {
          const stationMap = new Map<string, any>();
          (serverState.stations || []).forEach((st: any) => stationMap.set(st.id, st));
          stations.forEach((st: any) => {
            if (st && st.id) {
              stationMap.set(st.id, st);
            }
          });
          serverState.stations = Array.from(stationMap.values());
        }

        if (config && typeof config === 'object') {
          serverState.config = mergeConfigPreservingSecrets(serverState.config, config);
        }
        if (Array.isArray(notificationLogs) && notificationLogs.length > 0) {
          const logMap = new Map<string, any>();
          (serverState.notificationLogs || []).forEach((log: any) => logMap.set(log.id, log));
          notificationLogs.forEach((log: any) => {
            if (log && log.id) logMap.set(log.id, log);
          });
          serverState.notificationLogs = Array.from(logMap.values()).slice(-100).reverse();
        }
      }

      await savePersistedState(serverState);

      broadcastSseEvent({
        type: 'FULL_SYNC',
        samples: serverState.samples,
        stations: serverState.stations,
        users: sanitizeUsers((serverState as any).users),
        config: sanitizeConfig(serverState.config),
        notificationLogs: serverState.notificationLogs || [],
        timestamp: Date.now()
      });

      return res.status(200).json({
        success: true,
        message: `Đồng bộ máy chủ thành công! (${serverState.samples.length} mẫu bê tông, ${serverState.stations.length} trạm trộn, ${((serverState as any).users || []).length} tài khoản).`,
        config: sanitizeConfig(serverState.config),
        users: sanitizeUsers((serverState as any).users || []),
        samples: serverState.samples,
        stations: serverState.stations,
        notificationLogs: serverState.notificationLogs || [],
        timestamp: Date.now()
      });
    } catch (e: any) {
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // 2. Test Gmail HTTPS relay. The legacy verify-smtp path is retained for old clients.
  app.post(['/api/notifications/verify-gmail-relay', '/api/notifications/verify-smtp'], requireAuth, requireAdmin, async (_req, res) => {
    try {
      const result = await verifyGmailRelay();
      return res.status(200).json({
        success: true,
        message: result.message || 'Gmail HTTPS relay đang hoạt động và sẵn sàng gửi email tự động.',
        details: { transport: 'GmailApp over HTTPS', status: 'READY' },
      });
    } catch (error: any) {
      console.error('Lỗi khi kiểm tra Gmail relay:', error);
      return res.status(502).json({
        success: false,
        message: `Không thể kết nối Gmail relay HTTPS: ${error?.message || 'lỗi không xác định'}`,
        error: error?.message,
      });
    }
  });

  // 3. API Route: Send Real Email Notification via Gmail HTTPS relay
  app.post('/api/notifications/send-email', requireAuth, requireAdmin, async (req, res) => {
    try {
      const {
        recipients,
        subject,
        html,
        plainText
      } = req.body;

      if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Danh sách địa chỉ email người nhận không được để trống.'
        });
      }

      const validRecipients = recipients
        .map((r: string) => r.trim())
        .filter((r: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(r));

      if (validRecipients.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Không có địa chỉ email hợp lệ nào trong danh sách.'
        });
      }

      const todayStr = new Date().toLocaleDateString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' });
      const emailSubject = subject || `[TASAGO] Báo Cáo Lịch Nén Mẫu Bê Tông 07:00 Sáng - ${todayStr}`;
      const senderName = String(serverState.config.emailSender || 'Bê Tông Tasago').split('<')[0].trim() || 'Bê Tông Tasago';
      const result = await sendViaGmailRelay({
        recipients: validRecipients,
        subject: emailSubject,
        text: plainText || '',
        html: html || `<p>${(plainText || '').replace(/\n/g, '<br>')}</p>`,
        senderName,
      });

      return res.status(200).json({
        success: true,
        channel: 'gmail_relay',
        message: result.message || `Đã chuyển email tới Gmail cho ${validRecipients.length} địa chỉ qua HTTPS.`,
        messageId: result.messageId,
        recipients: validRecipients
      });

    } catch (error: any) {
      console.error('Lỗi khi gửi email:', error);
      return res.status(500).json({
        success: false,
        message: `Lỗi khi phát email qua Gmail relay HTTPS: ${error.message || 'lỗi không xác định'}`
      });
    }
  });

  // Trigger 07:00 AM email cron manually on the server
  app.post('/api/cron/trigger', requireAuth, requireAdmin, async (req, res) => {
    try {
      const todayIso = getVietnamDateIso();
      const urgentSamples = getCurrentSamples().filter(
        s => s.status === 'due_today' || s.status === 'overdue'
      );

      const targetSamples = urgentSamples.length > 0 ? urgentSamples : getCurrentSamples().slice(0, 5);
      const emailRecipients = serverState.config.emailRecipients || ['thanhtgndt@gmail.com', 'kythuat@tasago.vn'];

      if (targetSamples.length === 0) {
        return res.json({
          success: true,
          message: 'Không có mẫu nén nào để kích hoạt gửi thông báo.'
        });
      }

      const logParts: string[] = [];

      if (serverState.config.autoEmailEnabled) {
        try {
          const emailResult = await sendConfiguredEmail(targetSamples, serverState.config, todayIso);
          logParts.push(emailResult.success ? `Email Gmail relay thành công (${emailResult.messageId || 'accepted'})` : `Email lỗi: ${emailResult.message}`);
        } catch (emailError: any) {
          logParts.push(`Email lỗi: ${emailError.message}`);
        }
      }

      const resultSummary = logParts.length > 0 ? logParts.join(' | ') : 'Email tự động đang tắt';
      serverState.lastCronDate = todayIso;
      serverState.lastCronLog = `[Thủ công 07:00 AM] Phát thông báo lúc ${new Date().toLocaleTimeString('vi-VN')} cho ${targetSamples.length} mẫu nén. Kết quả: ${resultSummary}`;
      await savePersistedState(serverState);

      return res.json({
        success: true,
        message: serverState.lastCronLog,
        sampleCount: targetSamples.length,
        recipients: emailRecipients
      });
    } catch (e: any) {
      console.error('Lỗi khi kích hoạt thủ công cron:', e);
      return res.status(500).json({ success: false, message: e.message });
    }
  });

  // Development fallback cron. Production uses Vercel Cron so Render Free sleep does not stop delivery.
  setInterval(async () => {
    if (process.env.NODE_ENV === 'production') return;
    try {
      const now = new Date();
      const vnDate = getVietnamDateIso(now);
      const vnTimeParts = now.toLocaleTimeString('vi-VN', { 
        timeZone: 'Asia/Ho_Chi_Minh', 
        hour12: false 
      }).split(':');
      
      const hour = Number(vnTimeParts[0]);
      const minute = Number(vnTimeParts[1]);

      const targetHour = serverState.config.autoSendHour ?? 7;
      const targetMinute = serverState.config.autoSendMinute ?? 0;

      // Trigger at the configured Vietnam time once per day.
      if (hour === targetHour && minute === targetMinute && serverState.lastCronDate !== vnDate) {
        console.log(`[TASAGO CRON] Kích hoạt kiểm tra lịch nén mẫu ngày ${vnDate}...`);
        const urgentSamples = getCurrentSamples().filter(
          s => s.status === 'due_today' || s.status === 'overdue'
        );
        const cronLogItems: string[] = [];

        if (urgentSamples.length === 0) {
          cronLogItems.push('Không có mẫu đến hạn hoặc quá hạn');
        } else {
          if (serverState.config.autoEmailEnabled) {
            try {
              const emailResult = await sendConfiguredEmail(urgentSamples, serverState.config, vnDate);
              cronLogItems.push(emailResult.success ? emailResult.message : `Email lỗi: ${emailResult.message}`);
            } catch (emailError: any) {
              cronLogItems.push(`Email lỗi: ${emailError.message}`);
              console.error('[CRON EMAIL ERROR]', emailError.message);
            }
          }

        }

        serverState.lastCronDate = vnDate;
        serverState.lastCronLog = `[TỰ ĐỘNG ${String(targetHour).padStart(2, '0')}:${String(targetMinute).padStart(2, '0')}] Đã xử lý ${urgentSamples.length} mẫu: ${cronLogItems.join(' | ')}`;
        console.log(serverState.lastCronLog);
        await savePersistedState(serverState);
      }
    } catch (cronErr) {
      console.debug('Cron interval check note:', cronErr);
    }
  }, 30000); // Check every 30s

  // Vite Middleware for Development vs Static for Production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server Tasago running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
