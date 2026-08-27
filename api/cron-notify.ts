import { createClient } from '@supabase/supabase-js';
import { sendViaGmailRelay } from '../gmailRelay.js';
import { buildProfessionalEmail } from '../emailTemplate.js';

const TIME_ZONE = 'Asia/Ho_Chi_Minh';
const isEmail = (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

function vietnamDateIso(date = new Date()): string {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: TIME_ZONE, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(date);
  const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return `${values.year}-${values.month}-${values.day}`;
}

function formatDateVN(value?: string): string {
  if (!value) return '---';
  const parts = value.split('-');
  return parts.length === 3 ? `${parts[2]}/${parts[1]}/${parts[0]}` : value;
}

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
}

async function sendEmail(config: any, recipients: string[], report: { text: string; html: string }, today: string) {
  if (!recipients.length) return 'Email lỗi: chưa cấu hình địa chỉ email người nhận hợp lệ.';
  const senderName = String(config.emailSender || 'Bê Tông Tasago').split('<')[0].trim() || 'Bê Tông Tasago';
  const result = await sendViaGmailRelay({
    recipients,
    subject: `[TASAGO] Báo cáo lịch nén mẫu - ${formatDateVN(today)}`,
    text: report.text,
    html: report.html,
    senderName,
  });
  return result.message || `Email thành công tới ${recipients.length} địa chỉ qua Gmail HTTPS relay.`;
}

export default async function handler(req: any, res: any) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }

  const cronSecret = process.env.CRON_SECRET?.trim();
  if (!cronSecret) return res.status(503).json({ success: false, message: 'Chưa cấu hình CRON_SECRET cho Vercel Cron.' });
  const authorization = req.headers?.authorization || req.headers?.Authorization || '';
  const supplied = authorization === `Bearer ${cronSecret}` ? cronSecret : typeof req.query?.secret === 'string' ? req.query.secret : '';
  if (supplied !== cronSecret) return res.status(401).json({ success: false, message: 'Unauthorized' });

  const url = process.env.SUPABASE_URL?.trim();
  const key = (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '').trim();
  if (!url || !key) return res.status(503).json({ success: false, message: 'Chưa cấu hình Supabase cho cron.' });

  try {
    const supabase = createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
    const { data: state, error } = await supabase.from('app_state').select('stations, samples, config, last_cron_date').eq('id', 'default').single();
    if (error || !state) return res.status(502).json({ success: false, message: error?.message || 'Không tìm thấy app_state.' });

    const today = vietnamDateIso();
    const manual = req.query?.manual === '1' || req.query?.manual === 'true';
    if (!manual && state.last_cron_date === today) return res.json({ success: true, skipped: true, message: 'Cron hôm nay đã được xử lý.', executedDate: today });

    const samples = Array.isArray(state.samples) ? state.samples : [];
    const urgent = samples.filter((sample: any) => {
      if (['tested_passed', 'tested_failed', 'cancelled'].includes(sample.status)) return false;
      return sample.scheduledTestDate === today || (sample.scheduledTestDate && sample.scheduledTestDate < today);
    }).map((sample: any) => ({ ...sample, status: sample.scheduledTestDate < today ? 'overdue' : 'due_today' }));
    const config = state.config && typeof state.config === 'object' ? state.config : {};
    const stations = Array.isArray(state.stations) ? state.stations : [];
    const recipients = (Array.isArray(config.emailRecipients) ? config.emailRecipients : []).map((value: unknown) => String(value).trim()).filter(isEmail);
    const results: string[] = [];

    if (urgent.length > 0) {
      if (config.autoEmailEnabled !== false) {
        try { results.push(await sendEmail(config, recipients, buildProfessionalEmail(urgent, stations, {
          targetDate: today,
          title: 'BÁO CÁO LỊCH NÉN MẪU BÊ TÔNG',
          subtitle: 'Thông báo tự động từ lịch kiểm định chất lượng bê tông',
        }), today)); }
        catch (emailError: any) { results.push(`Email lỗi: ${emailError?.message || 'lỗi Gmail relay'}`); }
      } else {
        results.push('Email tự động đang tắt.');
      }
    } else {
      results.push('Không có mẫu đến hạn hoặc quá hạn.');
    }

    const log = `[VERCEL CRON 07:00] ${today}: ${results.join(' | ')}`;
    const { error: updateError } = await supabase.from('app_state').update({ last_cron_date: today, last_cron_log: log, updated_at: new Date().toISOString() }).eq('id', 'default');
    if (updateError) throw updateError;
    return res.json({ success: true, executedDate: today, sampleCount: urgent.length, details: results, log });
  } catch (error: any) {
    console.error('Lỗi Vercel cron:', error);
    return res.status(500).json({ success: false, message: error?.message || 'Lỗi không xác định khi chạy cron.' });
  }
}
