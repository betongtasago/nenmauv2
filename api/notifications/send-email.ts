import { sendViaGmailRelay } from '../../gmailRelay.js';

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '4mb',
    },
  },
};

const isEmail = (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

function requireCronSecret(req: any) {
  const expected = process.env.CRON_SECRET?.trim();
  const supplied = req.headers?.authorization || req.headers?.Authorization || '';
  return Boolean(expected && supplied === `Bearer ${expected}`);
}

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }
  if (!requireCronSecret(req)) return res.status(401).json({ success: false, message: 'Unauthorized' });

  try {
    const { recipients, subject, html, plainText } = req.body || {};
    const validRecipients = (Array.isArray(recipients) ? recipients : [])
      .map((value: unknown) => String(value).trim())
      .filter(isEmail);
    if (!validRecipients.length) return res.status(400).json({ success: false, message: 'Danh sách email người nhận không hợp lệ hoặc để trống.' });

    const result = await sendViaGmailRelay({
      recipients: validRecipients,
      subject: subject || '[TASAGO] Báo cáo lịch nén mẫu',
      html: html || `<p>${String(plainText || '').replace(/\n/g, '<br>')}</p>`,
      text: String(plainText || ''),
    });
    return res.status(200).json({
      success: true,
      channel: 'gmail_relay',
      message: result.message || `Đã chuyển email cho ${validRecipients.length} địa chỉ qua Gmail HTTPS relay.`,
      messageId: result.messageId,
      recipients: validRecipients,
    });
  } catch (error: any) {
    console.error('Lỗi Gmail relay:', error);
    return res.status(502).json({ success: false, message: `Lỗi Gmail relay HTTPS: ${error?.message || 'lỗi không xác định'}` });
  }
}
