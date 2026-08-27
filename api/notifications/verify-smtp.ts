import { verifyGmailRelay } from '../../gmailRelay.js';

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '2mb',
    },
  },
};

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ success: false, message: 'Method Not Allowed' });
  }
  const expected = process.env.CRON_SECRET?.trim();
  const supplied = req.headers?.authorization || req.headers?.Authorization || '';
  if (!expected || supplied !== `Bearer ${expected}`) return res.status(401).json({ success: false, message: 'Unauthorized' });

  try {
    const result = await verifyGmailRelay();
    return res.status(200).json({
      success: true,
      message: result.message || 'Gmail HTTPS relay đang hoạt động.',
      details: { transport: 'GmailApp over HTTPS', status: 'READY' },
    });
  } catch (error: any) {
    console.error('Lỗi khi kiểm tra Gmail relay:', error);
    return res.status(502).json({ success: false, message: `Không thể kết nối Gmail relay HTTPS: ${error?.message || 'lỗi không xác định'}` });
  }
}
