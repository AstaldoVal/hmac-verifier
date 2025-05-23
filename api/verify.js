const crypto = require('crypto');

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Only POST allowed' });
  }

  const secret = process.env.ELEVENLABS_HMAC_SECRET || 'wsec_a0360dcb0876cdd64e9feae0cf10fe4390d2c06e3ba85336d5e0bb298dcb3d89';
  const header = req.headers['x-elevenlabs-signature'];

  if (!header) {
    return res.status(400).json({ error: 'Missing signature' });
  }

  const v0Part = header.split(',').find(p => p.startsWith('v0='));
  const signature = v0Part?.split('=')[1];

  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const rawBody = Buffer.concat(chunks).toString('utf8');

    const expected = crypto
      .createHmac('sha256', secret)
      .update(rawBody)
      .digest('hex');

    if (signature !== expected) {
      return res.status(401).json({ ok: false, error: 'HMAC failed' });
    }

    return res.status(200).json({ ok: true });
  });
};
