const crypto = require('crypto');

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Only POST allowed' });
  }

  const secret = 'wsec_a0360dcb0876cdd64e9feae0cf10fe4390d2c06e3ba85336d5e0bb298dcb3d89';
  const header = req.headers['x-elevenlabs-signature'];

  if (!header) {
    return res.status(400).json({ error: 'Missing signature' });
  }

  const [timestampPart, v0Part] = header.split(',');
  const timestamp = timestampPart.split('=')[1];
  const receivedSignature = v0Part.split('=')[1];

  const payload = JSON.stringify(req.body);

  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  if (receivedSignature !== expected) {
    return res.status(401).json({ ok: false, error: 'HMAC failed' });
  }

  return res.status(200).json({ ok: true });
};
