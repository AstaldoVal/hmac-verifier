const crypto = require('crypto');

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Only POST allowed' });
  }

  const secret = 'wsec_a0360dcb0876cdd64e9feae0cf10fe4390d2c06e3ba85336d5e0bb298dcb3d89';
  const signature = req.headers['x-elevenlabs-signature'];
  const payload = JSON.stringify(req.body);

  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  if (signature !== expected) {
    return res.status(401).json({ ok: false, error: 'HMAC failed' });
  }

  return res.status(200).json({ ok: true });
};
