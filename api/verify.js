const crypto = require('crypto');

module.exports = async (req, res) => {
  const secret = 'ТВОЙ_СЕКРЕТ_ОТСЮДА';
  const signature = req.headers['x-elevenlabs-signature'];
  const payload = JSON.stringify(req.body);

  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  if (signature !== expected) {
    return res.status(401).json({ ok: false, error: 'HMAC failed' });
  }

  console.log('Payload OK', req.body);
  return res.status(200).json({ ok: true });
};
