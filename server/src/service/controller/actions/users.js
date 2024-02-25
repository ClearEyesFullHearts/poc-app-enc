import Ejwt from '../../../lib/eJWT.js';
import CryptoHelper from '../../../lib/cryptoHelper.js';
import Secret from '../../../lib/secrets.js';

export function createUser(req, res) {
  console.log('createUser', req.body);
  res.json({ success: true });
}

export function logUser(req, res) {
  console.log('logUser', req.body);
  const {
    username,
    password,
    pk,
  } = req.body;

  const {
    tss,
    spk,
  } = CryptoHelper.generateECDHKeys(Buffer.from(pk, 'base64url'));

  const claims = {
    tss,
    user: {
      id: 0,
      username,
      role: 'user',
    },
    iat: Date.now() + (1000 * 5),
  };

  const secret = new Secret();
  const jwt = Ejwt.getEJWT(claims, secret.keyAuth);
  res.set('x-auth-token', jwt);
  res.set('x-server-pk', spk.toString('base64url'));
  res.json({
    username,
    password,
  });
}
