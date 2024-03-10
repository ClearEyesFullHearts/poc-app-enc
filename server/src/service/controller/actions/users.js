export function createUser(req, res) {
  console.log('createUser', req.body);
  res.json({ success: true });
}

export async function logUser(req, res) {
  console.log('logUser', req.body);
  const {
    username,
    password,
    pk,
  } = req.body;

  const {
    locals: {
      crypto,
      eJwt,
      secret,
    },
  } = req;

  const key = Buffer.from(pk, 'base64url');
  const {
    spk,
    tss,
    salt,
  } = await crypto.generateECDHKeys(key);

  const claims = {
    tss,
    user: {
      id: 0,
      username,
      role: 'user',
    },
    iat: Date.now(),
  };
  const authKey = await secret.getKeyAuth();
  const jwt = await eJwt.sign(claims, authKey, username);

  res.set('x-auth-token', jwt);
  res.set('x-server-pk', Buffer.concat([spk, salt]).toString('base64url'));
  res.json({
    username,
    password,
  });
}
