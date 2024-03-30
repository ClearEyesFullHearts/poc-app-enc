export function createUser(req, res) {
  console.log('createUser', req.body);
  res.json({ success: true });
}

export async function logUser(req, res) {
  console.log('logUser', req.body);
  const {
    username,
    password,
    publicKey,
    signingKey,
  } = req.body;

  const {
    locals: {
      crypto,
      eJwt,
      secret,
    },
  } = req;

  const key = Buffer.from(publicKey, 'base64url');
  const {
    spk,
    tss,
    salt,
  } = await crypto.generateECDHKeys(key);

  const {
    ssk: sig,
    spk: signatureKey,
  } = await crypto.generateECDSAKeys();

  const claims = {
    tss: tss.toString('base64url'),
    pk: signingKey,
    sig,
    user: {
      id: 0,
      username,
      role: 'user',
    },
    iat: Date.now(),
  };

  const authKey = await secret.getKeyAuth();
  const jwt = await eJwt.sign(claims, authKey);

  res.set('x-auth-token', jwt);
  res.set('x-servenc-pk', `${salt.toString('base64url')}.${spk.toString('base64url')}`);
  res.set('x-servsig-pk', signatureKey);
  res.json({
    username,
    password,
  });
}
