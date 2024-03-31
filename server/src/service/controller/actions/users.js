export function createUser(req, res) {
  console.log('createUser', req.body);
  res.json({ success: true });
}

export async function logUser(req, res) {
  console.log('logUser', req.body);
  const {
    username,
    password,
  } = req.body;

  const issuerClaim = {
    user: {
      id: 0,
      username,
      role: 'user',
    },
    ttl: Date.now() + 600000,
  };
  res.json({
    username,
    password,
    issuerClaim,
  });
}
