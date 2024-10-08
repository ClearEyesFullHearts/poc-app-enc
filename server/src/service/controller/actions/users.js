import Datalayer from '../../datalayer/memory.js';

export function createUser(req, res) {
  console.log('createUser', req.body);
  const {
    username,
    password,
  } = req.body;

  Datalayer.createUser(username, password);
  res.json({ success: true });
}

export function listUsers(req, res) {
  console.log('listUsers', req.auth);
  res.json([
    { username: 'test', role: 'user' },
    { username: 'hello', role: 'user' },
    { username: 'admin', role: 'admin' },
    { username: 'muad dib', role: 'messiah' },
  ]);
}

export async function logUser(req, res) {
  console.log('logUser', req.body);
  const {
    username,
    password,
  } = req.body;

  const user = Datalayer.identifyUser(username, password);

  const issuerClaim = {
    user,
    ttl: Date.now() + 600000,
  };
  res.json({
    ...user,
    issuerClaim,
  });
}
