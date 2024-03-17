import fs from 'node:fs';
import crypto from 'node:crypto';
import express from 'express';
import { EnvSecretManager } from '@protocol/secrets';
import Ejwt from '@protocol/ejwt';
import CryptoHelper from '@protocol/crypto';
import Endpoint from '@protocol/endpoint';
import { ProtocolError } from '@protocol/errors';
import Service from './src/service/index.js';

const pem = fs.readFileSync('./data/rsaSK.pem');
process.env.MASTER_KEY_AUTH = crypto.randomBytes(32).toString('base64url');
process.env.RSA_KEY_SIGNATURE = pem;

const app = express();
const router = new Service().start();

app.use(express.text());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const cryptoH = new CryptoHelper({});
const tokenFactory = new Ejwt(cryptoH);

const secret = new EnvSecretManager();

const endpoints = new Endpoint({
  secretManager: secret,
  jwtFactory: tokenFactory,
});

app.post('/claim', async (req, res) => {
  const {
    body: {
      publicKey,
      signingKey,
    },
  } = req;

  const result = await endpoints.handshake(publicKey, signingKey, {});

  res.json(result);
});

app.post('/protected', async (req, res, next) => {
  const {
    headers: {
      authorization,
      'x-signature-request': proof,
      'content-type': contentType,
    },
    body: cipheredRequest,
  } = req;

  if (contentType !== 'text/plain') {
    return res.status(400).json({ message: 'content type should be plain text' });
  }

  if (!authorization) {
    return res.status(400).json({ message: 'missing authorization header' });
  }
  const [type, tokenBase64] = authorization.split(' ');
  if (type !== 'Bearer') {
    return res.status(400).json({ message: 'malformed authorization header' });
  }

  const {
    auth,
    body: clearRequest,
  } = await endpoints.request(tokenBase64, cipheredRequest, proof, {});

  const {
    headers,
    body,
    url,
    method,
  } = clearRequest;

  if (!headers || !method || !url || (!body && method !== 'GET')) {
    return res.status(400).end();
  }

  req.auth = auth;
  req.headers = Object.keys(headers)
    .reduce((o, p) => ({ ...o, [p.toLowerCase()]: headers[p] }), {});
  switch (req.headers['content-type']) {
    case 'application/json':
      req.body = JSON.parse(body);
      break;
    default:
      req.body = body;
      break;
  }

  req.originalUrl = url;
  req.url = url;
  req.method = method;

  req.locals = {
    crypto: cryptoH,
    eJwt: tokenFactory,
    secret,
  };

  const originalSend = res.send;
  res.send = (response, ...args) => {
    // console.log('send response', response);
    // console.log('res.statusCode', res.statusCode);
    if (Number(res.statusCode) < 300) {
      endpoints.response(response, auth.tss, auth.sig, {})
        .then(({
          message,
          signature,
        }) => {
          res.set('X-Signature-Response', signature);
          originalSend.apply(res, [message, ...args]);
        });
    } else {
      originalSend.apply(res, [response, ...args]);
    }
  };

  return router.handle(req, res, next);
});

app.use((req, res) => {
  res.status(404).send("Sorry can't find that!");
});

app.use((err, req, res, next) => {
  console.log('ERROR\n', err);
  if (err instanceof ProtocolError) {
    if (process.env.NODE_ENV === 'production') {
      return res.status(400).end();
    }
    return res.status(400).json(err);
  }
  return res.status(500).json(err);
});

app.listen(4000, () => {
  console.log('Your server is listening on port 4000');
});
