import CryptoHelper from '../lib/cryptoHelper.js';
import Ejwt from '../lib/eJWT.js';
import Translator from './Translator.js';
import Secret from '../lib/secrets.js';

class Auth {
  static anonClaim(req, res) {
    const {
      body: pk,
    } = req;

    const validator = /^[a-zA-Z0-9\-_]{87}$/;
    if (!validator.test(pk) || pk.length !== 87) {
      return res.status(400).end();
    }

    const {
      tss,
      spk,
    } = CryptoHelper.generateECDHKeys(Buffer.from(pk, 'base64url'));

    const claims = {
      tss,
      iat: Date.now() + (1000 * 5),
    };

    const secret = new Secret();
    const jwt = Ejwt.getEJWT(claims, secret.keyAuth);

    return res.json({
      token: jwt,
      publicKey: spk.toString('base64url'),
    });
  }

  static interceptor(router) {
    return (req, res, next) => {
      const {
        authorization,
      } = req.headers;

      if (!authorization) {
        return res.status(401).json({ message: 'missing authorization header' });
      }
      const [type, tokenBase64] = authorization.split(' ');
      if (type !== 'Bearer') {
        return res.status(401).json({ message: 'malformed authorization header' });
      }

      const validateJWT = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;
      if (!validateJWT.test(tokenBase64)) {
        return res.status(400).end();
      }

      let claims;
      try {
        const secret = new Secret();
        claims = Ejwt.getClaims(tokenBase64, secret.keyAuth);
      } catch (err) {
        return res.status(400).end();
      }

      const {
        iat,
        tss,
        ...claim
      } = claims;

      if (Date.now() > iat) {
        return res.status(401).json({ message: 'renew token' });
      }

      const {
        body: ciphertext,
      } = req;

      const validateBody = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?$/;
      if (!validateBody.test(ciphertext)) {
        return res.status(400).end();
      }

      let originalRequest;
      try {
        originalRequest = Translator.getRequest(ciphertext, tss);
      } catch (err) {
        return res.status(400).end();
      }

      const {
        headers,
        body,
        url,
        method,
      } = originalRequest;

      if (!headers || !body || !url || !method) {
        return res.status(400).end();
      }

      req.auth = claim;
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

      const originalSend = res.send;
      res.send = (response, ...args) => {
        console.log('send response', response);
        console.log('res.statusCode', res.statusCode);
        if (Number(res.statusCode) < 300) {
          const cipherResponse = Translator.setResponse(response, tss);
          originalSend.apply(res, [cipherResponse, ...args]);
        }
      };

      return router.handle(req, res, next);
    };
  }
}

export default Auth;
