import { EnvSecretManager } from '@protocol/secrets';
import Ejwt from '@protocol/ejwt';
import CryptoHelper from '@protocol/crypto';
import ProxyResponse from './proxies.js';
import Translator from './translator.js';

class ExpressEndpoint {
  #translator;

  constructor(translator) {
    if (translator) {
      this.#translator = translator;
    } else {
      const cryptoH = new CryptoHelper({});
      const tokenFactory = new Ejwt(cryptoH);

      const secret = new EnvSecretManager();

      this.#translator = new Translator({
        secretManager: secret,
        jwtFactory: tokenFactory,
      });
    }
  }

  async anonymous(req, res, next) {
    const {
      body: {
        publicKey,
        signingKey,
      },
    } = req;

    try {
      const result = await this.#translator.handshake(publicKey, signingKey, {});

      res.json(result);
    } catch (err) {
      next(err);
    }
  }

  async identified(req, res, next) {
    const {
      headers: {
        authorization,
        'x-anon-authorization': anonAuth,
        'x-signature-request': proof,
        'content-type': contentType,
      },
      body: cipheredRequest,
    } = req;

    if (contentType !== 'text/plain') {
      return res.status(400).json({ message: 'content type should be plain text' });
    }

    if (!authorization && !anonAuth) {
      return res.status(400).json({ message: 'missing authorization header' });
    }
    let type;
    let tokenBase64;
    if (authorization) {
      [type, tokenBase64] = authorization.split(' ');
    } else if (anonAuth) {
      [type, tokenBase64] = anonAuth.split(' ');
    }
    if (type !== 'Bearer') {
      return res.status(400).json({ message: 'malformed authorization header' });
    }

    try {
      const isAnonymous = !!anonAuth;

      const {
        auth,
        body: clearRequest,
      } = await this.#translator.request(isAnonymous, tokenBase64, cipheredRequest, proof, {});

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

      let als = false;
      let cleanBody = body;
      if (body && req.headers['content-type'] === 'application/json') {
        cleanBody = JSON.parse(body);
        if (cleanBody.als) {
          als = cleanBody.als;
          delete cleanBody.als;
        }
      }

      req.originalUrl = url;
      req.url = url;
      req.method = method;
      req.body = cleanBody;

      if (als) {
        const {
          publicKey,
          signingKey,
        } = als;
        if (!this.#translator.alsEncKeyValidator.test(publicKey)) {
          return res.status(400).json({ message: 'wrong als encryption key format' });
        }
        if (!this.#translator.alsSigKeyValidator.test(signingKey)) {
          return res.status(400).json({ message: 'wrong als signature key format' });
        }

        // eslint-disable-next-line no-param-reassign
        res = await ProxyResponse.encryptAndRenew(res, this.#translator, auth, als);
      } else {
        // eslint-disable-next-line no-param-reassign
        res = await ProxyResponse.encrypt(res, this.#translator, auth);
      }

      return next();
    } catch (err) {
      return next(err);
    }
  }
}
export default ExpressEndpoint;
