class ProxyResponse {
  static async encryptAndRenew(res, translator, keys, als) {
    const {
      spk,
      tss,
      salt,
    } = await translator.crypto.generateECDHKeys(Buffer.from(als.publicKey, 'base64url'));

    const {
      ssk: sig,
      spk: signatureKey,
    } = await translator.crypto.generateECDSAKeys();

    const alsClaim = {
      tss: tss.toString('base64url'),
      pk: als.signingKey,
      sig,
      iat: Date.now(),
    };

    const authKey = await translator.secrets.getKeyAuth();

    const originalSend = res.send;
    res.send = (response, ...args) => {
      if (Number(res.statusCode) < 300) {
        const {
          issuerClaim,
          ...body
        } = JSON.parse(response);
        translator.response(body, keys.tss, keys.sig, {})
          .then(async ({
            message,
            signature,
          }) => {
            if (issuerClaim && issuerClaim.user && issuerClaim.ttl) {
              const claims = {
                ...issuerClaim,
                ...alsClaim,
              };

              const jwt = await translator.ejwt.sign(claims, authKey);
              const result = {
                token: jwt,
                publicKey: spk.toString('base64url'),
                signatureKey,
                salt: salt.toString('base64url'),
              };

              const digest = Buffer.from(JSON.stringify(result));
              const signKey = await translator.secrets.getKeySignature();
              const authSig = await translator.crypto.signWithRSA(digest, signKey);

              res.set('x-auth-token', result.token);
              res.set('x-servenc-pk', `${result.salt}.${result.publicKey}`);
              res.set('x-servsig-pk', result.signatureKey);
              res.set('x-authority-sig', authSig.toString('base64url'));
              res.set('x-signature-response', signature);
              originalSend.apply(res, [message, ...args]);
            } else {
              res.set('x-signature-response', signature);
              originalSend.apply(res, [message, ...args]);
            }
          });
      } else {
        originalSend.apply(res, [response, ...args]);
      }
    };

    return res;
  }

  static async encrypt(res, translator, keys) {
    const originalSend = res.send;
    res.send = (response, ...args) => {
      if (Number(res.statusCode) < 300) {
        translator.response(response, keys.tss, keys.sig, {})
          .then(({
            message,
            signature,
          }) => {
            res.set('x-signature-response', signature);
            originalSend.apply(res, [message, ...args]);
          });
      } else {
        originalSend.apply(res, [response, ...args]);
      }
    };

    return Promise.resolve(res);
  }
}

export default ProxyResponse;
