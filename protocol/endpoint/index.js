import { EnvSecretManager } from '@protocol/secrets';
import Ejwt from '@protocol/ejwt';
import CryptoHelper from '@protocol/crypto';
import { EndpointError } from '@protocol/errors';

class Endpoints {
  #secrets;

  #ejwt;

  #crypto;

  #EncPKValidator;

  #SigPKValidator;

  #reqValidator;

  #ttl;

  constructor({
    timeToLive = 900000,
    secretManager = new EnvSecretManager(),
    jwtFactory = new Ejwt(),
  }) {
    this.#secrets = secretManager;
    this.#ejwt = jwtFactory;
    this.#crypto = this.#ejwt.crypto;
    this.#ttl = timeToLive;

    const encPKSize = CryptoHelper.base64urlSize(this.#crypto.ecdhPkSize);

    this.#EncPKValidator = new RegExp(`^[a-zA-Z0-9\\-_]{${encPKSize}}$`);
    this.#SigPKValidator = new RegExp(`^[a-zA-Z0-9\\-_]{${this.#crypto.ecdsaPkSize}}$`);

    const headerSize = CryptoHelper.base64urlSize(CryptoHelper.ivSize + CryptoHelper.saltSize);

    this.#reqValidator = new RegExp(`^[a-zA-Z0-9\\-_]{${headerSize}}\\.[a-zA-Z0-9\\-_]+?$`);
  }

  async handshake(pkEnc, pkSig, {
    sessionInfo = '', sessionAD = {},
  }) {
    if (!this.#EncPKValidator.test(pkEnc)) {
      throw new EndpointError('Invalid encryption public key format');
    }
    if (!this.#SigPKValidator.test(pkSig)) {
      throw new EndpointError('Invalid signature public key format');
    }

    const key = Buffer.from(pkEnc, 'base64url');
    const {
      spk,
      tss,
      salt,
    } = await this.#crypto.generateECDHKeys(key);

    const {
      ssk: sig,
      spk: signatureKey,
    } = await this.#crypto.generateECDSAKeys();

    const claims = {
      tss: tss.toString('base64url'),
      pk: pkSig,
      sig,
      user: 'anonymous',
      iat: Date.now() + (1000 * 5),
    };

    const authKey = await this.#secrets.getKeyAuth();
    const jwt = await this.#ejwt.sign(claims, authKey, sessionInfo, sessionAD);

    const result = {
      token: jwt,
      publicKey: spk.toString('base64url'),
      signatureKey,
      salt: salt.toString('base64url'),
    };

    const digest = Buffer.from(JSON.stringify(result));
    const signKey = await this.#secrets.getKeySignature();
    const signature = await this.#crypto.signWithRSA(digest, signKey);

    return {
      ...result,
      signature: signature.toString('base64url'),
    };
  }

  async request(token, cipheredBody, proof, {
    sessionInfo = '', requestInfo = '', sessionAD = {}, requestAD = {},
  }) {
    if (!this.#reqValidator.test(cipheredBody)) {
      throw new EndpointError('ciphered body is malformed');
    }

    const authKey = await this.#secrets.getKeyAuth();
    const auth = await this.#ejwt.verify(token, authKey, sessionInfo, sessionAD);

    const {
      iat,
      tss,
      pk,
    } = auth;

    if (Date.now() > (iat + this.#ttl)) {
      throw new EndpointError('Time to live is expired');
    }

    const digest = Buffer.from(cipheredBody);
    const signature = Buffer.from(proof, 'base64url');
    const pkVerif = Buffer.from(pk, 'base64url');

    const isVerifiedBody = await this.#crypto.verifyWithECDSA(digest, signature, pkVerif);
    if (!isVerifiedBody) {
      throw new EndpointError('ciphered body is invalid');
    }

    const [
      saltAndIvb64,
      bodyb64,
    ] = cipheredBody.split('.');

    const saltAndIv = Buffer.from(saltAndIvb64, 'base64url');
    const body = Buffer.from(bodyb64, 'base64url');

    const iv = saltAndIv.subarray(0, CryptoHelper.ivSize);
    const salt = saltAndIv.subarray(CryptoHelper.ivSize);

    const bufMK = Buffer.from(tss, 'base64url');
    const bufInfo = Buffer.from(requestInfo);

    const {
      key,
    } = await this.#crypto.deriveKey(bufMK, bufInfo, salt);

    const bufAD = Buffer.from(JSON.stringify(requestAD));
    const clearText = this.#crypto.aesDecrypt(body, key, iv, bufAD);

    return {
      auth,
      body: JSON.parse(clearText.toString()),
    };
  }

  async response(payload, sharedKey, sigKey, {
    requestInfo = '', requestAD = {},
  }) {
    if (!payload) {
      return payload;
    }
    let bufferBody;
    if (Buffer.isBuffer(payload)) {
      bufferBody = payload;
    } else if (Object.prototype.toString.call(payload) === '[object String]') {
      bufferBody = Buffer.from(payload);
    } else if (typeof payload === 'boolean') {
      bufferBody = Buffer.from(payload.toString());
    } else {
      bufferBody = Buffer.from(JSON.stringify(payload));
    }
    const bufMK = Buffer.from(sharedKey, 'base64url');
    const bufInfo = Buffer.from(requestInfo);
    const {
      key,
      salt,
    } = await this.#crypto.deriveKey(bufMK, bufInfo);

    const {
      iv,
      cipherBuffer,
    } = this.#crypto.aesEncrypt(bufferBody, key, Buffer.from(JSON.stringify(requestAD)));

    const message = `${Buffer.concat([iv, salt]).toString('base64url')}.${cipherBuffer.toString('base64url')}`;

    const sig = await this.#crypto.signWithEcdsa(Buffer.from(message), sigKey);

    return {
      message,
      signature: sig.toString('base64url'),
    };
  }
}

export default Endpoints;
