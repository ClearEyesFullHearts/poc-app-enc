import { EnvSecretManager } from '@protocol/secrets';
import Ejwt from '@protocol/ejwt';
import CryptoHelper from '@protocol/crypto';
import { InterceptorError } from '@protocol/errors';

class Interceptor {
  #secrets;

  #ejwt;

  #crypto;

  #ttl;

  #info;

  #validator;

  static #base64Size(byteSize) {
    let strSize = Math.floor((byteSize * 4) / 3);
    const remainer = byteSize % 3;
    switch (remainer) {
      case 2:
        strSize += 1;
        break;
      case 4:
        strSize += 2;
        break;
      default:
        break;
    }
    return strSize;
  }

  constructor(
    {
      timeToLive = 900000,
      sessionInfo = '',
    },
    {
      secretManager = new EnvSecretManager(),
      jwtFactory = new Ejwt(),
      cryptoHelper = new CryptoHelper(),
    },
  ) {
    this.#secrets = secretManager;
    this.#ejwt = jwtFactory;
    this.#crypto = cryptoHelper;
    this.#ttl = timeToLive;
    this.#info = sessionInfo;

    const headerSize = Interceptor.#base64Size(this.#crypto.ivSize + this.#crypto.saltSize);

    this.#validator = new RegExp(`^[a-zA-Z0-9\\-_]{${headerSize}}\\.[a-zA-Z0-9\\-_]+?$`);
  }

  async request(token, cipheredBody, proof, ad = {}, requestInfo = '') {
    if (!this.#validator.test(cipheredBody)) {
      throw new InterceptorError('ciphered body is malformed');
    }

    const authKey = await this.#secrets.getKeyAuth();
    const auth = await this.#ejwt.verify(token, authKey, this.#info, ad);

    const {
      iat,
      tss,
      pk,
    } = auth;

    if (Date.now() > (iat + this.#ttl)) {
      throw new InterceptorError('Time to live is expired');
    }

    const digest = Buffer.from(cipheredBody);
    const signature = Buffer.from(proof);
    const isVerifiedBody = await this.#crypto.verifyWithECDSA(digest, signature, pk);
    if (!isVerifiedBody) {
      throw new InterceptorError('ciphered body is invalid');
    }
    const [
      saltAndIvb64,
      bodyb64,
    ] = cipheredBody.split('.');

    const saltAndIv = Buffer.from(saltAndIvb64, 'base64');
    const body = Buffer.from(bodyb64, 'base64');

    const iv = saltAndIv.subarray(0, this.#crypto.ivSize);
    const salt = saltAndIv.subarray(this.#crypto.ivSize);

    const bufMK = Buffer.from(tss, 'base64url');
    const bufInfo = Buffer.from(requestInfo);

    const {
      key,
    } = await this.#crypto.deriveKey(bufMK, bufInfo, salt);

    const clearText = this.#crypto.aesDecrypt(body, key, iv, Buffer.from(JSON.stringify(ad)));

    return {
      auth,
      body: JSON.parse(clearText.toString()),
    };
  }

  async response(payload, sharedKey, ad = {}, requestInfo = '') {
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
    const bufMK = Buffer.from(sharedKey, 'base64');
    const bufInfo = Buffer.from(requestInfo);
    const {
      key,
      salt,
    } = await this.#crypto.deriveKey(bufMK, bufInfo);

    const {
      iv,
      cipherBuffer,
    } = this.#crypto.aesEncrypt(bufferBody, key, Buffer.from(JSON.stringify(ad)));

    const message = `${Buffer.concat([iv, salt]).toString('base64')}.${cipherBuffer.toString('base64')}`;

    const pem = await this.#secrets.getKeySignature();
    const sig = await this.#crypto.signWithRSA(Buffer.from(message), pem);

    return {
      message,
      signature: sig.toString('base64'),
    };
  }
}

export default Interceptor;
