import CryptoHelper from '@protocol/crypto/cryptoHelper.js';
import { EJwtError } from '@protocol/errors';

class EJwt {
  #helper;

  #validator;

  get crypto() {
    return this.#helper;
  }

  constructor(cryptoHelper) {
    if (!cryptoHelper) {
      this.#helper = new CryptoHelper();
    } else {
      this.#helper = cryptoHelper;
    }

    if (!(this.#helper instanceof CryptoHelper)) {
      throw new EJwtError('Need a valid crypto helper');
    }

    const headerSize = CryptoHelper.base64urlSize(CryptoHelper.ivSize + CryptoHelper.saltSize);
    const footerSize = CryptoHelper.base64urlSize(this.#helper.macSize);

    this.#validator = new RegExp(`^[a-zA-Z0-9\\-_]{${headerSize}}\\.[a-zA-Z0-9\\-_]+?\\.[a-zA-Z0-9\\-_]{${footerSize}}$`);
  }

  async sign(payload, secret, sessionInfo = '', ad = {}) {
    const bufMK = Buffer.from(secret, 'base64url');
    const bufInfo = Buffer.from(sessionInfo);
    const {
      key,
      salt,
    } = await this.#helper.deriveKey(bufMK, bufInfo, false, 64);

    const encKey = key.subarray(0, 32);
    const macKey = key.subarray(32);

    const bufClear = Buffer.from(JSON.stringify(payload));
    const bufData = Buffer.from(JSON.stringify(ad));
    const {
      iv,
      cipherBuffer: bufToken,
    } = this.#helper.aesEncrypt(bufClear, encKey, bufData);

    const mac = this.#helper.getHMAC(macKey, iv, bufToken, salt, bufData);

    return `${Buffer.concat([iv, salt]).toString('base64url')}.${bufToken.toString('base64url')}.${mac.toString('base64url')}`;
  }

  async verify(token, secret, sessionInfo = '', ad = {}) {
    if (!this.#validator.test(token)) {
      throw new EJwtError('jwt is malformed');
    }
    const [
      saltAndIvb64,
      bodyb64,
      macb64,
    ] = token.split('.');

    const saltAndIv = Buffer.from(saltAndIvb64, 'base64url');
    const body = Buffer.from(bodyb64, 'base64url');
    const mac = Buffer.from(macb64, 'base64url');

    const iv = saltAndIv.subarray(0, CryptoHelper.ivSize);
    const salt = saltAndIv.subarray(CryptoHelper.ivSize);

    const bufMK = Buffer.from(secret, 'base64url');
    const bufInfo = Buffer.from(sessionInfo);

    const {
      key,
    } = await this.#helper.deriveKey(bufMK, bufInfo, salt, 64);

    const encKey = key.subarray(0, 32);
    const macKey = key.subarray(32);

    const control = this.#helper.getHMAC(macKey, iv, body, salt, Buffer.from(JSON.stringify(ad)));

    if (!mac.equals(control)) {
      throw new EJwtError('jwt authentication failed');
    }

    const bufDeciphered = this.#helper.aesDecrypt(body, encKey, iv);

    try {
      return JSON.parse(Buffer.from(bufDeciphered));
    } catch (err) {
      throw new EJwtError('jwt body is not a JSON');
    }
  }
}

export default EJwt;
