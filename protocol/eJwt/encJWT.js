import CryptoHelper from '@protocol/crypto/cryptoHelper.js';
import EJwtError from '@protocol/errors/eJwtError.js';

class EJwt {
  #helper;

  constructor(cryptoHelper) {
    if (!cryptoHelper) {
      this.#helper = new CryptoHelper();
    } else {
      this.#helper = cryptoHelper;
    }

    if (!(this.#helper instanceof CryptoHelper)) {
      throw new EJwtError('Need a valid crypto helper');
    }
  }

  async sign(payload, secret, sessionInfo = '', ad = {}) {
    const bufMK = Buffer.from(secret, 'base64');
    const bufInfo = Buffer.from(sessionInfo);
    const {
      key,
      salt,
    } = await this.#helper.deriveKey(bufMK, bufInfo, false, 64);

    const encKey = key.subarray(0, 32);
    const macKey = key.subarray(32);

    const bufClear = Buffer.from(JSON.stringify(payload));
    const {
      iv,
      cipherBuffer: bufToken,
    } = this.#helper.aesEncrypt(bufClear, encKey);

    const mac = this.#helper.getHMAC(macKey, iv, salt, bufToken, Buffer.from(JSON.stringify(ad)));

    return `${Buffer.concat([iv, salt]).toString('base64url')}.${bufToken.toString('base64url')}.${mac.toString('base64url')}`;
  }

  async verify(ejwt, secret, sessionInfo = '', ad = {}) {
    const [
      saltAndIvb64,
      tokenb64,
      macb64,
    ] = ejwt.split('.');

    if (!saltAndIvb64 || !tokenb64 || !macb64) {
      throw new EJwtError('jwt is malformed');
    }

    const saltAndIv = Buffer.from(saltAndIvb64, 'base64url');
    const token = Buffer.from(tokenb64, 'base64url');
    const mac = Buffer.from(macb64, 'base64url');

    const iv = saltAndIv.subarray(0, CryptoHelper.ivSize);
    const salt = saltAndIv.subarray(CryptoHelper.ivSize);
    if (salt.length !== CryptoHelper.saltSize) {
      throw new EJwtError('iv or salt size mismatch');
    }

    if (mac.length !== CryptoHelper.macSize) {
      throw new EJwtError('MAC size mismatch');
    }

    const bufMK = Buffer.from(secret, 'base64');
    const bufInfo = Buffer.from(sessionInfo);

    const {
      key,
    } = await this.#helper.deriveKey(bufMK, bufInfo, salt, 64);

    const encKey = key.subarray(0, 32);
    const macKey = key.subarray(32);

    const control = this.#helper.getHMAC(macKey, iv, salt, token, Buffer.from(JSON.stringify(ad)));

    if (!mac.equals(control)) {
      throw new EJwtError('jwt authentication failed');
    }

    const bufDeciphered = this.#helper.aesDecrypt(token, encKey, iv);

    try {
      return JSON.parse(Buffer.from(bufDeciphered));
    } catch (err) {
      throw new EJwtError('jwt body is not a JSON');
    }
  }
}

export default EJwt;
