class Helper {
  static cryptograph;

  static async init() {
    const MyHelper = (await import('@protocol/client/helper.js')).default;
    this.cryptoHelper = new MyHelper({});
  }

  static async encryptRequest(req, masterKey, aad = {}) {
    const {
      key,
      salt,
    } = await this.cryptoHelper.deriveKey(masterKey, '');

    const {
      iv,
      cipherText,
    } = await this.cryptoHelper.aesEncrypt(req, key, JSON.stringify(aad));

    const bufIV = Buffer.from(iv, 'base64url');
    const bufSalt = Buffer.from(salt, 'base64url');

    return `${Buffer.concat([bufIV, bufSalt]).toString('base64url')}.${cipherText}`;
  }

  static async decryptResponse(ciphertext, masterKey, aad = {}) {
    const [
      saltAndIvb64,
      tokenb64,
    ] = ciphertext.split('.');

    if (!saltAndIvb64 || !tokenb64) {
      throw new Error('ciphertext is malformed');
    }

    const saltAndIv = Buffer.from(saltAndIvb64, 'base64url');

    const iv = saltAndIv.subarray(0, 16);
    const salt = saltAndIv.subarray(16);
    if (salt.length !== 64) {
      throw new Error('iv or salt size mismatch');
    }

    const {
      key,
    } = await this.cryptoHelper.deriveKey(masterKey, '', salt.toString('base64url'));

    const txt = await this.cryptoHelper.aesDecrypt(tokenb64, key, iv.toString('base64url'), JSON.stringify(aad));

    return txt;
  }
}

module.exports = Helper;
