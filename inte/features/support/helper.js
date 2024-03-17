const Salt = require('./salt');
const IV = require('./iVector');

class Helper {
  static cryptograph;

  static async init() {
    const CryptoHelper = (await import('@protocol/crypto/cryptoHelper.js')).default;
    this.cryptograph = new CryptoHelper({});
  }

  static async encryptRequest(bufferReq, masterKey, aad = {}) {
    const bufMK = Buffer.from(masterKey, 'base64url');
    const bufInfo = Buffer.from('');
    const {
      key,
      salt,
    } = await this.cryptograph.deriveKey(bufMK, bufInfo);

    const {
      iv,
      cipherBuffer,
    } = this.cryptograph.aesEncrypt(bufferReq, key, Buffer.from(JSON.stringify(aad)));

    return `${Buffer.concat([iv, salt]).toString('base64url')}.${cipherBuffer.toString('base64url')}`;
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
    const token = Buffer.from(tokenb64, 'base64url');

    const iv = saltAndIv.subarray(0, IV.Size);
    const salt = saltAndIv.subarray(IV.Size);
    if (salt.length !== Salt.Size) {
      throw new Error('iv or salt size mismatch');
    }

    const bufMK = Buffer.from(masterKey, 'base64');
    const bufInfo = Buffer.from('');

    const {
      key,
    } = await this.cryptograph.deriveKey(bufMK, bufInfo, salt);

    const bufDeciphered = this.cryptograph.aesDecrypt(token, key, iv, Buffer.from(JSON.stringify(aad)));

    return bufDeciphered.toString();
  }
}

module.exports = Helper;
