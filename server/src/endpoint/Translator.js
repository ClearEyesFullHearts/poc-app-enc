import CryptoHelper from '../lib/cryptoHelper.js';
import Salt from '../lib/salt.js';
import IVector from '../lib/iVector.js';

class Translator {
  static REQ_INFO = 'purpose is request decryption';

  static setResponse(any, masterKey) {
    if (!any) {
      return any;
    }
    let bufferBody;
    if (Buffer.isBuffer(any)) {
      bufferBody = any;
    } else if (Object.prototype.toString.call(any) === '[object String]') {
      bufferBody = Buffer.from(any);
    } else if (typeof any === 'boolean') {
      bufferBody = Buffer.from(any.toString());
    } else {
      bufferBody = Buffer.from(JSON.stringify(any));
    }

    const bufMK = Buffer.from(masterKey, 'base64');
    const bufInfo = Buffer.from(this.REQ_INFO);
    const {
      key,
      salt,
    } = CryptoHelper.deriveKey(bufMK, bufInfo);

    const {
      iv,
      cipherBuffer,
    } = CryptoHelper.aesEncrypt(bufferBody, key);

    return `${Buffer.concat([iv, salt]).toString('base64url')}.${cipherBuffer.toString('base64url')}`;
  }

  static getRequest(ciphertext, masterKey) {
    const [
      saltAndIvb64,
      tokenb64,
    ] = ciphertext.split('.');

    if (!saltAndIvb64 || !tokenb64) {
      throw new Error('ciphertext is malformed');
    }

    const saltAndIv = Buffer.from(saltAndIvb64, 'base64url');
    const token = Buffer.from(tokenb64, 'base64url');

    const iv = saltAndIv.subarray(0, IVector.Size);
    const salt = saltAndIv.subarray(IVector.Size);
    if (salt.length !== Salt.Size) {
      throw new Error('iv or salt size mismatch');
    }

    const bufMK = Buffer.from(masterKey, 'base64');
    const bufInfo = Buffer.from(this.REQ_INFO);

    const {
      key,
    } = CryptoHelper.deriveKey(bufMK, bufInfo, salt);

    const bufDeciphered = CryptoHelper.aesDecrypt(token, key, iv);

    return JSON.parse(bufDeciphered.toString());
  }
}

export default Translator;
