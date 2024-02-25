import CryptoHelper from './cryptoHelper.js';
import Salt from './salt.js';
import IVector from './iVector.js';

class Ejwt {
  static JWT_INFO = 'purpose is jwt';

  static getEJWT(claims, masterKey, ad = {}) {
    const bufMK = Buffer.from(masterKey, 'base64');
    const bufInfo = Buffer.from(this.JWT_INFO);
    const {
      key,
      salt,
    } = CryptoHelper.deriveKey(bufMK, bufInfo, false, 64);

    const encKey = key.subarray(0, 32);
    const macKey = key.subarray(32);

    const bufClear = Buffer.from(JSON.stringify(claims));
    const {
      iv,
      cipherBuffer: bufToken,
    } = CryptoHelper.aesEncrypt(bufClear, encKey);

    const mac = CryptoHelper.getHMAC(macKey, iv, salt, bufToken, Buffer.from(JSON.stringify(ad)));

    return `${Buffer.concat([iv, salt]).toString('base64url')}.${bufToken.toString('base64url')}.${mac.toString('base64url')}`;
  }

  static getClaims(ejwt, masterKey, ad = {}) {
    const [
      saltAndIvb64,
      tokenb64,
      macb64,
    ] = ejwt.split('.');

    if (!saltAndIvb64 || !tokenb64 || !macb64) {
      throw new Error('jwt is malformed');
    }

    const saltAndIv = Buffer.from(saltAndIvb64, 'base64url');
    const token = Buffer.from(tokenb64, 'base64url');
    const mac = Buffer.from(macb64, 'base64url');

    const iv = saltAndIv.subarray(0, IVector.Size);
    const salt = saltAndIv.subarray(IVector.Size);
    if (salt.length !== Salt.Size) {
      throw new Error('iv or salt size mismatch');
    }

    if (mac.length !== 32) {
      throw new Error('MAC size mismatch');
    }

    const bufMK = Buffer.from(masterKey, 'base64');
    const bufInfo = Buffer.from(this.JWT_INFO);

    const {
      key,
    } = CryptoHelper.deriveKey(bufMK, bufInfo, salt, 64);

    const encKey = key.subarray(0, 32);
    const macKey = key.subarray(32);

    const control = CryptoHelper.getHMAC(macKey, iv, salt, token, Buffer.from(JSON.stringify(ad)));

    if (!mac.equals(control)) {
      throw new Error('jwt authentication failed');
    }

    const bufDeciphered = CryptoHelper.aesDecrypt(token, encKey, iv);

    return JSON.parse(Buffer.from(bufDeciphered));
  }
}

export default Ejwt;
