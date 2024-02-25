const crypto = require('crypto');
const Salt = require('./salt');
const IV = require('./iVector');

class Helper {
  static NAMED_CURVE = 'prime256v1';

  static DERIVATION_ALGO = 'sha256';

  static AES_ALGO = 'aes-256-gcm';

  static REQ_INFO = 'purpose is request decryption';

  static generateECDHKeys() {
    const alice = crypto.createECDH(this.NAMED_CURVE);
    alice.generateKeys();

    return {
      ssk: alice.getPrivateKey(),
      spk: alice.getPublicKey(),
    };
  }

  static getSharedSecret(privK, pubK) {
    const bob = crypto.createECDH(this.NAMED_CURVE);
    bob.setPrivateKey(privK);

    return bob.computeSecret(pubK);
  }

  static deriveKey(masterKey, info, usedSalt, size = 32) {
    const salt = new Salt(usedSalt);
    const bufInfo = Buffer.concat([info, salt.value]);

    const hkdfUIntArray = crypto.hkdfSync(
      this.DERIVATION_ALGO,
      masterKey,
      Buffer.alloc(size),
      bufInfo,
      size,
    );

    // hkdfSync doesn't return a Buffer object but a typed array
    // To be consistent we convert it to a real Buffer
    const key = Buffer.from(hkdfUIntArray);

    return {
      key,
      salt: salt.value,
    };
  }

  static aesEncrypt(clear, key) {
    const iv = new IV().value;

    const cipher = crypto.createCipheriv(
      this.AES_ALGO,
      key,
      iv,
      { authTagLength: 16 },
    );

    const cipherBuffer = Buffer.concat([
      cipher.update(clear),
      cipher.final(),
      cipher.getAuthTag(), // 16 bytes auth tag is appended to the end
    ]);

    return {
      cipherBuffer,
      iv,
    };
  }

  static aesDecrypt(ciphered, key, iv) {
    // extract the auth tag
    const authTag = ciphered.subarray(ciphered.length - 16);
    const crypted = ciphered.subarray(0, ciphered.length - 16);

    const decipher = crypto.createDecipheriv(this.AES_ALGO, key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(crypted), decipher.final()]);
  }

  static encryptRequest(bufferReq, masterKey) {
    const bufMK = Buffer.from(masterKey, 'base64url');
    const bufInfo = Buffer.from(this.REQ_INFO);
    const {
      key,
      salt,
    } = this.deriveKey(bufMK, bufInfo);

    const {
      iv,
      cipherBuffer,
    } = this.aesEncrypt(bufferReq, key);

    return `${Buffer.concat([iv, salt]).toString('base64url')}.${cipherBuffer.toString('base64url')}`;
  }

  static decryptResponse(ciphertext, masterKey) {
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
    const bufInfo = Buffer.from(this.REQ_INFO);

    const {
      key,
    } = this.deriveKey(bufMK, bufInfo, salt);

    const bufDeciphered = this.aesDecrypt(token, key, iv);

    return bufDeciphered.toString();
  }
}

module.exports = Helper;
