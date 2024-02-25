import crypto from 'node:crypto';
import Salt from './salt.js';
import IV from './iVector.js';

class CryptoHelper {
  static NAMED_CURVE = 'prime256v1';

  static AES_ALGO = 'aes-256-gcm';

  static DERIVATION_ALGO = 'sha256';

  static MAC_ALGO = 'sha256';

  static generateECDHKeys(bobKey) {
    const alice = crypto.createECDH(this.NAMED_CURVE);
    alice.generateKeys();

    const tss = alice.computeSecret(bobKey);

    return {
      ssk: alice.getPrivateKey(),
      spk: alice.getPublicKey(),
      tss,
    };
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

  static getHMAC(key, ...data) {
    const hmac = crypto.createHmac(this.MAC_ALGO, key);
    data.forEach((d) => {
      hmac.update(d);
    });

    return hmac.digest();
  }
}

export default CryptoHelper;
