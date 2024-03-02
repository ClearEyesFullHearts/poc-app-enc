import crypto from 'node:crypto';
import CryptoError from '@protocol/errors/cryptoError.js';
import Salt from './salt.js';
import IV from './iVector.js';

class CryptoHelper {
  static #AUTH_TAG_LENGTH = 16;

  #NAMED_CURVE;

  #AES_ALGO;

  #DERIVATION_ALGO;

  #MAC_ALGO;

  #RSA_SIG_ALGO;

  #ECDSA_SIG_ALGO;

  constructor({
    ecCurveName = 'prime256v1',
    symmetricEncryptionAlgo = 'aes-256-gcm',
    derivationAlgo = 'sha256',
    macAlgo = 'sha256',
    rsaSignAlgo = 'rsa-sha256',
    ecdsaSignAlgo = 'sha256',
  }) {
    this.#NAMED_CURVE = ecCurveName;
    this.#AES_ALGO = symmetricEncryptionAlgo;
    this.#DERIVATION_ALGO = derivationAlgo;
    this.#MAC_ALGO = macAlgo;
    this.#RSA_SIG_ALGO = rsaSignAlgo;
    this.#ECDSA_SIG_ALGO = ecdsaSignAlgo;
  }

  static get saltSize() {
    return Salt.Size;
  }

  static get ivSize() {
    return IV.Size;
  }

  static get macSize() {
    return 32;
  }

  generateECDHKeys(pk) {
    if (!Buffer.isBuffer(pk)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }
    try {
      const me = crypto.createECDH(this.#NAMED_CURVE);
      me.generateKeys();

      const tss = me.computeSecret(pk);

      return {
        ssk: me.getPrivateKey(),
        spk: me.getPublicKey(),
        tss,
      };
    } catch (err) {
      throw new CryptoError(err);
    }
  }

  async deriveKey(masterKey, info, usedSalt, size = 32) {
    if (!Buffer.isBuffer(masterKey) || !Buffer.isBuffer(info) || !Buffer.isBuffer(usedSalt)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }
    const salt = new Salt(usedSalt);
    const bufInfo = Buffer.concat([info, salt.value]);

    try {
      const hkdfUIntArray = await new Promise((resolve, reject) => {
        crypto.hkdf(
          this.#DERIVATION_ALGO,
          masterKey,
          Buffer.alloc(size),
          bufInfo,
          size,
          (err, derivedKey) => {
            if (err) {
              reject(err);
            }

            resolve(derivedKey);
          },
        );
      });

      // hkdfSync doesn't return a Buffer object but a typed array
      // To be consistent we convert it to a real Buffer
      const key = Buffer.from(hkdfUIntArray);

      return {
        key,
        salt: salt.value,
      };
    } catch (err) {
      throw new CryptoError(err);
    }
  }

  aesEncrypt(message, key, aad) {
    if (!Buffer.isBuffer(message) || !Buffer.isBuffer(key) || !Buffer.isBuffer(aad)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }

    const iv = new IV().value;
    try {
      const cipher = crypto.createCipheriv(
        this.#AES_ALGO,
        key,
        iv,
        { authTagLength: CryptoHelper.#AUTH_TAG_LENGTH },
      );

      if (aad) cipher.setAAD(aad);

      const cipherBuffer = Buffer.concat([
        cipher.update(message),
        cipher.final(),
        cipher.getAuthTag(), // 16 bytes auth tag is appended to the end
      ]);

      return {
        cipherBuffer,
        iv,
      };
    } catch (err) {
      throw new CryptoError(err);
    }
  }

  aesDecrypt(cipherText, key, iv, aad) {
    if (!Buffer.isBuffer(cipherText)
      || !Buffer.isBuffer(key)
      || !Buffer.isBuffer(iv)
      || !Buffer.isBuffer(aad)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }

    try {
      const authTag = cipherText.subarray(cipherText.length - CryptoHelper.#AUTH_TAG_LENGTH);
      const crypted = cipherText.subarray(0, cipherText.length - CryptoHelper.#AUTH_TAG_LENGTH);

      const decipher = crypto.createDecipheriv(this.#AES_ALGO, key, iv);
      decipher.setAuthTag(authTag);
      if (aad) decipher.setAAD(aad);
      return Buffer.concat([decipher.update(crypted), decipher.final()]);
    } catch (err) {
      throw new CryptoError(err);
    }
  }

  getHMAC(key, ...data) {
    if (!Buffer.isBuffer(key)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }
    try {
      const hmac = crypto.createHmac(this.#MAC_ALGO, key);
      data.forEach((d) => {
        if (!Buffer.isBuffer(d)) {
          throw new CryptoError('Crypto Helper class only deals with buffers');
        }
        hmac.update(d);
      });

      return hmac.digest();
    } catch (err) {
      throw new CryptoError(err);
    }
  }

  async signWithRSA(digest, pem) {
    if (!Buffer.isBuffer(digest) || !Buffer.isBuffer(pem)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }

    try {
      const signature = await new Promise((resolve, reject) => {
        crypto.sign(
          this.#RSA_SIG_ALGO,
          digest,
          {
            key: pem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: Salt.Size,
          },
          (err, result) => {
            if (err) {
              reject(err);
            }

            resolve(result);
          },
        );
      });

      return signature;
    } catch (err) {
      throw new CryptoError(err);
    }
  }

  async verifyWithECDSA(digest, pem) {
    if (!Buffer.isBuffer(digest) || !Buffer.isBuffer(pem)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }

    try {
      const verification = await new Promise((resolve, reject) => {
        crypto.verify(
          this.#ECDSA_SIG_ALGO,
          digest,
          {
            key: pem,
            dsaEncoding: 'ieee-p1363',
          },
          (err, result) => {
            if (err) {
              reject(err);
            }

            resolve(result);
          },
        );
      });

      return verification;
    } catch (err) {
      throw new CryptoError(err);
    }
  }
}

export default CryptoHelper;
