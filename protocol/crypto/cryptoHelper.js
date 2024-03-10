import crypto from 'node:crypto';
import { CryptoError } from '@protocol/errors';
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

  #SHARED_INFO;

  #pubHeader = '-----BEGIN PUBLIC KEY-----';

  #pubFooter = '-----END PUBLIC KEY-----';

  #privHeader = '-----BEGIN PRIVATE KEY-----';

  #privFooter = '-----END PRIVATE KEY-----';

  constructor({
    ecCurveName = 'prime256v1',
    symmetricEncryptionAlgo = 'aes-256-gcm',
    derivationAlgo = 'sha256',
    macAlgo = 'sha256',
    rsaSignAlgo = 'rsa-sha256',
    ecdsaSignAlgo = 'sha256',
    sharedSecretInfo = 'uniformly_random_shared_secret',
  }) {
    this.#NAMED_CURVE = ecCurveName;
    this.#AES_ALGO = symmetricEncryptionAlgo;
    this.#DERIVATION_ALGO = derivationAlgo;
    this.#MAC_ALGO = macAlgo;
    this.#RSA_SIG_ALGO = rsaSignAlgo;
    this.#ECDSA_SIG_ALGO = ecdsaSignAlgo;
    this.#SHARED_INFO = sharedSecretInfo;

    if (!['sha256', 'sha512'].includes(this.#MAC_ALGO)) {
      throw new CryptoError(`Hmac algorithm (${this.#MAC_ALGO}) is not available, use one of 'sha256', 'sha512'`);
    }

    if (!['prime256v1', 'secp384r1', 'secp521r1'].includes(this.#NAMED_CURVE)) {
      throw new CryptoError(`Curve name (${this.#NAMED_CURVE}) is not available, use one of 'prime256v1', 'secp384r1' or'secp521r1'`);
    }

    // switch (this.#RSA_SIG_ALGO) {
    //   case 'rsa-sha256':
    //     Salt.Size = 32;
    //     break;
    //   case 'rsa-sha512':
    //     Salt.Size = 64;
    //     break;
    //   default:
    //     throw new CryptoError(`RSA signature algorithm (${this.#RSA_SIG_ALGO}) is not available, use one of 'rsa-sha256', 'rsa-sha512'`);
    // }
  }

  static get saltSize() {
    return Salt.Size;
  }

  static get ivSize() {
    return IV.Size;
  }

  get macSize() {
    switch (this.#MAC_ALGO) {
      case 'sha512':
        return 64;
      default:
        return 32;
    }
  }

  get sharedSecretSize() {
    switch (this.#NAMED_CURVE) {
      case 'secp384r1':
        return 48;
      case 'secp521r1':
        return 66;
      default:
        return 32;
    }
  }

  get ecdhPkSize() {
    switch (this.#NAMED_CURVE) {
      case 'secp384r1':
        return 97;
      case 'secp521r1':
        return 133;
      default:
        return 65;
    }
  }

  get ecdsaPkSize() {
    switch (this.#NAMED_CURVE) {
      case 'secp384r1':
        return 160;
      case 'secp521r1':
        return 211;
      default:
        return 122;
    }
  }

  static base64urlSize(byteSize) {
    let strSize = Math.floor((byteSize * 4) / 3);
    strSize += (byteSize % 3 !== 0) ? 1 : 0;
    return strSize;
  }

  async generateECDHKeys(pk) {
    if (!!pk && !Buffer.isBuffer(pk)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }
    try {
      const me = crypto.createECDH(this.#NAMED_CURVE);
      me.generateKeys();

      if (!pk) {
        return {
          ssk: me.getPrivateKey(),
          spk: me.getPublicKey(),
        };
      }

      const tss = me.computeSecret(pk);

      const salt = crypto.randomBytes(this.sharedSecretSize);
      const hkdfUIntArray = await new Promise((resolve, reject) => {
        crypto.hkdf(
          this.#DERIVATION_ALGO,
          tss,
          salt,
          Buffer.from(this.#SHARED_INFO),
          this.sharedSecretSize,
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
        ssk: me.getPrivateKey(),
        spk: me.getPublicKey(),
        tss: key,
        salt,
      };
    } catch (err) {
      throw new CryptoError(err);
    }
  }

  async generateECDSAKeys() {
    const keyPair = await new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        'ec',
        {
          namedCurve: this.#NAMED_CURVE,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        },
        (err, publicKey, privateKey) => {
          if (err) return reject(err);

          return resolve({
            privateKey, publicKey,
          });
        },
      );
    });

    const { privateKey, publicKey } = keyPair;

    const trimmedPK = publicKey.replace(/\n/g, '');
    const pemPK = trimmedPK
      .substring(this.#pubHeader.length, trimmedPK.length - this.#pubFooter.length);

    const trimmedSK = privateKey.replace(/\n/g, '');
    const pemSK = trimmedSK
      .substring(this.#privHeader.length, trimmedSK.length - this.#privFooter.length);

    return {
      ssk: Buffer.from(pemSK, 'base64').toString('base64url'),
      spk: Buffer.from(pemPK, 'base64').toString('base64url'),
    };
  }

  async deriveKey(masterKey, info, usedSalt, size = 32) {
    if (!Buffer.isBuffer(masterKey)
      || !Buffer.isBuffer(info)
      || (!!usedSalt && !Buffer.isBuffer(usedSalt))) {
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

  async getSharedSecret(privK, pubK, salt) {
    if (!Buffer.isBuffer(privK)
        || !Buffer.isBuffer(pubK)
        || !Buffer.isBuffer(salt)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }
    const me = crypto.createECDH(this.#NAMED_CURVE);
    me.setPrivateKey(privK);

    const tss = me.computeSecret(pubK);

    const hkdfUIntArray = await new Promise((resolve, reject) => {
      crypto.hkdf(
        this.#DERIVATION_ALGO,
        tss,
        salt,
        Buffer.from(this.#SHARED_INFO),
        this.sharedSecretSize,
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
    return Buffer.from(hkdfUIntArray);
  }

  aesEncrypt(message, key, aad) {
    if (!Buffer.isBuffer(message)
        || !Buffer.isBuffer(key)
        || !Buffer.isBuffer(aad)) {
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
    if (!Buffer.isBuffer(digest)) {
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
            saltLength: 32,
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

  async signWithEcdsa(digest, pem) {
    if (!Buffer.isBuffer(digest)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }

    const pemSK = `${this.#privHeader}\n${Buffer.from(pem, 'base64url').toString('base64')}\n${this.#privFooter}`;
    try {
      const signature = await new Promise((resolve, reject) => {
        crypto.sign(
          this.#ECDSA_SIG_ALGO,
          digest,
          {
            key: pemSK,
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

      return signature;
    } catch (err) {
      throw new CryptoError(err);
    }
  }

  async verifyRSASignature(digest, signature, pem) {
    if (!Buffer.isBuffer(digest) || !Buffer.isBuffer(signature)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }

    try {
      const verification = await new Promise((resolve, reject) => {
        crypto.verify(
          this.#RSA_SIG_ALGO,
          digest,
          {
            key: pem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 32,
          },
          signature,
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

  async verifyWithECDSA(digest, signature, pem) {
    if (!Buffer.isBuffer(digest) || !Buffer.isBuffer(signature)) {
      throw new CryptoError('Crypto Helper class only deals with buffers');
    }

    const pemPK = `${this.#pubHeader}\n${Buffer.from(pem, 'base64url').toString('base64')}\n${this.#pubFooter}`;

    try {
      const verification = await new Promise((resolve, reject) => {
        crypto.verify(
          this.#ECDSA_SIG_ALGO,
          digest,
          {
            key: pemPK,
            dsaEncoding: 'ieee-p1363',
          },
          signature,
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
