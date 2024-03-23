import Encoder from './util.js';

// eslint-disable-next-line no-undef
const { subtle } = globalThis.crypto;

class ClientHelper {
  #NAMED_CURVE;

  #DERIVATION_ALGO;

  #SHARED_INFO;

  #AES_ALGO;

  #AUTH_TAG_LENGTH;

  #IV_SIZE;

  #RSA_SIG_ALGO;

  get sharedSecretSize() {
    switch (this.#NAMED_CURVE) {
      case 'P-384':
        return 384;
      case 'p-521':
        return 521;
      default:
        return 256;
    }
  }

  constructor({
    ecCurveName = 'P-256',
    symmetricEncryptionAlgo = 'AES-GCM',
    derivationAlgo = 'SHA-256',
    // macAlgo = 'sha256',
    rsaSignAlgo = 'RSA-PSS',
    // ecdsaSignAlgo = 'sha256',
    sharedSecretInfo = 'uniformly_random_shared_secret',
    authTagLength = 16,
    ivSize = 16,
  }) {
    this.#NAMED_CURVE = ecCurveName;
    this.#AES_ALGO = symmetricEncryptionAlgo;
    this.#DERIVATION_ALGO = derivationAlgo;
    // this.#MAC_ALGO = macAlgo;
    this.#RSA_SIG_ALGO = rsaSignAlgo;
    // this.#ECDSA_SIG_ALGO = ecdsaSignAlgo;
    this.#SHARED_INFO = sharedSecretInfo;
    this.#AUTH_TAG_LENGTH = authTagLength;
    this.#IV_SIZE = ivSize;
  }

  async generateECDHKeys() {
    const myKeyPair = await subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: this.#NAMED_CURVE,
      },
      true,
      ['deriveBits'],
    );

    const PK = await subtle.exportKey('raw', myKeyPair.publicKey);
    const SK = await subtle.exportKey('pkcs8', myKeyPair.privateKey);

    return {
      privateKey: Encoder.bufferToBase64(SK),
      publicKey: Encoder.bufferToBase64(PK),
    };
  }

  async getSharedSecret(pk, sk, salt) {
    const bufferSK = Encoder.base64ToBuffer(sk);
    const bufferPK = Encoder.base64ToBuffer(pk);
    // import other public key
    const PK = await subtle.importKey(
      'raw',
      bufferPK,
      {
        name: 'ECDH',
        namedCurve: this.#NAMED_CURVE,
      },
      false,
      [], // no key usage
    );

    // import my secret key
    const SK = await subtle.importKey(
      'pkcs8', // match previous export
      bufferSK,
      {
        name: 'ECDH',
        namedCurve: this.#NAMED_CURVE,
      },
      false,
      ['deriveBits'],
    );

    // get derived shared secret
    const sharedSecret = await subtle.deriveBits(
      {
        name: 'ECDH',
        namedCurve: this.#NAMED_CURVE,
        public: PK,
      },
      SK,
      this.sharedSecretSize,
    );

    const sharedSecretKey = await subtle.importKey(
      'raw',
      sharedSecret, // the shared secret comes as a buffer from the previous step
      { name: 'HKDF' },
      false,
      ['deriveBits'],
    );

    const bufferSalt = Encoder.base64ToBuffer(salt);
    const info = Encoder.clearTextToBuffer(this.#SHARED_INFO);

    const bufferKey = await subtle.deriveBits(
      {
        name: 'HKDF',
        hash: this.#DERIVATION_ALGO,
        salt: bufferSalt,
        info,
      },
      sharedSecretKey,
      this.sharedSecretSize,
    );

    return Encoder.bufferToBase64(bufferKey);
  }

  // async generateECDSAKeys();
  async deriveKey(masterKey, info, usedSalt, size = 32) {
    const masterKeyBuff = Encoder.base64ToBuffer(masterKey);
    const key = await subtle.importKey(
      'raw',
      masterKeyBuff,
      { name: 'HKDF' },
      false,
      ['deriveBits'],
    );

    const salt = new ArrayBuffer(size);
    const infoBuf = Encoder.clearTextToBuffer(info);
    let trueSaltBuf;
    if (usedSalt) {
      trueSaltBuf = Encoder.base64ToBuffer(usedSalt);
    } else {
      trueSaltBuf = Encoder.getRandomBuffer(64);
    }

    const bufferKey = await subtle.deriveBits(
      {
        name: 'HKDF',
        hash: this.#DERIVATION_ALGO,
        salt,
        info: Encoder.concatBuffers(infoBuf, trueSaltBuf),
      },
      key,
      size * 8, // size of the derived key (bits)
    );

    return {
      key: Encoder.bufferToBase64(bufferKey),
      salt: Encoder.bufferToBase64(trueSaltBuf),
    };
  }

  async aesEncrypt(message, key, aad) {
    const bufferKey = Encoder.base64ToBuffer(key);
    const keyObj = await subtle.importKey(
      'raw',
      bufferKey,
      {
        name: this.#AES_ALGO,
      },
      false,
      ['encrypt'],
    );

    let aadBuf;
    if (aad) {
      aadBuf = Encoder.clearTextToBuffer(aad);
    }

    const bufferIv = Encoder.getRandomBuffer(this.#IV_SIZE);
    const bufferTxt = Encoder.clearTextToBuffer(message);
    const bufferCypher = await subtle.encrypt({
      name: this.#AES_ALGO,
      iv: bufferIv,
      tagLength: this.#AUTH_TAG_LENGTH * 8, // length of the auth tag
      additionalData: aadBuf,
    }, keyObj, bufferTxt);

    return {
      cipherBuffer: Encoder.bufferToBase64(bufferCypher),
      iv: Encoder.bufferToBase64(bufferIv),
    };
  }

  async aesDecrypt(cipherText, key, iv, aad) {
    const bufferKey = Encoder.base64ToBuffer(key);
    const bufferIv = Encoder.base64ToBuffer(iv);
    const bufferCypher = Encoder.base64ToBuffer(cipherText);

    const importedKey = await subtle.importKey(
      'raw',
      bufferKey,
      {
        name: this.#AES_ALGO,
      },
      false,
      ['decrypt'],
    );

    let aadBuf;
    if (aad) {
      aadBuf = Encoder.clearTextToBuffer(aad);
    }

    const bufferText = await subtle.decrypt(
      {
        name: this.#AES_ALGO,
        iv: bufferIv,
        tagLength: this.#AUTH_TAG_LENGTH * 8,
        additionalData: aadBuf,
      },
      importedKey,
      bufferCypher,
    );

    return Encoder.bufferToClearText(bufferText);
  }

  async verifyRSASignature(digest, signature, pem) {
    const buffer = Encoder.clearTextToBuffer(digest);

    const bufferPemContent = Encoder.base64ToBuffer(pem);
    const key = await subtle.importKey(
      'spki',
      bufferPemContent,
      {
        name: this.#RSA_SIG_ALGO,
        hash: this.#DERIVATION_ALGO,
      },
      true,
      ['verify'],
    );

    const signatureBuffer = Encoder.base64ToBuffer(signature);
    const result = await subtle.verify(
      {
        name: this.#RSA_SIG_ALGO,
        saltLength: 32,
      },
      key,
      signatureBuffer,
      buffer,
    );

    return result;
  }
  // async signWithEcdsa();
  // async verifyWithECDSA();
}

export default ClientHelper;
