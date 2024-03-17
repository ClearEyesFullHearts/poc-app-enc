import Encoder from './util.js';

const { subtle } = globalThis.crypto;

class ClientHelper {
  #NAMED_CURVE;

  #DERIVATION_ALGO;

  #SHARED_INFO;

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
    // symmetricEncryptionAlgo = 'aes-256-gcm',
    derivationAlgo = 'sha256',
    // macAlgo = 'sha256',
    // rsaSignAlgo = 'rsa-sha256',
    // ecdsaSignAlgo = 'sha256',
    sharedSecretInfo = 'uniformly_random_shared_secret',
  }) {
    this.#NAMED_CURVE = ecCurveName;
    // this.#AES_ALGO = symmetricEncryptionAlgo;
    this.#DERIVATION_ALGO = derivationAlgo;
    // this.#MAC_ALGO = macAlgo;
    // this.#RSA_SIG_ALGO = rsaSignAlgo;
    // this.#ECDSA_SIG_ALGO = ecdsaSignAlgo;
    this.#SHARED_INFO = sharedSecretInfo;
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
    // import bob public key
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

    // import alice secret key
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
  // async deriveKey();
  // async aesEncrypt();
  // async aesDecrypt();
  // async verifyRSASignature();
  // async signWithEcdsa();
  // async verifyWithECDSA();
}
