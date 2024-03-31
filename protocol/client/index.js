import ClientHelper from './helper.js';
import Encoder from './util.js';

// const { fetch: nodeFetch } = globalThis;

class Client {
  #crypto;

  #apiURL;

  #storage;

  #config;

  async #encryptRequest(body) {
    const tss = await this.#storage.get(this.#config.sharedSecretName);
    const {
      key,
      salt,
    } = await this.#crypto.deriveKey(tss, '');

    const {
      iv,
      cipherText,
    } = await this.#crypto.aesEncrypt(JSON.stringify(body), key, '{}');

    const bufHeader = Encoder.concatBuffers(
      Encoder.base64ToBuffer(iv),
      Encoder.base64ToBuffer(salt),
    );

    const cypherBody = `${Encoder.bufferToBase64(bufHeader)}.${cipherText}`;

    const pem = this.#storage.get(this.#config.signingKeyName);
    const signature = await this.#crypto.signWithEcdsa(cypherBody, pem);

    return {
      cypherBody,
      signature,
    };
  }

  async #decryptResponse(body) {
    const [
      saltAndIvb64,
      tokenb64,
    ] = body.split('.');

    if (!saltAndIvb64 || !tokenb64) {
      throw new Error('ciphertext is malformed');
    }

    const saltAndIv = Encoder.base64ToBuffer(saltAndIvb64);

    const iv = saltAndIv.slice(0, 16);
    const salt = saltAndIv.slice(16);
    if (salt.byteLength !== 64) {
      throw new Error('iv or salt size mismatch');
    }

    const tss = await this.#storage.get(this.#config.sharedSecretName);
    const {
      key,
    } = await this.#crypto.deriveKey(tss, '', Encoder.bufferToBase64(salt));

    const txt = await this.#crypto.aesDecrypt(tokenb64, key, Encoder.bufferToBase64(iv), '{}');

    return txt;
  }

  constructor(apiURL, storage, options = {}, cryptOptions = {}) {
    if (!apiURL || Object.prototype.toString.call(apiURL) !== '[object String]') {
      throw new Error('Missing API base url');
    }
    this.#apiURL = apiURL;

    if (!storage) {
      throw new Error('Missing storage method');
    }
    this.#storage = storage;

    this.#config = {
      anonClaimPath: '/claim',
      endpointPath: '/protected',
      authorityName: 'PK_SIG_ANON_CLAIM',
      tokenName: 'BEARER_TOKEN',
      sharedSecretName: 'EC_ENC_SSK',
      signingKeyName: 'EC_SIG_CLIENT_SK',
      verifyingKeyName: 'EC_SIG_SERVER_PK',
      ...options,
    };

    this.#crypto = new ClientHelper(cryptOptions);
  }

  async generateKeys() {
    const [
      {
        privateKey: EC_ENC_CLIENT_SK,
        publicKey: EC_ENC_CLIENT_PK,
      },
      {
        privateKey: EC_SIG_CLIENT_SK,
        publicKey: EC_SIG_CLIENT_PK,
      },
    ] = await Promise.all([
      this.#crypto.generateECDHKeys(),
      this.#crypto.generateECDSAKeys(),
    ]);

    return {
      EC_ENC_CLIENT_PK,
      EC_ENC_CLIENT_SK,
      EC_SIG_CLIENT_PK,
      EC_SIG_CLIENT_SK,
    };
  }

  async renewAuth(
    { encSK, sigSK },
    {
      token, publicKey, salt, signatureKey,
    },
  ) {
    await Promise.all([
      this.#storage.clear(this.#config.tokenName),
      this.#storage.clear(this.#config.sharedSecretName),
      this.#storage.clear(this.#config.signingKeyName),
      this.#storage.clear(this.#config.verifyingKeyName),
    ]);

    const tss = await this.#crypto.getSharedSecret(publicKey, encSK, salt);

    await Promise.all([
      this.#storage.set(this.#config.tokenName, token),
      this.#storage.set(this.#config.sharedSecretName, tss),
      this.#storage.set(this.#config.signingKeyName, sigSK),
      this.#storage.set(this.#config.verifyingKeyName, signatureKey),
    ]);
  }

  async handShake() {
    const {
      EC_ENC_CLIENT_PK,
      EC_ENC_CLIENT_SK,
      EC_SIG_CLIENT_PK,
      EC_SIG_CLIENT_SK,
    } = await this.generateKeys();

    const body = JSON.stringify({
      publicKey: EC_ENC_CLIENT_PK,
      signingKey: EC_SIG_CLIENT_PK,
    });

    const resp = await fetch(`${this.#apiURL}${this.#config.anonClaimPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body,
    });

    if (!resp.ok) {
      throw new Error(`Handshake error: ${resp.status} - ${resp.statusText}`);
    }

    const {
      token,
      publicKey,
      signatureKey,
      salt,
      signature,
    } = await resp.json();

    const authority = await this.#storage.get(this.#config.authorityName);

    const digest = JSON.stringify({
      token,
      publicKey,
      signatureKey,
      salt,
    });
    const isVerified = await this.#crypto.verifyRSASignature(digest, signature, authority);

    if (!isVerified) {
      throw new Error('RSA signature is wrong');
    }

    await this.renewAuth(
      {
        encSK: EC_ENC_CLIENT_SK,
        sigSK: EC_SIG_CLIENT_SK,
      },
      {
        token, publicKey, salt, signatureKey,
      },
    );
  }

  async call(resource, options) {
    if (!resource) throw new Error('No resource defined');

    let target = resource;
    let request = options;
    if (Object.prototype.toString.call(resource) !== '[object String]') {
      request = resource;
      target = request.url;
    }

    if (!target) throw new Error('No resource defined');

    if (!(request instanceof Request)) {
      request = new Request(`${this.#apiURL}${target}`, request);
      target = request.url;
    }

    let isAnonymous = false;
    if (!this.#storage.has(this.#config.tokenName)) {
      await this.handShake();
      isAnonymous = true;
    }

    const targetURL = new URL(target);
    const path = `${targetURL.pathname}${targetURL.search}`;

    const body = await request.text();

    const {
      headers: reqHeaders,
      method,
    } = request;

    const headers = {};
    reqHeaders.forEach((value, key) => {
      headers[key] = value;
    });

    const encBody = {
      url: path,
      method,
      headers,
      body,
    };

    const {
      cypherBody,
      signature,
    } = await this.#encryptRequest(encBody);

    const authHeader = await this.#storage.get(this.#config.tokenName);
    const post = {
      method: 'POST',
      headers: {
        'X-Signature-Request': signature,
        'Content-Type': 'text/plain',
        'Content-Length': Encoder.clearTextToBuffer(cypherBody).byteLength,
      },
      body: cypherBody,
    };
    if (isAnonymous) {
      post.headers['X-Anon-Authorization'] = `Bearer ${authHeader}`;
    } else {
      post.headers.Authorization = `Bearer ${authHeader}`;
    }

    const resp = await fetch(`${this.#apiURL}${this.#config.endpointPath}`, post);
    if (!resp.ok) {
      throw new Error(`Call error: ${resp.status} - ${resp.statusText}`);
    }

    const cypherResponse = await resp.text();
    const proof = resp.headers.get('x-signature-response');
    const verificationKey = await this.#storage.get(this.#config.verifyingKeyName);

    const isVerifed = await this.#crypto.verifyWithECDSA(cypherResponse, proof, verificationKey);

    if (!isVerifed) {
      throw new Error('Bad Response');
    }

    const respBody = await this.#decryptResponse(cypherResponse);

    if (isAnonymous) {
      await Promise.all([
        this.#storage.clear(this.#config.tokenName),
        this.#storage.clear(this.#config.sharedSecretName),
        this.#storage.clear(this.#config.signingKeyName),
        this.#storage.clear(this.#config.verifyingKeyName),
      ]);
    }

    return new Response(respBody, {
      status: resp.status,
      statusText: resp.statusText,
      headers: resp.headers,
    });
  }

  async keyRenewalCall(resource, options) {
    const {
      EC_ENC_CLIENT_PK: publicKey,
      EC_ENC_CLIENT_SK: encSK,
      EC_SIG_CLIENT_PK: signingKey,
      EC_SIG_CLIENT_SK: sigSK,
    } = await this.generateKeys();

    const loginOptions = {
      ...options,
      body: JSON.stringify({
        ...JSON.parse(options.body),
        als: {
          publicKey,
          signingKey,
        },
      }),
    };

    const resp = await this.call(resource, loginOptions);

    if (resp.headers.has('x-auth-token') && resp.headers.has('x-servenc-pk') && resp.headers.has('x-servsig-pk')) {
      const token = resp.headers.get('x-auth-token');
      const [salt, servPK] = resp.headers.get('x-servenc-pk').split('.');
      const signatureKey = resp.headers.get('x-servsig-pk');

      await this.renewAuth(
        { encSK, sigSK },
        {
          token, publicKey: servPK, salt, signatureKey,
        },
      );
    }

    return resp;
  }
}

export default Client;
