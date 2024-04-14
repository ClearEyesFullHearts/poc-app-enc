import crypto from 'node:crypto';
import CryptoHelper from '@protocol/crypto';

const users = [];
let id = 0;

const DATA_ENCRYPTION_KEY = crypto.randomBytes(32);
const helper = new CryptoHelper({});

class MemoryDataLayer {
  static #encrypt(txt) {
    const {
      cipherBuffer,
      iv,
    } = helper.aesEncrypt(Buffer.from(txt), DATA_ENCRYPTION_KEY, Buffer.from(''));

    return `${iv.toString('base64url')}.${cipherBuffer.toString('base64url')}`;
  }

  static #decrypt(val) {
    const [iv, ciphertext] = val.split('.');

    const ref = helper.aesDecrypt(Buffer.from(ciphertext, 'base64url'), DATA_ENCRYPTION_KEY, Buffer.from(iv, 'base64url'), Buffer.from(''));
    return ref.toString();
  }

  static #hashAndEncrypt(txt) {
    const hash = helper.getSimpleHash(Buffer.from(txt));
    const cypherText = this.#encrypt(txt);

    return {
      hash: hash.toString('base64url'),
      cypherText,
    };
  }

  static createUser(email, password) {
    const username = this.#hashAndEncrypt(email);
    if (users.find((o) => o.emailH === username.hash)) {
      throw new Error('already exists');
    }

    const pass = this.#encrypt(password);

    id += 1;
    const role = 'user';
    users.push({
      id, emailH: username.hash, emailE: username.cypherText, password: pass, role,
    });

    return {
      id,
      email,
      role,
    };
  }

  static getUsers() {
    if (!users.length < 1) throw new Error('no users');
    return users.map((u) => {
      const {
        password,
        emailH,
        emailE,
        ...user
      } = u;

      return {
        email: this.#decrypt(emailE),
        ...user,
      };
    });
  }

  static getUser(email) {
    const emailHash = helper.getSimpleHash(Buffer.from(email));
    const u = users.find((o) => o.emailH === emailHash.toString('base64url'));
    if (!u) throw new Error('no user');
    const {
      password,
      emailH,
      emailE,
      ...user
    } = u;

    return {
      email: this.#decrypt(emailE),
      ...user,
    };
  }

  static identifyUser(email, password) {
    const emailHash = helper.getSimpleHash(Buffer.from(email));
    const u = users.find((o) => o.emailH === emailHash.toString('base64url'));
    if (!u) throw new Error('no user');

    const {
      password: encPass,
      emailH,
      emailE,
      ...user
    } = u;

    const reference = this.#decrypt(encPass);

    if (password !== reference) throw new Error('wrong password');

    return {
      email: this.#decrypt(emailE),
      ...user,
    };
  }
}

export default MemoryDataLayer;
