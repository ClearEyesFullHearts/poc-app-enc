import crypto from 'node:crypto';

const fakeKey = crypto.randomBytes(32);

class Secret {
  #KEY_AUTH_SIGN;

  constructor() {
    this.#KEY_AUTH_SIGN = fakeKey;
  }

  get keyAuth() {
    return this.#KEY_AUTH_SIGN;
  }
}

export default Secret;
