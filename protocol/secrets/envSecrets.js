import ISecretManager from './secretManager.js';

class EnvSecretManager extends ISecretManager {
  #MASTER_KEY_AUTH;

  #RSA_KEY_SIGNATURE;

  constructor() {
    super();
    this.#MASTER_KEY_AUTH = process.env.MASTER_KEY_AUTH;
    this.#RSA_KEY_SIGNATURE = process.env.RSA_KEY_SIGNATURE;
  }

  async getKeyAuth() {
    return Promise.resolve(this.#MASTER_KEY_AUTH);
  }

  async getKeySignature() {
    return Promise.resolve(this.#RSA_KEY_SIGNATURE);
  }
}

export default EnvSecretManager;
