const crypto = require('crypto');

class Salt {
  static Size = 64;

  #value;

  constructor(original, encoding) {
    if (!original) {
      this.#value = crypto.randomBytes(Salt.Size);
    } else if (encoding) {
      this.#value = Buffer.from(original, encoding);
    } else {
      this.#value = Buffer.from(original);
    }
    if (this.#value.length !== Salt.Size) {
      throw new Error(`salt size should be ${Salt.Size} and is ${this.#value.length}`);
    }
  }

  get value() {
    return this.#value;
  }
}

module.exports = Salt;
