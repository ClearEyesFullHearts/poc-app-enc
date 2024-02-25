import crypto from 'node:crypto';

class IVector {
  static Size = 16;

  #value;

  constructor(original, encoding) {
    if (!original) {
      this.#value = crypto.randomBytes(IVector.Size);
    } else if (encoding) {
      this.#value = Buffer.from(original, encoding);
    } else {
      this.#value = Buffer.from(original);
    }
    if (this.#value.length !== IVector.Size) {
      throw new Error(`iv size should be ${IVector.Size} and is ${this.#value.length}`);
    }
  }

  get value() {
    return this.#value;
  }
}

export default IVector;
