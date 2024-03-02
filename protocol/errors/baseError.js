class ProtocolError extends Error {
  #internalError;

  constructor(arg) {
    if (Object.prototype.toString.call(arg) === '[object String]') {
      super(arg);
    } else {
      super(arg.message);
      this.#internalError = arg;
    }
  }
}

export default ProtocolError;
