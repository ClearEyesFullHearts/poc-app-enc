const {
  crypto,
  atob,
  btoa,
} = globalThis;

class Encoder {
  static clearTextToBuffer(txt) {
    const buf = new ArrayBuffer(txt.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = txt.length; i < strLen; i += 1) {
      bufView[i] = txt.charCodeAt(i);
    }
    return buf;
  }

  static base64ToBuffer(b64Txt) {
    const str = atob(b64Txt).replace(/\-/g, '+').replace(/_/g, '/'); // decode base64url
    return this.clearTextToBuffer(str);
  }

  static bufferToBase64(buffer) {
    const str = this.bufferToClearText(buffer);
    return btoa(str)
      .replace(/\//g, '_')
      .replace(/\+/g, '-')
      .replace(/=+$/, ''); // encode base64url
  }

  static bufferToClearText(buffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
  }

  static getRandomBuffer(size) {
    return crypto.getRandomValues(new Uint8Array(size));
  }

  static concatBuffers(buf1, buf2) {
    const tmp = new Uint8Array(buf1.byteLength + buf2.byteLength);
    tmp.set(new Uint8Array(buf1), 0);
    tmp.set(new Uint8Array(buf2), buf1.byteLength);
    return tmp.buffer;
  }
}

export default Encoder;
