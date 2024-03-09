class ISecretManager {
  /**
   * Returns the authenticating key in base64url encoded format
   */
  async getKeyAuth() {}

  /**
   * Returns the RSA signing key in PEM format
   */
  async getKeySignature() {}
}

export default ISecretManager;
