/**
 * Interface for crypto algorithm implementations.
 *
 * Each crypto algorithm (ed25519, rsa, bls) will implement this interface.
 */
export interface CryptoImplementation {
  /**
   * Signs a payload with the algorithm's private key.
   *
   * @param payload - The data to be signed.
   * @param privateKey - The private key used for signing.
   * @returns The signed payload as a Uint8Array.
   */
  sign(
    payload: Uint8Array,
    privateKey: CryptoKey | Uint8Array
  ): Promise<Uint8Array>

  /**
   * Verifies the signature of a payload using the algorithm's public key.
   *
   * @param payload - The data to verify.
   * @param signature - The signature to verify.
   * @param publicKey - The public key used for verification.
   * @returns True if the signature is valid, false otherwise.
   */
  verify(
    payload: Uint8Array,
    signature: Uint8Array,
    publicKey: CryptoKey | Uint8Array
  ): Promise<boolean>

  /**
   * Returns the hash algorithm used for signing as a number.
   *
   * @returns The hash algorithm (e.g., SHA-256) as a number.
   */
  getHashAlgorithm(): number

  /**
   * Returns the signature header to be used in the varsig format.
   *
   * @returns The signature header as a number.
   */
  getSignatureHeader(): number

  /**
   * Generates a key pair (private and public keys) for the algorithm.
   *
   * @returns An object containing the private and public keys as Uint8Arrays.
   */
  generateKey(): Promise<
    { privateKey: Uint8Array; publicKey: Uint8Array } | CryptoKeyPair
  >
}
