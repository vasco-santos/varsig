/* global crypto */
import * as API from '../api.js'

import { HASH_ALGO_SHA256, SIGNATURE_HEADER_TAGS } from '../constants.js'

/**
 * RSA crypto implementation.
 *
 * @type {API.CryptoImplementation}
 */
export const rsaImplementation = {
  /**
   * Signs a payload with RSA private key.
   *
   * @param {Uint8Array} payload - The data to sign.
   * @param {CryptoKey} privateKey - The RSA private key.
   * @returns {Promise<Uint8Array>} The signed payload.
   */
  async sign(payload, privateKey) {
    return new Uint8Array(
      await crypto.subtle.sign(
        { name: 'RSASSA-PKCS1-v1_5' },
        privateKey,
        payload
      )
    )
  },

  /**
   * Verifies the RSA signature.
   *
   * @param {Uint8Array} payload - The data to verify.
   * @param {Uint8Array} signature - The signature to verify.
   * @param {CryptoKey} publicKey - The public key for verification.
   * @returns {Promise<boolean>} True if valid, false otherwise.
   */
  async verify(payload, signature, publicKey) {
    return await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      publicKey,
      signature,
      payload
    )
  },

  /**
   * Returns the RSA signature header for varsig.
   *
   * @returns {number} The algorithm signature header.
   */
  getSignatureHeader() {
    return SIGNATURE_HEADER_TAGS.rsa
  },

  /**
   * Returns the hash algorithm used for signing.
   *
   * @returns {number} The hash algorithm (e.g., SHA-256).
   */
  getHashAlgorithm() {
    return HASH_ALGO_SHA256
  },

  /**
   * Generates a new RSA key pair.
   *
   * @returns {Promise<CryptoKeyPair>} The generated key pair.
   */
  async generateKey() {
    return crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    )
  },
}
