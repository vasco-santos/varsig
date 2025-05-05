import * as API from '../api.js'
import { bls12_381 as bls } from '@noble/curves/bls12-381'
import { HASH_ALGO_SHA256, SIGNATURE_HEADER_TAGS } from '../constants.js'

/**
 * BLS crypto implementation.
 *
 * @type {API.CryptoImplementation}
 */
export const blsImplementation = {
  /**
   * Signs a payload with BLS private key.
   *
   * @param {Uint8Array} payload - The data to sign.
   * @param {Uint8Array} privateKey - The BLS private key.
   * @returns {Promise<Uint8Array>} The signed payload.
   */
  async sign(payload, privateKey) {
    return await bls.sign(payload, privateKey)
  },

  /**
   * Verifies the BLS signature.
   *
   * @param {Uint8Array} payload - The data to verify.
   * @param {Uint8Array} signature - The signature to verify.
   * @param {Uint8Array} publicKey - The public key for verification.
   * @returns {Promise<boolean>} True if valid, false otherwise.
   */
  async verify(payload, signature, publicKey) {
    const sig = bls.Signature.fromHex(signature)
    return bls.verify(sig, payload, publicKey)
  },

  /**
   * Returns the BLS signature header for varsig.
   *
   * @returns {number} The algorithm signature header.
   */
  getSignatureHeader() {
    return SIGNATURE_HEADER_TAGS.bls
  },

  /**
   * Returns the hash algorithm for varsig.
   *
   * @returns {number} The hash algorithm tag.
   */
  getHashAlgorithm() {
    return HASH_ALGO_SHA256
  },

  /**
   * Generates a new BLS key pair.
   *
   * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array}>} The generated key pair.
   */
  async generateKey() {
    const privateKey = bls.utils.randomPrivateKey()
    const publicKey = bls.getPublicKey(privateKey)
    return { privateKey, publicKey }
  },
}
