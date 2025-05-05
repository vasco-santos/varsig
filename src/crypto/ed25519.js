import * as API from '../api.js'

import * as ED25519 from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'

// ✅ manually set sync hash function for noble
// @ts-expect-error no type for m
ED25519.etc.sha512Sync = (...m) => sha512(...m)

import { HASH_ALGO_SHA256, SIGNATURE_HEADER_TAGS } from '../constants.js'

/**
 * Ed25519 crypto implementation.
 *
 * @type {API.CryptoImplementation}
 */
export const ed25519Implementation = {
  /**
   * Signs a payload with Ed25519 private key.
   *
   * @param {Uint8Array} payload - The data to sign.
   * @param {Uint8Array} privateKey - The private key for signing.
   * @returns {Promise<Uint8Array>} The signed payload.
   */
  async sign(payload, privateKey) {
    return await ED25519.sign(payload, privateKey)
  },

  /**
   * Verifies the Ed25519 signature.
   *
   * @param {Uint8Array} payload - The data to verify.
   * @param {Uint8Array} signature - The signature to verify.
   * @param {Uint8Array} publicKey - The public key for verification.
   * @returns {Promise<boolean>} True if valid, false otherwise.
   */
  async verify(payload, signature, publicKey) {
    return await ED25519.verify(signature, payload, publicKey)
  },

  /**
   * Returns the Ed25519 signature header for varsig.
   *
   * @returns {number} The algorithm signature header.
   */
  getSignatureHeader() {
    return SIGNATURE_HEADER_TAGS.ed25519
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
   * Generates a new Ed25519 key pair.
   *
   * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array}>} The generated key pair.
   */
  async generateKey() {
    const privateKey = ED25519.utils.randomPrivateKey()
    const publicKey = await ED25519.getPublicKey(privateKey)
    return { privateKey, publicKey }
  },
}
