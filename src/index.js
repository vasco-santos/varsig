import * as API from './api.js'

import { varint } from 'multiformats'
import { toString } from 'uint8arrays'

import { cryptoAlgorithms } from './crypto/implementations.js'
import {
  VARSIG_PREFIX,
  SIGNATURE_HEADER_TAGS,
  ENCODING_INFO,
} from './constants.js'

/**
 * Create a varsig signature for a payload.
 *
 * @param {Uint8Array} payload - The data to sign.
 * @param {API.CryptoImplementation} cryptoImplementation - The crypto implementation (ed25519, rsa, bls).
 * @param {Uint8Array|CryptoKey} privateKey - The private key for signing.
 * @returns {Promise<Uint8Array>} The varsig-encoded signature.
 */
export async function create(payload, cryptoImplementation, privateKey) {
  // varsig = [ varsig-prefix, signature-header, varsig-body ]
  // varsig-body = [ hash-algorithm, signature-length (2 bytes), encoding-info, sig-bytes ]

  const prefix = VARSIG_PREFIX
  const signatureHeaderBytes = encodeVarint(
    cryptoImplementation.getSignatureHeader()
  )
  const hashAlgorithmBytes = encodeVarint(
    cryptoImplementation.getHashAlgorithm()
  )

  // Prepare signature
  const signature = await cryptoImplementation.sign(payload, privateKey)

  const signatureLengthBytes = encodeVarint(signature.length)
  const encodingInfoBytes = encodeVarint(ENCODING_INFO)

  // Prepare varsig
  const totalLength =
    prefix.length +
    signatureHeaderBytes.length +
    hashAlgorithmBytes.length +
    signatureLengthBytes.length +
    encodingInfoBytes.length +
    signature.length

  const varsig = new Uint8Array(totalLength)

  let offset = 0
  varsig.set(prefix, offset)
  offset += prefix.length
  varsig.set(signatureHeaderBytes, offset)
  offset += signatureHeaderBytes.length
  varsig.set(hashAlgorithmBytes, offset)
  offset += hashAlgorithmBytes.length
  varsig.set(signatureLengthBytes, offset)
  offset += signatureLengthBytes.length
  varsig.set(encodingInfoBytes, offset)
  offset += encodingInfoBytes.length
  varsig.set(signature, offset)

  return varsig
}

/**
 * Verify a varsig signature for a payload.
 *
 * @param {Uint8Array} payload - The data to verify.
 * @param {Uint8Array} varsig - The varsig-encoded signature.
 * @param {Uint8Array|CryptoKey} publicKey - The public key for verification.
 * @returns {Promise<boolean>} True if valid, false otherwise.
 */
export async function verify(payload, varsig, publicKey) {
  const { signature, algorithm } = inspectVarsig(varsig)

  const cryptoImplementation = cryptoAlgorithms[algorithm]

  return await cryptoImplementation.verify(payload, signature, publicKey)
}

/**
 * Inspect the components of a varsig signature.
 *
 * @param {Uint8Array} varsig - The varsig as a Uint8Array.
 * @returns {{
 *   prefix: string,
 *   signatureHeader: string,
 *   hashAlgorithm: string,
 *   signatureByteLength: string,
 *   encodingInfo: string,
 *   signature: Uint8Array,
 *   algorithm: string,
 *   totalLength: number
 * }} An object containing the decoded varsig components:
 * - `prefix`: hex string of the varsig prefix
 * - `signatureHeader`: hex string of the signature algorithm identifier
 * - `hashAlgorithm`: hex string of the algorithm hash
 * - `signatureByteLength`: hex string of the signature byte length
 * - `encodingInfo`: hex string of the encoding info
 * - `signature`: signature bytes
 * - `algorithm`: string name of the matched algorithm (e.g. "ed25519")
 * - `totalLength`: total length of the input varsig
 */
export function inspectVarsig(varsig) {
  // varsig = [ varsig-prefix, signature-header, varsig-body ]
  // varsig-body = [ hash-algorithm, signature-length (2 bytes), encoding-info, sig-bytes ]

  const prefixLength = VARSIG_PREFIX.length
  const prefix = varsig.slice(0, prefixLength)

  // Decode signature header
  const { value: signatureHeaderCode, nextOffset: offsetAfterSignatureHeader } =
    decodeVarintAt(varsig, prefixLength)

  const signatureHeaderMatched = Object.entries(SIGNATURE_HEADER_TAGS).find(
    ([algo, code]) => code === signatureHeaderCode
  )?.[0]

  /* c8 ignore next 3 */
  if (!signatureHeaderMatched) {
    throw new Error(`Unknown signature header code: ${signatureHeaderCode}`)
  }

  // Decode hash algorithm
  const { value: hashAlgorithmCode, nextOffset: offsetAfterHashAlgorithm } =
    decodeVarintAt(varsig, offsetAfterSignatureHeader)

  // Decode signature length
  const {
    value: signatureLengthValue,
    length: signatureLengthBytesLength,
    nextOffset: encodingInfoOffset,
  } = decodeVarintAt(varsig, offsetAfterHashAlgorithm)

  const signatureLengthBytes = varsig.slice(
    offsetAfterHashAlgorithm,
    offsetAfterHashAlgorithm + signatureLengthBytesLength
  )

  // Decode encoding info
  const { value: encodingInfoCode, nextOffset: signatureStart } =
    decodeVarintAt(varsig, encodingInfoOffset)

  const signatureEnd = signatureStart + signatureLengthValue
  const signature = varsig.slice(signatureStart, signatureEnd)

  return {
    prefix: toString(prefix, 'hex'),
    signatureHeader: signatureHeaderCode.toString(16),
    hashAlgorithm: hashAlgorithmCode.toString(16),
    signatureByteLength: toString(signatureLengthBytes, 'hex'),
    encodingInfo: encodingInfoCode.toString(16),
    signature,
    algorithm: signatureHeaderMatched,
    totalLength: varsig.length,
  }
}

/**
 * Generate a key pair for an algorithm.
 *
 * @param {API.CryptoImplementation} cryptoImplementation - The crypto implementation (ed25519, rsa, bls).
 * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array} | CryptoKeyPair>} The generated key pair.
 */
export function generateKey(cryptoImplementation) {
  /* c8 ignore next 2 */
  return cryptoImplementation.generateKey()
}

/**
 * @param {number} code
 * @returns {Uint8Array}
 */
function encodeVarint(code) {
  const len = varint.encodingLength(code)
  const bytes = new Uint8Array(len)
  varint.encodeTo(code, bytes, 0)
  return bytes
}

/**
 * @param {Uint8Array} buffer
 * @param {number} offset
 */
function decodeVarintAt(buffer, offset) {
  const [value, length] = varint.decode(buffer.subarray(offset))
  return { value, length, nextOffset: offset + length }
}
