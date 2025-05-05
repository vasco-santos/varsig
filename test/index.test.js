/* global console */

import assert from 'assert'

import { varint } from 'multiformats'
import { fromString } from 'uint8arrays'

import { create, verify } from '../src/index.js'
import { ed25519Implementation } from '../src/crypto/ed25519.js'
import { blsImplementation } from '../src/crypto/bls.js'
import { rsaImplementation } from '../src/crypto/rsa.js'
import {
  VARSIG_PREFIX,
  HASH_ALGO_SHA256,
  ENCODING_INFO,
} from '../src/constants.js'

describe('creates a varsig', () => {
  const payload = fromString('hello world')

  /**
   * @type {Array<import('../src/api.js').CryptoImplementation & { algo: string, expectedSigLength: number }>}
   */
  const signers = [
    {
      ...ed25519Implementation,
      algo: 'ed25519',
      expectedSigLength: 64,
    },
    {
      ...blsImplementation,
      algo: 'bls',
      expectedSigLength: 96,
    },
    {
      ...rsaImplementation,
      algo: 'rsa',
      expectedSigLength: 256, // 2048 bits = 256 bytes
    },
  ]

  for (const signer of signers) {
    it(`creates a valid varsig signature for a payload with ${signer.algo} and verifies it`, async () => {
      const { privateKey, publicKey } = await signer.generateKey()

      // Create a varsig signature
      const varsig = await create(payload, signer, privateKey)
      assert(varsig instanceof Uint8Array)

      // Verify prefix values
      const prefixOffset = 0
      const prefixLength = VARSIG_PREFIX.length
      const varsigPrefix = varsig.slice(
        prefixOffset,
        prefixOffset + prefixLength
      )
      assert.deepEqual(
        varsigPrefix,
        VARSIG_PREFIX,
        'varsig prefix should match'
      )

      // Verify signature header values
      const sigHeaderOffset = prefixOffset + prefixLength
      const [decodedSignatureHeaderCode, decodedSignatureHeaderLength] =
        varint.decode(varsig.subarray(sigHeaderOffset))
      assert.deepEqual(
        decodedSignatureHeaderCode,
        signer.getSignatureHeader(),
        'signature header should match'
      )

      // Verify hash algorithm values
      const hashAlgoOffset = sigHeaderOffset + decodedSignatureHeaderLength
      const [decodedHashAlgorithmCode, decodedHashAlgorithmLength] =
        varint.decode(varsig.subarray(hashAlgoOffset))
      assert.deepEqual(
        decodedHashAlgorithmCode,
        HASH_ALGO_SHA256,
        'hash algorithm should match'
      )

      // Verify signature length bytes
      const signatureLengthOffset = hashAlgoOffset + decodedHashAlgorithmLength
      const [decodedSigLength, decodedSigLengthBytesLength] = varint.decode(
        varsig.subarray(signatureLengthOffset)
      )
      assert.equal(
        decodedSigLength,
        signer.expectedSigLength,
        `signature length bytes should encode ${signer.expectedSigLength} for ${signer.algo}`
      )

      // Verify encoding info bytes
      const encodingInfoOffset =
        signatureLengthOffset + decodedSigLengthBytesLength
      const [decodedEncodingInfoCode, decodedEncodingInfoLength] =
        varint.decode(varsig.subarray(encodingInfoOffset))
      assert.equal(
        decodedEncodingInfoCode,
        ENCODING_INFO,
        'encoding info code should match'
      )

      // Verify Signature bytes
      const sigBytesOffset = encodingInfoOffset + decodedEncodingInfoLength
      const sigBytes = varsig.slice(sigBytesOffset)
      assert.equal(
        sigBytes.length,
        signer.expectedSigLength,
        `sig-bytes should be ${signer.expectedSigLength} bytes for ${signer.algo}`
      )

      const verified = await verify(payload, varsig, publicKey)
      assert(verified, `signature should verify for ${signer.algo}`)
      console.log(`✅ verified: ${verified} for ${signer.algo}`)
    })
  }
})
