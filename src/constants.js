export const VARSIG_PREFIX = Uint8Array.of(0x34)
export const HASH_ALGO_SHA256 = 0x12 // multicodec sha2-256 tag
export const ENCODING_INFO = 0x5f // Single verbatim payload (without key)

export const SIGNATURE_HEADER_TAGS = {
  ed25519: 0xed,
  rsa: 0x1205,
  bls: 0x1309,
}
