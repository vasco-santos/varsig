/**
 * Parse a varsig-encoded signature into its components.
 *
 * @param {Uint8Array} varsig - The varsig-encoded signature.
 * @returns {{
 *   varsigHeader: number,
 *   hashAlgorithm: number,
 *   encodingInfo: number,
 *   sigBytes: Uint8Array
 * }} The parsed components.
 */
export function parseVarsig(varsig) {
  const varsigHeader = varsig[0]
  const hashAlgorithm = varsig[1]
  const encodingInfo = varsig[2]
  const sigBytes = varsig.slice(3)

  return { varsigHeader, hashAlgorithm, encodingInfo, sigBytes }
}
