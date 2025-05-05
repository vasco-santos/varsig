import * as API from '../api.js'

import { ed25519Implementation } from './ed25519.js'
import { rsaImplementation } from './rsa.js'
import { blsImplementation } from './bls.js'

/** @type {Record<String, API.CryptoImplementation>} */
export const cryptoAlgorithms = {
  ed25519: ed25519Implementation,
  rsa: rsaImplementation,
  bls: blsImplementation,
}
