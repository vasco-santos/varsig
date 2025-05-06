#!/usr/bin/env node

/* global console, process, Buffer */
import sade from 'sade'
import fs from 'fs'
import updateNotifier from 'update-notifier'
import { fromString } from 'uint8arrays'

import { create, verify, inspectVarsig } from './index.js'
import { cryptoAlgorithms } from './crypto/implementations.js'

const pkg = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url)).toString()
)
updateNotifier({ pkg }).notify({ isGlobal: true })

const cli = sade('varsig-cli')
cli.version(pkg.version)

cli
  .command('create <message>')
  .option('-o, --out', 'Output file path (default: stdout)')
  .option('-a, --algo', 'Signature algorithm (default: ed25519)', 'ed25519')
  .option('-k, --key', 'Private key as hex string or file path (required)')
  .describe('create a varsig for a message')
  .action(
    /**
     * CLI action to create a varsig signature.
     *
     * @param {string} message - The message to sign.
     * @param {{
     *   out?: string,
     *   algo: string,
     *   key: string
     * }} opts - Command options.
     * @returns {Promise<void>}
     */
    async (message, opts) => {
      const { out, algo, key: keyInput } = opts
      if (algo === 'rsa') {
        console.error(
          '❌ RSA support is not yet available in CLI mode. Please use ed25519.'
        )
        process.exit(1)
      }

      if (!keyInput) {
        console.error('❌ Error: --key is required')
        process.exit(1)
      }

      const cryptoImpl = cryptoAlgorithms[algo]
      if (!cryptoImpl) {
        console.error(`❌ Unsupported algorithm: ${algo}`)
        process.exit(1)
      }

      let keyHex
      try {
        if (keyInput.startsWith('/') || keyInput.startsWith('./')) {
          keyHex = fs.readFileSync(keyInput, 'utf8').trim()
        } else {
          keyHex = keyInput
        }
      } catch (/** @type {any} */ err) {
        console.error(`❌ Error reading key: ${err.message}`)
        process.exit(1)
      }

      let privateKey
      try {
        const keyBytes = Buffer.from(keyHex, 'hex')
        if (keyBytes.length !== 32) {
          // adjust if needed for RSA/BLS
          throw new Error(
            `Private key must be 32 bytes (64 hex chars), got ${keyBytes.length} bytes`
          )
        }
        privateKey = new Uint8Array(keyBytes)
      } catch (/** @type {any} */ err) {
        console.error(`❌ Invalid private key hex: ${err.message}`)
        process.exit(1)
      }

      try {
        const payload = fromString(message)
        const varsig = await create(payload, cryptoImpl, privateKey)
        if (out) {
          // ✅ write raw bytes
          fs.writeFileSync(out, Buffer.from(varsig))
          console.log(`✅ varsig written to ${out}`)
        } else {
          // ✅ still print hex to stdout for human use
          console.log(Buffer.from(varsig).toString('hex'))
        }
      } catch (/** @type {any} */ err) {
        console.error(`❌ Error creating signature: ${err.message}`)
        process.exit(1)
      }
    }
  )

cli
  .command('verify <message>')
  .option('--key', 'Public key hex or file path (required)')
  .option('--sig', 'Varsig file path (required)')
  .describe('verify a varsig signature for a message')
  .action(async (message, opts) => {
    if (!opts.key || !opts.sig) {
      console.error(`❌ Missing --key or --sig`)
      process.exit(1)
    }

    let pubHex
    try {
      pubHex =
        opts.key.startsWith('/') || opts.key.startsWith('./')
          ? fs.readFileSync(opts.key, 'utf8').trim()
          : opts.key
    } catch (/** @type {any} */ err) {
      console.error(`❌ Error reading public key: ${err.message}`)
      process.exit(1)
    }

    if (!/^[0-9a-fA-F]+$/.test(pubHex)) {
      console.error('❌ Invalid hex format')
      process.exit(1)
    }

    pubHex = pubHex.replace(/\s+/g, '').toLowerCase() // Remove any spaces/newlines

    let publicKey
    try {
      const pubBytes = Buffer.from(pubHex, 'hex')
      publicKey = new Uint8Array(pubBytes)
    } catch (/** @type {any} */ err) {
      console.error(`❌ Invalid public key hex: ${err.message}`)
      process.exit(1)
    }

    let varsig
    try {
      // ✅ read raw bytes
      varsig = fs.readFileSync(opts.sig)
      varsig = new Uint8Array(varsig)
    } catch (/** @type {any} */ err) {
      console.error(`❌ Error reading signature: ${err.message}`)
      process.exit(1)
    }

    const payload = fromString(message)
    // @ts-ignore
    const valid = await verify(payload, varsig, publicKey)
    if (valid) {
      console.log(`✅ Signature is valid`)
    } else {
      console.error(`❌ Invalid signature`)
      process.exit(1)
    }
  })

cli
  .command('inspect <varsig>')
  .describe('Inspect and display the components of a varsig signature')
  .action(async (varsigInput) => {
    try {
      // Read the varsig as a Uint8Array from file or hex string
      let varsig
      if (varsigInput.startsWith('/') || varsigInput.startsWith('./')) {
        varsig = fs.readFileSync(varsigInput)
      } else {
        varsig = new Uint8Array(Buffer.from(varsigInput, 'hex'))
      }

      // Inspect the varsig
      const components = await inspectVarsig(varsig)
      console.log(`🔍 Varsig Components:`)
      console.log(`  Varsig Prefix:         0x${components.prefix}`)
      console.log(`  Signature Header:      0x${components.signatureHeader}`)
      console.log(`  Hash Algorithm:        0x${components.hashAlgorithm}`)
      console.log(
        `  Signature Byte Length: 0x${components.signatureByteLength}`
      )
      console.log(`  Encoding Info:         0x${components.encodingInfo}`)
      console.log(
        `  Signature:             0x${Buffer.from(
          components.signature
        ).toString('hex')}`
      )
      console.log(`  Total Length:          ${components.totalLength} bytes`)
    } catch (/** @type {any} */ err) {
      console.error(`❌ Error inspecting varsig: ${err.message}`)
      process.exit(1)
    }
  })

cli
  .command('generate-key')
  .option('-a, --algo', 'Signature algorithm (default: ed25519)', 'ed25519')
  .option('--private', 'Output private key file path')
  .option('--public', 'Output public key file path')
  .describe('generate a private/public key pair')
  .action(async (opts) => {
    if (opts.algo === 'rsa') {
      console.error(
        '❌ RSA support is not yet available in CLI mode. Please use ed25519.'
      )
      process.exit(1)
    }
    const cryptoImpl = cryptoAlgorithms[opts.algo]
    if (!cryptoImpl) {
      console.error(`❌ Unsupported algorithm: ${opts.algo}`)
      process.exit(1)
    }

    try {
      const { privateKey, publicKey } = await cryptoImpl.generateKey()
      // @ts-ignore
      const privHex = Buffer.from(privateKey).toString('hex')
      // @ts-ignore
      const pubHex = Buffer.from(publicKey).toString('hex')

      if (opts.private) {
        fs.writeFileSync(opts.private, privHex)
        console.log(`✅ Private key saved to ${opts.private}`)
      } else {
        console.log(`Private key (hex): ${privHex}`)
      }

      if (opts.public) {
        fs.writeFileSync(opts.public, pubHex)
        console.log(`✅ Public key saved to ${opts.public}`)
      } else {
        console.log(`Public key (hex): ${pubHex}`)
      }
    } catch (/** @type {any} */ err) {
      console.error(`❌ Error generating key: ${err.message}`)
      process.exit(1)
    }
  })

cli.parse(process.argv)

cli.command('help [cmd]', 'Show help text', { default: true }).action((cmd) => {
  try {
    cli.help(cmd)
  } catch (/** @type {any} */ err) {
    console.log(`
ERROR
  Invalid command: ${cmd}
  
Run \`$ varsig-cli --help\` for more info.
`)
    process.exit(1)
  }
})

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err)
})

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason)
})
