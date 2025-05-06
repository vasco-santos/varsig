# varsig

> A JavaScript/TypeScript library for working with **varsig-encoded signatures**.

Provides utilities to **create**, **verify**, and **inspect** compact, self-describing digital signatures supporting multiple cryptographic algorithms.

For more information, read the [spec](https://github.com/ChainAgnostic/varsig/tree/main).

## ✨ Features

- ✅ Create varsig signatures
- ✅ Verify varsig signatures
- ✅ Inspect varsig-encoded signature components
- ✅ Support for multiple crypto implementations (e.g., Ed25519, RSA, BLS)
- ❌ Support for payload encoding

---

## 📦 Installation

```bash
npm install varsig
```

---

## 🚀 Usage

### CLI

This CLI allows you to generate key pairs, sign messages with a `varsig`, verify signatures, and inspect `varsig` signatures.

**📝 Flow overview:**

1. ✅ Generate key pair
2. ✅ Sign a message (create varsig)
3. ✅ Verify the varsig
4. ✅ Inspect varsig

---

#### `generate-key`

Generate a new private/public key pair.

##### Usage:

```sh
$ varsig-cli generate-key [options]
```

##### Options:

| Option       | Description                             | Default   |
| ------------ | --------------------------------------- | --------- |
| `-a, --algo` | Signature algorithm (ed25519, rsa, bls) | `ed25519` |
| `--private`  | Output private key file path            | stdout    |
| `--public`   | Output public key file path             | stdout    |

##### Example:

```sh
$ varsig-cli generate-key --algo ed25519 --private priv.key --public pub.key
✅ Private key saved to priv.key
✅ Public key saved to pub.key
```

---

#### `create <message>`

Sign a message and create a `varsig` signature.

##### Usage:

```sh
$ varsig-cli create <message> [options]
```

##### Options:

| Option       | Description                                                            | Default      |
| ------------ | ---------------------------------------------------------------------- | ------------ |
| `-o, --out`  | Output file path (writes raw bytes). If omitted, prints hex to stdout. | stdout (hex) |
| `-a, --algo` | Signature algorithm (ed25519, rsa, bls)                                | `ed25519`    |
| `-k, --key`  | Private key as hex string or file path (required)                      |              |

##### Example:

```sh
$ varsig-cli create "hello world" --key ./priv.key --out signature.varsig
✅ varsig written to signature.varsig
```

You can omit `--out` to print the varsig as hex string to stdout instead.

---

#### `verify <message>`

Verify a `varsig` signature against a message.

##### Usage:

```sh
$ varsig-cli verify <message> [options]
```

##### Options:

| Option  | Description                        | Required |
| ------- | ---------------------------------- | -------- |
| `--key` | Public key hex string or file path | ✅       |
| `--sig` | Varsig signature file path         | ✅       |

##### Example:

```sh
$ varsig-cli verify "hello world" --algo ed25519 --key ./pub.key --sig ./signature.varsig
✅ Signature is valid
```

If the signature is invalid, an error is printed and the command exits with a non-zero status.

---

#### `inspect <varsig>`

Inspect and display the internal components of a `varsig` signature.

##### Usage:

```sh
$ varsig-cli inspect <varsig>
```

`<varsig>` can be a file path or a hex string.

##### Example:

```sh
$ varsig-cli inspect ./signature.varsig
🔍 Varsig Components:
  Varsig Prefix:         0x34
  Signature Header:      0xed
  Hash Algorithm:        0x12
  Signature Byte Length: 0x40
  Encoding Info:         0x5f
  Signature:             0x27a666a89ba3bf04846a981e2c400975975040ff899bb3bda13e0b6ee44ef80fa6b9cfbff1698744113d5dae90010aec1570951a0246d84885444e225ace8703
  Total Length:          70 bytes
```

---

#### 🆘 Help

Run `varsig-cli --help` or `varsig-cli help <command>` to display help for any command.

### Library

#### 1️⃣ **Generate a Key Pair**

```js
import { generateKey } from 'varsig'

// Assuming `cryptoImplementation` is an object implementing the CryptoImplementation interface
const { privateKey, publicKey } = await generateKey(cryptoImplementation)
```

---

#### 2️⃣ **Create a varsig Signature**

```js
import { create } from 'varsig'
import { ed25519Implementation as cryptoImplementation } from 'varsig/crypto/ed25519'

const payload = new TextEncoder().encode('hello world')
const varsig = await create(payload, cryptoImplementation, privateKey)

console.log('varsig:', varsig)
```

---

#### 3️⃣ **Verify a varsig Signature**

```js
import { verify } from 'varsig'

const isValid = await verify(payload, varsig, publicKey)

console.log('Signature valid?', isValid)
```

---

#### 4️⃣ **Inspect a varsig Signature**

```js
import { inspectVarsig } from 'varsig'

const info = inspectVarsig(varsig)

console.log('Decoded varsig:', info)
/*
{
  prefix: '...',
  signatureHeader: '...',
  hashAlgorithm: '...',
  signatureByteLength: '...',
  encodingInfo: '...',
  signature: Uint8Array(...),
  algorithm: 'ed25519',
  totalLength: 123
}
*/
```

---

## 📝 API Reference

### `async create(payload, cryptoImplementation, privateKey): Uint8Array`

Creates a varsig-encoded signature.

- `payload`: `Uint8Array` — Data to sign
- `cryptoImplementation`: `CryptoImplementation` — Object implementing signing logic
- `privateKey`: `Uint8Array | CryptoKey` — Private key
- **Returns**: `Promise<Uint8Array>` — Varsig-encoded signature

---

### `async verify(payload, varsig, publicKey): boolean`

Verifies a varsig-encoded signature.

- `payload`: `Uint8Array` — Data to verify
- `varsig`: `Uint8Array` — Varsig-encoded signature
- `publicKey`: `Uint8Array | CryptoKey` — Public key
- **Returns**: `Promise<boolean>` — Verification result

---

### `inspectVarsig(varsig): object`

Decodes a varsig-encoded signature.

- `varsig`: `Uint8Array` — Varsig signature
- **Returns**: object with:
  - `prefix`: hex string of prefix
  - `signatureHeader`: hex string of signature header
  - `hashAlgorithm`: hex string of hash algorithm
  - `signatureByteLength`: hex string of signature length
  - `encodingInfo`: hex string of encoding info
  - `signature`: `Uint8Array` of signature bytes
  - `algorithm`: string algorithm name (e.g. `"ed25519"`)
  - `totalLength`: number of bytes

---

### `async generateKey(cryptoImplementation): {privateKey, publicKey}`

Generates a key pair for the given crypto implementation.

- `cryptoImplementation`: `CryptoImplementation` — Object implementing key generation
- **Returns**: `Promise<{privateKey, publicKey}>` — Key pair

---

## 🔍 Supported CryptoImplementations

You must provide a `cryptoImplementation` object that implements:

```ts
interface CryptoImplementation {
  getSignatureHeader(): number
  getHashAlgorithm(): number
  sign(
    payload: Uint8Array,
    privateKey: Uint8Array | CryptoKey
  ): Promise<Uint8Array>
  verify(
    payload: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array | CryptoKey
  ): Promise<boolean>
  generateKey(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }>
}
```

You can use built-in implementations or supply your own. The built-in implementations are:

- `varsig/crypto/bls`
- `varsig/crypto/ed25519`
- `varsig/crypto/rsa`

---

## 🛠️ Example CryptoImplementation

```js
const cryptoImplementation = {
  getSignatureHeader: () => 0x01,
  getHashAlgorithm: () => 0x02,
  async sign(payload, privateKey) {
    /* ... */
  },
  async verify(payload, signature, publicKey) {
    /* ... */
  },
  async generateKey() {
    /* ... */
  },
}
```

---

## 🧑‍💻 License

Dual-licensed under [MIT + Apache 2.0](license.md)

---

Enjoy cryptographic signatures with compact, self-describing encodings! 🎉
