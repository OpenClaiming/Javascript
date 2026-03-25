// Optional strict canonicalizer (Node only):
// npm install json-canonicalize
// https://github.com/cyberphone/json-canonicalization

let strictCanonicalize = null

if (typeof require !== "undefined") {
  try { strictCanonicalize = require("json-canonicalize").canonicalize } catch {}
}

// ---------- ENV DETECTION ----------

const isNode = typeof process !== "undefined" && !!process.versions?.node

// Resolve SubtleCrypto — works in Node 18+ (globalThis.crypto), browsers, and
// Node 16 (crypto.webcrypto.subtle). Never import node:crypto at module level
// so this file loads cleanly in browsers.
const _subtle = (() => {
  if (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) {
    return globalThis.crypto.subtle
  }
  if (typeof window !== "undefined" && window.crypto?.subtle) {
    return window.crypto.subtle
  }
  // Node 16 fallback — lazy require so browsers never hit this branch
  if (isNode) {
    try { return require("crypto").webcrypto.subtle } catch {}
  }
  return null
})()

// atob/btoa — available natively in browsers and Node 16+
const _atob = typeof atob  !== "undefined" ? atob  : (b64) => Buffer.from(b64, "base64").toString("binary")
const _btoa = typeof btoa  !== "undefined" ? btoa  : (bin) => Buffer.from(bin, "binary").toString("base64")

// ---------- CACHE ----------

const CACHE_TTL = 60_000 // 60 seconds

const urlCache = new Map()
const keyCache = new Map()
const pubKeyCache = new Map()

function now() {
  return Date.now()
}

function getCache(map, key) {
  if (!map.has(key)) return null
  const entry = map.get(key)
  if (now() > entry.exp) {
    map.delete(key)
    return null
  }
  return entry.val
}

function setCache(map, key, val) {
  map.set(key, { val, exp: now() + CACHE_TTL })
}

// ---------- NORMALIZATION ----------

// RFC 8785 / JCS: numbers stay as numbers, booleans stay as booleans.
// Only object keys are sorted recursively.
// Callers must use strings for integers outside Number.MAX_SAFE_INTEGER.
function normalize(v) {

  if (Array.isArray(v)) {
    return v.map(normalize)
  }

  if (v && typeof v === "object") {
    const out = {}
    for (const k of Object.keys(v).sort()) {
      out[k] = normalize(v[k])
    }
    return out
  }

  // Numbers and booleans are preserved as-is (RFC 8785).
  // Strings, null, undefined pass through unchanged.
  return v
}

// ---------- VALIDATION ----------

// Walk a value and throw if any number is outside IEEE 754 safe integer range.
// For large integers (e.g. uint256 EIP712 fields), callers must use strings.
function validateNumbers(v, path) {
  path = path || "claim"

  if (Array.isArray(v)) {
    v.forEach(function (item, i) { validateNumbers(item, path + "[" + i + "]") })
    return
  }

  if (v && typeof v === "object") {
    for (const k of Object.keys(v)) {
      validateNumbers(v[k], path + "." + k)
    }
    return
  }

  if (typeof v === "number" && !Number.isSafeInteger(v) && !Number.isFinite(v) === false) {
    // Allow floats — only reject unsafe integers
    if (Number.isInteger(v) && !Number.isSafeInteger(v)) {
      throw new Error(
        "OpenClaim: integer at " + path + " exceeds safe range — use a string instead"
      )
    }
  }
}

// ---------- BINARY HELPERS ----------
// All binary ops use Uint8Array so they work identically in Node and browser.

function _toUint8Array(v) {
  if (v instanceof Uint8Array) return v
  if (v instanceof ArrayBuffer) return new Uint8Array(v)
  if (typeof v === "string") return new TextEncoder().encode(v)
  if (isNode && Buffer.isBuffer(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
  throw new Error("OpenClaim: unsupported binary type")
}

// base64 encode/decode — universal, no Buffer dependency
function _toBase64(bytes) {
  bytes = _toUint8Array(bytes)
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return _btoa(bin)
}

function _fromBase64(b64) {
  const bin = _atob(String(b64).replace(/\s+/g, ""))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function _fromBase64url(b64url) {
  const pad = b64url.length % 4
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") +
    (pad ? "=".repeat(4 - pad) : "")
  return _fromBase64(b64)
}

function _hexToBytes(hex) {
  hex = hex.replace(/^0x/, "")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

// ---------- PROTOCOL HELPERS ----------

function toArray(v) {
  if (v == null) return []
  return Array.isArray(v) ? v : [v]
}

function normalizeSignatures(v) {
  const arr = toArray(v)
  return arr.map(x => x == null ? null : String(x))
}

function ensureStringKeys(keys) {
  for (const k of keys) {
    if (typeof k !== "string") throw new Error("OpenClaim: all keys must be strings")
  }
}

function ensureUniqueKeys(keys) {
  const seen = new Set()
  for (const k of keys) {
    if (seen.has(k)) throw new Error("OpenClaim: duplicate keys are not allowed")
    seen.add(k)
  }
}

function ensureSortedKeys(keys) {
  const sorted = [...keys].sort()
  for (let i = 0; i < keys.length; i++) {
    if (keys[i] !== sorted[i]) throw new Error("OpenClaim: key array must be lexicographically sorted")
  }
}

// Strip PEM headers and whitespace → bare base64 DER string
function _pemToBase64Der(pem) {
  return pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "")
}

// Wrap bare base64 DER in PEM headers
function _base64DerToPem(b64) {
  const body = String(b64).replace(/\s+/g, "")
  const lines = body.match(/.{1,64}/g) || []
  return ["-----BEGIN PUBLIC KEY-----", ...lines, "-----END PUBLIC KEY-----"].join("\n")
}

// Derive the public SPKI DER base64 from a PEM private key (Node only)
function _derivePublicBase64Der(privateKeyPem) {
  if (!isNode) throw new Error("OpenClaim: deriving public key from PEM requires Node")
  const nodeCrypto = require("crypto")
  const pubPem = nodeCrypto.createPublicKey(privateKeyPem)
    .export({ type: "spki", format: "pem" })
    .toString()
  return _pemToBase64Der(pubPem)
}

// Build a data:key/es256;base64,<DER> URI from a raw uncompressed P-256 public key (Uint8Array, 65 bytes)
// SPKI wrapper for P-256 uncompressed point — same as what SubtleCrypto exportKey("spki") produces
const _P256_SPKI_PREFIX = _fromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE")

function _rawPublicKeyToKeyString(rawPublicKey) {
  // rawPublicKey: 65-byte uncompressed point (04 || X || Y)
  // SPKI = sequence { AlgorithmIdentifier(ecPublicKey, prime256v1), bitString(00 || point) }
  // The prefix above encodes everything up to and including the leading 04 of the point.
  // So SPKI = prefix(30 bytes) || X(32) || Y(32)
  const spki = new Uint8Array(_P256_SPKI_PREFIX.length + rawPublicKey.length - 1)
  spki.set(_P256_SPKI_PREFIX, 0)
  spki.set(rawPublicKey.slice(1), _P256_SPKI_PREFIX.length) // skip the 04 prefix byte
  return "data:key/es256;base64," + _toBase64(spki)
}

// Export a SubtleCrypto public CryptoKey to a data:key/es256;base64,<SPKI> URI
function _cryptoKeyToKeyString(publicCryptoKey) {
  return _subtle.exportKey("spki", publicCryptoKey)
    .then(function (spkiBuffer) {
      return "data:key/es256;base64," + _toBase64(new Uint8Array(spkiBuffer))
    })
}

// ---------- CRYPTO ----------

// Universal sign: takes PEM private key (Node) or PKCS8 base64 (browser).
// Always receives the canonical string — hashing is handled internally by
// both Node crypto.sign("sha256",...) and SubtleCrypto {hash:"SHA-256"}.
function signAsync(privateKeyInput, canonicalString) {
  const data = new TextEncoder().encode(canonicalString)

  if (isNode && typeof privateKeyInput === "string" && privateKeyInput.includes("PRIVATE KEY")) {
    const nodeCrypto = require("crypto")
    return Promise.resolve(
      new Uint8Array(nodeCrypto.sign("sha256", Buffer.from(data), privateKeyInput))
    )
  }

  // Browser path: privateKeyInput is either a PEM string or a base64 PKCS8 DER string
  // or a CryptoKey already
  return _importPrivateKey(privateKeyInput).then(function (key) {
    return _subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data)
  }).then(function (sig) { return new Uint8Array(sig) })
}

// Universal verify: publicKeyInput is a PEM string (Node) or base64 SPKI DER string (both).
// sig is Uint8Array. Always receives canonical string — hashing handled internally.
function verifyAsync(publicKeyInput, sig, canonicalString) {
  const data = new TextEncoder().encode(canonicalString)

  if (isNode && typeof publicKeyInput === "string" && publicKeyInput.includes("PUBLIC KEY")) {
    const nodeCrypto = require("crypto")
    return Promise.resolve(
      nodeCrypto.verify("sha256", Buffer.from(data), publicKeyInput, Buffer.from(sig))
    )
  }

  return _importPublicKey(publicKeyInput).then(function (key) {
    return _subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, data)
  })
}

// ---------- WEBCRYPTO KEY IMPORT ----------

// Cache imported CryptoKey objects by base64 DER to avoid repeated imports
const _cryptoKeyCache = new Map()

function _importPublicKey(input) {
  // input: PEM string or base64 SPKI DER string
  const b64 = input.includes("BEGIN PUBLIC KEY") ? _pemToBase64Der(input) : input.replace(/\s+/g, "")
  const cached = getCache(_cryptoKeyCache, b64)
  if (cached) return Promise.resolve(cached)

  const spki = _fromBase64(b64).buffer
  return _subtle.importKey(
    "spki", spki,
    { name: "ECDSA", namedCurve: "P-256" },
    false, ["verify"]
  ).then(function (key) {
    setCache(_cryptoKeyCache, b64, key)
    return key
  })
}

function _importPrivateKey(input) {
  // input: PEM PKCS8 string or base64 PKCS8 DER string or CryptoKey
  if (input && typeof input === "object" && input.type === "private") return Promise.resolve(input)
  const b64 = (typeof input === "string" && input.includes("PRIVATE KEY"))
    ? input.replace(/-----.*PRIVATE KEY-----/g, "").replace(/\s+/g, "")
    : String(input).replace(/\s+/g, "")
  const pkcs8 = _fromBase64(b64).buffer
  return _subtle.importKey(
    "pkcs8", pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false, ["sign"]
  )
}

// ---------- DATA KEY PARSER ----------

// Parse a data:key/ URI → { fmt: "ES256"|"EIP712", value: Uint8Array|string }
// value is Uint8Array for ES256 (raw SPKI DER bytes), string for EIP712 (address).
function parseDataKey(keyStr) {
  if (!keyStr.startsWith("data:key/")) return null
  const idx = keyStr.indexOf(",")
  if (idx < 0) return null

  const meta = keyStr.slice(5, idx)   // e.g. "key/es256;base64"
  const data = keyStr.slice(idx + 1)

  const [typePart, ...params] = meta.split(";")
  const fmt = typePart.replace("key/", "").toUpperCase()

  let encoding = "raw"
  for (const p of params) {
    if (p === "base64")    encoding = "base64"
    if (p === "base64url") encoding = "base64url"
  }

  let value
  if (encoding === "base64")    { value = _fromBase64(data) }
  else if (encoding === "base64url") { value = _fromBase64url(data) }
  else { value = data } // raw string (e.g. EIP712 address)

  return { fmt, value }
}

// ---------- FETCH ----------

function fetchJson(url) {
  const cached = getCache(urlCache, url)
  if (cached !== null) return Promise.resolve(cached)

  return fetch(url)
    .then(r => r.ok ? r.json() : null)
    .catch(() => null)
    .then(json => {
      setCache(urlCache, url, json)
      return json
    })
}

// ---------- KEY RESOLUTION ----------

function resolveKeyString(keyStr, seen = new Set()) {
  if (seen.has(keyStr)) {
    return Promise.reject(
      new Error("OpenClaim: cyclic key reference detected")
    )
  }

  const cached = getCache(keyCache, keyStr)
  if (cached !== null) return Promise.resolve(cached)

  const nextSeen = new Set(seen)
  nextSeen.add(keyStr)

  if (keyStr.startsWith("data:key/")) {
    const parsed = parseDataKey(keyStr)
    if (parsed) {
      setCache(keyCache, keyStr, parsed)
      return Promise.resolve(parsed)
    }
  }

  if (keyStr.startsWith("http")) {
    const [url, ...path] = keyStr.split("#")
    return fetchJson(url).then(json => {
      if (!json) return null
      let current = json
      path.forEach(p => { if (p) current = current?.[p] })
      if (Array.isArray(current)) return current
      if (typeof current === "string") {
        return resolveKeyString(current, nextSeen)
      }
      return null
    }).then(res => {
      setCache(keyCache, keyStr, res)
      return res
    })
  }

  const idx = keyStr.indexOf(":")
  if (idx > 0) {
    const result = {
      fmt: keyStr.slice(0, idx).toUpperCase(),
      value: keyStr.slice(idx + 1)
    }
    setCache(keyCache, keyStr, result)
    return Promise.resolve(result)
  }

  return Promise.resolve(null)
}

// ---------- KEY STATE ----------

function buildSortedKeyState(keysInput, signaturesInput) {
  const keys = toArray(keysInput).slice()
  const signatures = normalizeSignatures(signaturesInput)

  ensureStringKeys(keys)
  ensureUniqueKeys(keys)

  if (signatures.length > keys.length) {
    throw new Error("OpenClaim: signature array cannot be longer than key array")
  }

  const pairs = keys.map((key, i) => ({
    key,
    sig: i < signatures.length ? signatures[i] : null
  }))

  pairs.sort((a, b) => a.key.localeCompare(b.key))

  const sortedKeys = pairs.map(p => p.key)
  const sortedSignatures = pairs.map(p => p.sig)

  ensureSortedKeys(sortedKeys)

  return { keys: sortedKeys, signatures: sortedSignatures }
}

function parseVerifyPolicy(policy, totalKeys) {
  if (policy == null) return { minValid: 1 }
  if (typeof policy === "number") return { minValid: policy }
  if (policy.mode === "all") return { minValid: totalKeys }
  if (typeof policy.minValid === "number") return { minValid: policy.minValid }
  return { minValid: 1 }
}

// ---------- MAIN ----------

export class OpenClaim {

  /**
   * Produce canonical JSON for signing/verification.
   * RFC 8785 / JCS: keys sorted recursively, numbers preserved as numbers,
   * booleans preserved as booleans. sig field always excluded.
   */
  static canonicalize(claim) {
    const obj = { ...claim }
    delete obj.sig
    if (strictCanonicalize) return strictCanonicalize(obj)
    return JSON.stringify(normalize(obj))
  }

  /**
   * Sign a claim with a P-256 private key.
   *
   * privateKeyInput accepts:
   *   - PEM PKCS8 string (Node)
   *   - base64 PKCS8 DER string (both)
   *   - SubtleCrypto CryptoKey {type:"private"} (browser)
   *
   * publicKeyInput (optional) — provide when using CryptoKey or raw key pair:
   *   - SubtleCrypto CryptoKey {type:"public"} → resolved to key URI via exportKey
   *   - Uint8Array 65-byte uncompressed raw point (04||X||Y)
   *   - PEM public key string (Node)
   *   - omit when privateKeyInput is PEM (public key derived automatically on Node)
   *
   * Pass existing = { keys, signatures } to add to a multisig claim.
   */
  static sign(claim, privateKeyInput, publicKeyInput, existing) {

    // Allow sign(claim, privateKey, existing) when publicKeyInput is an object
    // that looks like existing rather than a key
    if (
      publicKeyInput &&
      typeof publicKeyInput === "object" &&
      !ArrayBuffer.isView(publicKeyInput) &&
      !(publicKeyInput instanceof ArrayBuffer) &&
      publicKeyInput.type === undefined &&
      (publicKeyInput.keys !== undefined || publicKeyInput.signatures !== undefined)
    ) {
      existing = publicKeyInput
      publicKeyInput = null
    }
    existing = existing || {}

    validateNumbers(claim)

    // Resolve the key URI for this signer
    function resolveSignerKeyString() {
      // CryptoKey public
      if (publicKeyInput && typeof publicKeyInput === "object" && publicKeyInput.type === "public") {
        return _cryptoKeyToKeyString(publicKeyInput)
      }
      // Raw 65-byte uncompressed point
      if (publicKeyInput instanceof Uint8Array && publicKeyInput.length === 65) {
        return Promise.resolve(_rawPublicKeyToKeyString(publicKeyInput))
      }
      // PEM public key string
      if (typeof publicKeyInput === "string" && publicKeyInput.includes("PUBLIC KEY")) {
        return Promise.resolve("data:key/es256;base64," + _pemToBase64Der(publicKeyInput))
      }
      // PEM private key → derive public on Node
      if (isNode && typeof privateKeyInput === "string" && privateKeyInput.includes("PRIVATE KEY")) {
        return Promise.resolve("data:key/es256;base64," + _derivePublicBase64Der(privateKeyInput))
      }
      // base64 PKCS8 private key → import and export public via SubtleCrypto
      return _importPrivateKey(privateKeyInput).then(function (privKey) {
        // Can't export public from a non-extractable private key — caller must provide publicKeyInput
        throw new Error(
          "OpenClaim: provide publicKeyInput when privateKeyInput is not a PEM string"
        )
      })
    }

    return resolveSignerKeyString().then(function (signerKey) {
      let keys = toArray(existing.keys != null ? existing.keys : claim.key)
      let sigs = normalizeSignatures(existing.signatures != null ? existing.signatures : claim.sig)

      if (!keys.length) keys = [signerKey]
      else if (!keys.includes(signerKey)) keys.push(signerKey)

      const state = buildSortedKeyState(keys, sigs)
      const tmp   = { ...claim, key: state.keys, sig: state.signatures }
      const canon = OpenClaim.canonicalize(tmp)

      return signAsync(privateKeyInput, canon).then(function (sigBytes) {
        const i = state.keys.indexOf(signerKey)
        state.signatures[i] = _toBase64(sigBytes)
        return { ...claim, key: state.keys, sig: state.signatures }
      })
    })
  }

  /**
   * Verify a claim's signatures.
   * Policy: null/omitted = 1 valid required, N = N required, {mode:"all"} = all required.
   */
  static verify(claim, policy) {

    const keys = toArray(claim.key)
    const sigs = normalizeSignatures(claim.sig)

    if (!keys.length) {
      return Promise.reject(new Error("OpenClaim: missing public keys"))
    }

    const state = buildSortedKeyState(keys, sigs)
    const tmp   = { ...claim, key: state.keys, sig: state.signatures }
    const canon = OpenClaim.canonicalize(tmp)

    let valid = 0

    return Promise.all(state.keys.map(function (k, i) {
      const sig = state.signatures[i]
      if (!sig) return Promise.resolve(false)

      return resolveKeyString(k).then(function (keyObj) {
        const keyObjs = Array.isArray(keyObj) ? keyObj : [keyObj]

        return Promise.all(keyObjs.map(function (ko) {
          if (!ko || ko.fmt !== "ES256") return false

          // ko.value is Uint8Array (raw SPKI DER bytes from parseDataKey)
          // Convert to base64 DER string for _importPublicKey
          const b64Der = _toBase64(ko.value)
          const sigBytes = _fromBase64(sig)

          return verifyAsync(b64Der, sigBytes, canon)
        })).then(function (results) {
          if (results.some(Boolean)) valid++
        })
      })
    })).then(function () {
      return valid >= parseVerifyPolicy(policy, state.keys.length).minValid
    })
  }
}
