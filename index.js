// Optional strict canonicalizer:
// npm install json-canonicalize
// https://github.com/cyberphone/json-canonicalization

import crypto from "crypto"

let strictCanonicalize = null

try {
  strictCanonicalize = require("json-canonicalize").canonicalize
} catch {}

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
  map.set(key, {
    val,
    exp: now() + CACHE_TTL
  })
}

// ---------- EXISTING ----------

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

  if (typeof v === "number") {
    return Number(v).toString()
  }

  return v
}

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
    if (typeof k !== "string") {
      throw new Error("all keys must be strings")
    }
  }
}

function ensureUniqueKeys(keys) {
  const seen = new Set()

  for (const k of keys) {
    if (seen.has(k)) {
      throw new Error("duplicate keys are not allowed")
    }
    seen.add(k)
  }
}

function ensureSortedKeys(keys) {
  const sorted = [...keys].sort()

  for (let i = 0; i < keys.length; i++) {
    if (keys[i] !== sorted[i]) {
      throw new Error("key array must be lexicographically sorted")
    }
  }
}

function derivePublicKeyPem(privateKeyPem) {
  return crypto
    .createPublicKey(privateKeyPem)
    .export({ type: "spki", format: "pem" })
    .toString()
}

function stripPemHeaders(pem) {
  return pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "")
}

function derToPem(base64Der) {
  const body = String(base64Der).replace(/\s+/g, "")
  const lines = body.match(/.{1,64}/g) || []
  return [
    "-----BEGIN PUBLIC KEY-----",
    ...lines,
    "-----END PUBLIC KEY-----"
  ].join("\n")
}

function pemToDer(pem) {
  return stripPemHeaders(String(pem))
}

function isPemPublicKey(v) {
  return typeof v === "string" && v.includes("BEGIN PUBLIC KEY")
}

function toEs256KeyStringFromPublicPem(publicKeyPem) {
  return "es256:" + pemToDer(publicKeyPem)
}

function sha256(bufOrString) {
  return crypto
    .createHash("sha256")
    .update(bufOrString)
    .digest()
}

// ---------- CACHED FETCH ----------

async function fetchJson(url) {

  const cached = getCache(urlCache, url)
  if (cached !== null) return cached

  try {
    const res = await fetch(url)

    if (!res.ok) return null

    const json = await res.json()

    setCache(urlCache, url, json)

    return json

  } catch {
    return null
  }
}

// ---------- CACHED RESOLVE ----------

async function resolveKeyString(keyStr) {

  const cached = getCache(keyCache, keyStr)
  if (cached !== null) return cached

  if (!keyStr || typeof keyStr !== "string") {
    return null
  }

  const idx = keyStr.indexOf(":")
  if (idx <= 0) {
    return null
  }

  const scheme = keyStr.slice(0, idx).toLowerCase()
  const rest = keyStr.slice(idx + 1)

  if (scheme !== "es256" && scheme !== "eip712") {
    return null
  }

  let result = null

  if (rest.startsWith("http://") || rest.startsWith("https://")) {

    const [url, ...path] = rest.split("#")
    const json = await fetchJson(url)

    if (!json) return null

    let current = json

    for (const p of path) {
      if (!p) continue
      current = current?.[p]
    }

    if (typeof current !== "string") {
      return null
    }

    result = { typ: scheme.toUpperCase(), value: current }

  } else {
    result = { typ: scheme.toUpperCase(), value: rest }
  }

  if (result) {
    setCache(keyCache, keyStr, result)
  }

  return result
}

// ---------- KEY PARSE CACHE ----------

function getCachedPublicKey(base64Der) {

  const cached = getCache(pubKeyCache, base64Der)
  if (cached !== null) return cached

  const pem = derToPem(base64Der)

  setCache(pubKeyCache, base64Der, pem)

  return pem
}

// ---------- EXISTING ----------

function buildSortedKeyState(keysInput, signaturesInput) {
  const keys = toArray(keysInput).slice()
  const signatures = normalizeSignatures(signaturesInput)

  ensureStringKeys(keys)
  ensureUniqueKeys(keys)

  if (signatures.length > keys.length) {
    throw new Error("signature array cannot be longer than key array")
  }

  const pairs = keys.map((key, i) => ({
    key,
    sig: i < signatures.length ? signatures[i] : null
  }))

  pairs.sort((a, b) => a.key.localeCompare(b.key))

  const sortedKeys = pairs.map(p => p.key)
  const sortedSignatures = pairs.map(p => p.sig)

  ensureSortedKeys(sortedKeys)

  return {
    keys: sortedKeys,
    signatures: sortedSignatures
  }
}

function parseVerifyPolicy(policy, totalKeys) {
  if (policy == null) return { minValid: 1 }
  if (typeof policy === "number") return { minValid: policy }
  if (policy.mode === "all") return { minValid: totalKeys }
  if (typeof policy.minValid === "number") return { minValid: policy.minValid }
  return { minValid: 1 }
}

export class OpenClaim {

  static canonicalize(claim) {
    const obj = { ...claim }
    delete obj.sig
    if (strictCanonicalize) return strictCanonicalize(obj)
    return JSON.stringify(normalize(obj))
  }

  static sign(claim, privateKeyPem, existing = {}) {

    const signerPublicKeyPem = derivePublicKeyPem(privateKeyPem)
    const signerKey = toEs256KeyStringFromPublicPem(signerPublicKeyPem)

    let keys = existing.keys ?? claim.key
    let signatures = existing.signatures ?? claim.sig

    keys = toArray(keys)
    signatures = normalizeSignatures(signatures)

    if (!keys.length) {
      keys = [signerKey]
    } else if (!keys.includes(signerKey)) {
      keys = [...keys, signerKey]
    }

    let state = buildSortedKeyState(keys, signatures)

    const signerIndex = state.keys.indexOf(signerKey)

    const canon = OpenClaim.canonicalize({
      ...claim,
      key: state.keys,
      sig: state.signatures
    })

    const hash = sha256(canon)

    const signer = crypto.createSign("SHA256")
    signer.update(hash)
    signer.end()

    state.signatures[signerIndex] =
      signer.sign(privateKeyPem).toString("base64")

    return {
      ...claim,
      key: state.keys,
      sig: state.signatures
    }
  }

  static async verify(claim, publicKeyPem, policy = {}) {

    let keys = toArray(claim.key)
    let signatures = normalizeSignatures(claim.sig)

    if (!signatures.length) return false

    if (!keys.length && publicKeyPem) {
      keys = [toEs256KeyStringFromPublicPem(publicKeyPem)]
    }

    const state = buildSortedKeyState(keys, signatures)
    keys = state.keys
    signatures = state.signatures

    const canon = OpenClaim.canonicalize({
      ...claim,
      key: keys,
      sig: signatures
    })

    const hash = sha256(canon)

    let valid = 0

    for (let i = 0; i < keys.length; i++) {

      const sig = signatures[i]
      if (!sig) continue

      const keyObj = await resolveKeyString(keys[i])
      if (!keyObj) continue

      if (keyObj.typ !== "ES256") continue

      const pub = getCachedPublicKey(keyObj.value)
      if (!pub) continue

      const verifier = crypto.createVerify("SHA256")
      verifier.update(hash)
      verifier.end()

      if (verifier.verify(pub, Buffer.from(sig, "base64"))) {
        valid++
      }
    }

    return valid >= parseVerifyPolicy(policy, keys.length).minValid
  }
}