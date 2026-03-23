// Optional strict canonicalizer:
// npm install json-canonicalize
// https://github.com/cyberphone/json-canonicalization

import crypto from "crypto"

let strictCanonicalize = null

try {
  strictCanonicalize = require("json-canonicalize").canonicalize
} catch {}

// ---------- ENV DETECTION ----------

const isNode = typeof process !== "undefined" && process.versions?.node
const subtle = (typeof crypto !== "undefined" && crypto.webcrypto?.subtle)
  || (typeof window !== "undefined" && window.crypto?.subtle)

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
      throw new Error("OpenClaim: all keys must be strings")
    }
  }
}

function ensureUniqueKeys(keys) {
  const seen = new Set()

  for (const k of keys) {
    if (seen.has(k)) {
      throw new Error("OpenClaim: duplicate keys are not allowed")
    }
    seen.add(k)
  }
}

function ensureSortedKeys(keys) {
  const sorted = [...keys].sort()

  for (let i = 0; i < keys.length; i++) {
    if (keys[i] !== sorted[i]) {
      throw new Error("OpenClaim: key array must be lexicographically sorted")
    }
  }
}

function derivePublicKeyPem(privateKeyPem) {
  if (!isNode) {
    throw new Error("OpenClaim: derivePublicKeyPem requires Node")
  }
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
  return "data:key/es256;base64," + pemToDer(publicKeyPem)
}

// ---------- HASH ----------

function sha256(bufOrString) {

  if (isNode) {
    return Promise.resolve(
      crypto.createHash("sha256").update(bufOrString).digest()
    )
  }

  return subtle.digest("SHA-256",
    typeof bufOrString === "string"
      ? new TextEncoder().encode(bufOrString)
      : bufOrString
  ).then(buf => new Uint8Array(buf))
}

// ---------- CRYPTO ----------

function signAsync(privateKeyPem, hash) {

  if (isNode) {
    return Promise.resolve(
      crypto.sign(null, hash, privateKeyPem)
    )
  }

  return importPrivateKey(privateKeyPem).then(key =>
    subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      hash
    )
  ).then(sig => new Uint8Array(sig))
}

function verifyAsync(publicKeyPem, sig, hash) {

  if (isNode) {
    return Promise.resolve(
      crypto.verify(null, hash, publicKeyPem, sig)
    )
  }

  return importPublicKey(publicKeyPem).then(key =>
    subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sig,
      hash
    )
  )
}

// ---------- WEBCRYPTO IMPORT ----------

function importPublicKey(pem) {
  const der = base64ToArrayBuffer(pemToDer(pem))
  return subtle.importKey("spki", der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  )
}

function importPrivateKey(pem) {
  const der = base64ToArrayBuffer(
    pem.replace(/-----.*PRIVATE KEY-----/g, "").replace(/\s+/g, "")
  )
  return subtle.importKey("pkcs8", der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  )
}

function base64ToArrayBuffer(b64) {
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i)
  }
  return bytes.buffer
}

// ---------- PUBLIC KEY CACHE ----------

function getCachedPublicKey(base64Der) {

  const cached = getCache(pubKeyCache, base64Der)
  if (cached !== null) return cached

  const pem = derToPem(base64Der)

  setCache(pubKeyCache, base64Der, pem)

  return pem
}

// ---------- DATA KEY PARSER ----------

function parseDataKey(keyStr) {

  if (!keyStr.startsWith("data:key/")) return null

  const idx = keyStr.indexOf(",")
  if (idx < 0) return null

  const meta = keyStr.slice(5, idx)
  const data = keyStr.slice(idx + 1)

  const [typePart, ...params] = meta.split(";")
  const type = typePart.replace("key/", "").toUpperCase()

  let encoding = "raw"

  for (const p of params) {
    if (p === "base64") encoding = "base64"
    if (p === "base64url") encoding = "base64url"
  }

  let value = data

  if (encoding === "base64") {
    value = Buffer.from(data, "base64")
  }

  if (encoding === "base64url") {
    const pad = data.length % 4
    const b64 = data.replace(/-/g, "+").replace(/_/g, "/") +
      (pad ? "=".repeat(4 - pad) : "")
    value = Buffer.from(b64, "base64")
  }

  return { fmt: type, value }
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

      path.forEach(p => {
        if (p) current = current?.[p]
      })

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

// ---------- EXISTING ----------

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

// ---------- MAIN ----------

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

    let keys = toArray(existing.keys ?? claim.key)
    let sigs = normalizeSignatures(existing.signatures ?? claim.sig)

    if (!keys.length) keys = [signerKey]
    else if (!keys.includes(signerKey)) keys.push(signerKey)

    const state = buildSortedKeyState(keys, sigs)

    const tmp = {
      ...claim,
      key: state.keys,
      sig: state.signatures
    }

    const canon = OpenClaim.canonicalize(tmp)

    return sha256(canon)
      .then(hash => signAsync(privateKeyPem, hash))
      .then(sig => {

        const i = state.keys.indexOf(signerKey)
        state.signatures[i] = Buffer.from(sig).toString("base64")

        return {
          ...claim,
          key: state.keys,
          sig: state.signatures
        }
      })
  }

  static verify(claim, policy = {}) {

    let keys = toArray(claim.key)
    let sigs = normalizeSignatures(claim.sig)

    if (!keys.length) {
      return Promise.reject(
        new Error("OpenClaim: missing public keys")
      )
    }

    const state = buildSortedKeyState(keys, sigs)

    const tmp = {
      ...claim,
      key: state.keys,
      sig: state.signatures
    }

    const canon = OpenClaim.canonicalize(tmp)

    return sha256(canon).then(hash => {

      let valid = 0

      return Promise.all(state.keys.map((k, i) => {

        const sig = state.signatures[i]
        if (!sig) return Promise.resolve(false)

        return resolveKeyString(k).then(keyObj => {

          const keyObjs = Array.isArray(keyObj) ? keyObj : [keyObj]

          return Promise.all(keyObjs.map(ko => {

            if (!ko || ko.fmt !== "ES256") return false

            const der = Buffer.isBuffer(ko.value)
              ? ko.value.toString("base64")
              : String(ko.value)

            const pub = getCachedPublicKey(der)

            return verifyAsync(pub, Buffer.from(sig, "base64"), hash)

          })).then(results => {
            if (results.some(Boolean)) valid++
          })
        })
      })).then(() =>
        valid >= parseVerifyPolicy(policy, state.keys.length).minValid
      )
    })
  }
}