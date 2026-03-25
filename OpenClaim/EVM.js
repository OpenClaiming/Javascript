/**
 * Q.OpenClaim.EVM — EIP-712 Payment and Authorization extensions for OCP.
 *
 * Works in browsers (SubtleCrypto + dynamic import) and Node.js.
 * No Buffer, no top-level require().
 *
 * Dependencies — all already in Q:
 *   sha3.js      — keccak_256  (Q ships this at {{Q}}/src/js/crypto/sha3.js)
 *   eip712.js    — hashTypedData (Q ships this at {{Q}}/src/js/crypto/eip712.js)
 *   secp256k1.js — @noble/secp256k1 v3 (Q ships this at {{Q}}/src/js/crypto/secp256k1.js)
 *
 * PHP parity:
 *   keccak_256      <->  Crypto\Keccak::hash($data, 256, true)
 *   eip712.js       <->  Q_Crypto_EIP712::hashTypedData()
 *   noble secp256k1 <->  Crypto\Signature::recoverPublicKey() + Q_ECC
 *
 * @class Q.OpenClaim.EVM
 * @static
 */

// ---------- ENV ----------

const _isNode = typeof process !== "undefined" && !!process.versions?.node

// ---------- BINARY HELPERS (Uint8Array only, no Buffer) ----------

function _toU8(v) {
    if (v instanceof Uint8Array) return v
    if (v instanceof ArrayBuffer) return new Uint8Array(v)
    if (_isNode && typeof Buffer !== "undefined" && Buffer.isBuffer(v)) {
        return new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
    }
    throw new Error("Q.OpenClaim.EVM: unsupported binary type: " + typeof v)
}

function _hexToU8(hex) {
    hex = String(hex).replace(/^0x/i, "")
    if (hex.length % 2) throw new Error("Q.OpenClaim.EVM: odd-length hex")
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    }
    return out
}

function _u8ToHex(bytes) {
    bytes = _toU8(bytes)
    let hex = ""
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0")
    return hex
}

function _concat() {
    const parts = Array.prototype.slice.call(arguments).map(_toU8)
    let len = 0
    parts.forEach(function (p) { len += p.length })
    const out = new Uint8Array(len)
    let pos = 0
    parts.forEach(function (p) { out.set(p, pos); pos += p.length })
    return out
}

function _padLeft32(bytes) {
    bytes = _toU8(bytes)
    if (bytes.length > 32) throw new Error("Q.OpenClaim.EVM: value exceeds 32 bytes")
    const out = new Uint8Array(32)
    out.set(bytes, 32 - bytes.length)
    return out
}

function _encodeAddress(addr) {
    const hex = String(addr).replace(/^0x/i, "").toLowerCase().padStart(40, "0")
    return _padLeft32(_hexToU8(hex))
}

// ---------- LAZY MODULE LOADING ----------
// Q ships sha3, eip712, secp256k1 at known paths.
// Browsers load via Q.url(); Node uses require() fallback.

function _qUrl(path) {
    return typeof Q !== "undefined" && Q.url
        ? Q.url(path)
        : path
}

let _sha3Mod    = null
let _eip712Mod  = null
let _secpMod    = null

async function _getSha3() {
    if (_sha3Mod) return _sha3Mod
    if (_isNode) { try { _sha3Mod = require("./sha3");    return _sha3Mod } catch {} }
    _sha3Mod = await import(_qUrl("{{Q}}/src/js/crypto/sha3.js"))
    return _sha3Mod
}

async function _getEIP712() {
    if (_eip712Mod) return _eip712Mod
    if (_isNode) { try { _eip712Mod = require("./eip712"); return _eip712Mod } catch {} }
    _eip712Mod = await import(_qUrl("{{Q}}/src/js/crypto/eip712.js"))
    return _eip712Mod
}

async function _getSecp() {
    if (_secpMod) return _secpMod
    if (_isNode) { try { _secpMod = require("@noble/secp256k1"); } catch {} }
    if (!_secpMod) {
        _secpMod = await import(_qUrl("{{Q}}/src/js/crypto/secp256k1.js"))
    }
    // noble v3 needs hmacSha256Sync for RFC 6979 deterministic k on Node
    if (_isNode && !_secpMod.secp256k1.hmacSha256Sync) {
        const nc = require("crypto")
        _secpMod.secp256k1.hmacSha256Sync = function (key) {
            const args = Array.prototype.slice.call(arguments, 1)
            const hmac = nc.createHmac("sha256", _toU8(key))
            args.forEach(function (a) { hmac.update(_toU8(a)) })
            return new Uint8Array(hmac.digest())
        }
    }
    return _secpMod
}

function _keccak(sha3Mod) {
    return function (bytes) {
        return new Uint8Array(sha3Mod.keccak_256(_toU8(bytes)))
    }
}

// ---------- HELPERS ----------

function _toArray(v)   { return v == null ? [] : Array.isArray(v) ? v : [v] }
function _lower(v)     { return String(v).toLowerCase() }

function _readField(claim, key, fallback) {
    if (claim[key] != null)                  return claim[key]
    if (claim.stm && claim.stm[key] != null) return claim.stm[key]
    return fallback !== undefined ? fallback : null
}

// ---------- TYPE DEFINITIONS ----------

const PAYMENT_TYPES = {
    EIP712Domain: [
        { name: "name",              type: "string"  },
        { name: "version",           type: "string"  },
        { name: "chainId",           type: "uint256" },
        { name: "verifyingContract", type: "address" }
    ],
    Payment: [
        { name: "payer",          type: "address" },
        { name: "token",          type: "address" },
        { name: "recipientsHash", type: "bytes32" },
        { name: "max",            type: "uint256" },
        { name: "line",           type: "uint256" },
        { name: "nbf",            type: "uint256" },
        { name: "exp",            type: "uint256" }
    ]
}

const AUTHORIZATION_TYPES = {
    EIP712Domain: [
        { name: "name",              type: "string"  },
        { name: "version",           type: "string"  },
        { name: "chainId",           type: "uint256" },
        { name: "verifyingContract", type: "address" }
    ],
    Authorization: [
        { name: "authority",       type: "address" },
        { name: "subject",         type: "address" },
        { name: "actorsHash",      type: "bytes32" },
        { name: "rolesHash",       type: "bytes32" },
        { name: "actionsHash",     type: "bytes32" },
        { name: "constraintsHash", type: "bytes32" },
        { name: "contextsHash",    type: "bytes32" },
        { name: "nbf",             type: "uint256" },
        { name: "exp",             type: "uint256" }
    ]
}

const CONSTRAINT_TYPES = {
    Constraint: [
        { name: "key",   type: "string" },
        { name: "op",    type: "string" },
        { name: "value", type: "string" }
    ]
}

const CONTEXT_TYPES = {
    Context: [
        { name: "type",  type: "string" },
        { name: "value", type: "string" }
    ]
}

// ---------- HASH HELPERS (keccak injected, no global state) ----------

function _hashRecipients(keccak, recipients) {
    const addrs = _toArray(recipients)
    if (!addrs.length) return keccak(new Uint8Array(0))
    return keccak(_concat.apply(null, addrs.map(_encodeAddress)))
}

function _hashActors(keccak, actors) {
    const addrs = _toArray(actors)
    if (!addrs.length) return keccak(new Uint8Array(0))
    return keccak(_concat.apply(null, addrs.map(_encodeAddress)))
}

function _hashStringArray(keccak, strings) {
    const arr = _toArray(strings)
    if (!arr.length) return keccak(new Uint8Array(0))
    const hashes = arr.map(function (s) { return keccak(new TextEncoder().encode(String(s))) })
    return keccak(_concat.apply(null, hashes))
}

function _hashConstraints(keccak, constraints) {
    const arr = _toArray(constraints)
    if (!arr.length) return keccak(new Uint8Array(0))
    const th = keccak(new TextEncoder().encode("Constraint(string key,string op,string value)"))
    const hashes = arr.map(function (c) {
        return keccak(_concat(
            th,
            keccak(new TextEncoder().encode(c.key   || "")),
            keccak(new TextEncoder().encode(c.op    || "")),
            keccak(new TextEncoder().encode(c.value || ""))
        ))
    })
    return keccak(_concat.apply(null, hashes))
}

function _hashContexts(keccak, contexts) {
    const arr = _toArray(contexts)
    if (!arr.length) return keccak(new Uint8Array(0))
    const th = keccak(new TextEncoder().encode("Context(string type,string value)"))
    const hashes = arr.map(function (ctx) {
        return keccak(_concat(
            th,
            keccak(new TextEncoder().encode(ctx.type  || ctx.fmt || "")),
            keccak(new TextEncoder().encode(ctx.value || ""))
        ))
    })
    return keccak(_concat.apply(null, hashes))
}

// ---------- EXTENSION DETECTION ----------

function detectExtension(claim) {
    const payer = _readField(claim, "payer")
    const token = _readField(claim, "token")
    const line  = _readField(claim, "line")
    if (payer && token != null && line != null) return "payment"

    const authority = _readField(claim, "authority")
    const subject   = _readField(claim, "subject")
    if (authority && subject) return "authorization"

    return null
}

// ---------- PAYLOAD BUILDERS ----------

function _buildPaymentPayload(claim, keccak) {
    const recipients = _toArray(_readField(claim, "recipients", []))
    return {
        primaryType: "Payment",
        domain: {
            name:              "OpenClaiming.payments",
            version:           "1",
            chainId:           claim.chainId,
            verifyingContract: claim.contract
        },
        types: PAYMENT_TYPES,
        value: {
            payer:          _lower(_readField(claim, "payer", "")),
            token:          _lower(_readField(claim, "token", "")),
            recipientsHash: _hashRecipients(keccak, recipients),
            max:            BigInt(_readField(claim, "max",  0) || 0),
            line:           BigInt(_readField(claim, "line", 0) || 0),
            nbf:            BigInt(_readField(claim, "nbf",  0) || 0),
            exp:            BigInt(_readField(claim, "exp",  0) || 0)
        },
        data: { recipients }
    }
}

function _buildAuthorizationPayload(claim, keccak) {
    const actors      = _toArray(_readField(claim, "actors",      []))
    const roles       = _toArray(_readField(claim, "roles",       []))
    const actions     = _toArray(_readField(claim, "actions",     []))
    const constraints = _toArray(_readField(claim, "constraints", []))
    const contexts    = _toArray(_readField(claim, "contexts",    []))
    return {
        primaryType: "Authorization",
        domain: {
            name:              "OpenClaiming.authorizations",
            version:           "1",
            chainId:           claim.chainId,
            verifyingContract: claim.contract
        },
        types: AUTHORIZATION_TYPES,
        value: {
            authority:       _lower(_readField(claim, "authority", "")),
            subject:         _lower(_readField(claim, "subject",   "")),
            actorsHash:      _hashActors(keccak, actors),
            rolesHash:       _hashStringArray(keccak, roles),
            actionsHash:     _hashStringArray(keccak, actions),
            constraintsHash: _hashConstraints(keccak, constraints),
            contextsHash:    _hashContexts(keccak, contexts),
            nbf:             BigInt(_readField(claim, "nbf", 0) || 0),
            exp:             BigInt(_readField(claim, "exp", 0) || 0)
        },
        data: { actors, roles, actions, constraints, contexts }
    }
}

// ---------- hashTypedData (async, browser + node) ----------

/**
 * Compute the EIP-712 typed-data digest for an OpenClaim EVM claim.
 * Returns a 32-byte Uint8Array.
 * Byte-identical to PHP Q_OpenClaim_EVM::hashTypedData().
 *
 * @param {Object} claim
 * @return {Promise<Uint8Array>} 32-byte digest
 */
async function hashTypedData(claim) {
    const [sha3Mod, eip712Mod] = await Promise.all([_getSha3(), _getEIP712()])
    const keccak = _keccak(sha3Mod)

    const ext = detectExtension(claim)
    let payload
    if (ext === "payment")            payload = _buildPaymentPayload(claim, keccak)
    else if (ext === "authorization") payload = _buildAuthorizationPayload(claim, keccak)
    else throw new Error("Q.OpenClaim.EVM: unable to detect claim extension")

    // eip712.js hashTypedData uses its own internal keccak (from sha3.js import)
    // so we don't pass keccak — it's self-contained
    return new Uint8Array(eip712Mod.hashTypedData(
        payload.domain,
        payload.primaryType,
        payload.value,
        payload.types
    ))
}

// ---------- SIGN ----------

/**
 * Sign an OpenClaim EVM claim using a secp256k1 private key.
 * Returns Ethereum-style 65-byte r||s||v signature (0x-prefixed hex).
 * v = 27 + recovery (Ethereum convention).
 *
 * Uses noble secp256k1 v3. For production use wallets sign via MetaMask.
 *
 * @param {Object}     claim
 * @param {Uint8Array} privateKeyBytes  32-byte secp256k1 scalar
 * @return {Promise<String>}  "0x" + 130-char hex
 */
async function sign(claim, privateKeyBytes) {
    const [digest, secpMod] = await Promise.all([hashTypedData(claim), _getSecp()])
    privateKeyBytes = _toU8(privateKeyBytes)

    // noble v3: .sign() returns Signature object
    const sig     = secpMod.secp256k1.sign(digest, privateKeyBytes, { lowS: true })
    const compact = sig.toCompactRawBytes() // 64 bytes r||s
    const ethSig  = new Uint8Array(65)
    ethSig.set(compact, 0)
    ethSig[64] = 27 + sig.recovery  // v = 27 or 28

    return "0x" + _u8ToHex(ethSig)
}

// ---------- RECOVER SIGNER ----------

/**
 * Recover the Ethereum signer address from a claim + signature.
 *
 * Uses noble secp256k1 v3 — works in browser and Node without ECDH.
 * noble's .toRawBytes(false) gives the uncompressed 65-byte point directly.
 *
 * @param {Object} claim
 * @param {String} signature  "0x" + 130-char hex (r||s||v)
 * @return {Promise<String>}  "0x" + lowercase 40-char Ethereum address
 */
async function recoverSigner(claim, signature) {
    const [digest, sha3Mod, secpMod] = await Promise.all([
        hashTypedData(claim),
        _getSha3(),
        _getSecp()
    ])
    const keccak = _keccak(sha3Mod)

    const sigHex = String(signature).replace(/^0x/i, "")
    if (sigHex.length !== 130) {
        throw new Error("Q.OpenClaim.EVM: invalid signature length (expected 65 bytes, got " +
            (sigHex.length / 2) + ")")
    }

    const compact  = _hexToU8(sigHex.slice(0, 128))   // 64 bytes r||s
    const v        = parseInt(sigHex.slice(128, 130), 16)
    const recovery = (v === 27 || v === 28) ? v - 27 : v

    // noble v3: fromCompact → addRecoveryBit → recoverPublicKey
    const sigObj         = secpMod.secp256k1.Signature.fromCompact(compact).addRecoveryBit(recovery)
    const pubUncompressed = sigObj.recoverPublicKey(digest).toRawBytes(false) // 65 bytes: 04||X||Y

    // Verify the recovered key signs this digest
    if (!secpMod.secp256k1.verify(secpMod.secp256k1.Signature.fromCompact(compact), digest, pubUncompressed)) {
        throw new Error("Q.OpenClaim.EVM: signature verification failed after recovery")
    }

    // Ethereum address = last 20 bytes of keccak256(pub[1:])  (drop the 04 prefix)
    const addrBytes = keccak(pubUncompressed.slice(1)).slice(-20)
    return "0x" + _u8ToHex(addrBytes)
}

// ---------- VERIFY ----------

/**
 * Verify a claim signature and optionally check against an expected address.
 * Returns the recovered address string if no expectedAddress given,
 * or a boolean if expectedAddress is provided.
 * Returns false on any error.
 *
 * @param {Object} claim
 * @param {String} signature
 * @param {String} [expectedAddress]
 * @return {Promise<String|Boolean>}
 */
async function verify(claim, signature, expectedAddress) {
    try {
        const recovered = await recoverSigner(claim, signature)
        if (expectedAddress) return recovered.toLowerCase() === _lower(expectedAddress)
        return recovered
    } catch (e) {
        return false
    }
}

async function verifyPayment(claim, signature, expectedAddress) {
    return verify(claim, signature, expectedAddress)
}

async function verifyAuthorization(claim, signature, expectedAddress) {
    return verify(claim, signature, expectedAddress)
}

// ---------- EXPORT ----------

export {
    // Type definitions (for callers that need to reference the schemas)
    PAYMENT_TYPES,
    AUTHORIZATION_TYPES,
    CONSTRAINT_TYPES,
    CONTEXT_TYPES,

    // Detection
    detectExtension,

    // Hashing
    hashTypedData,

    // Signing (server-side / test — in production wallets sign)
    sign,

    // Verification
    recoverSigner,
    verify,
    verifyPayment,
    verifyAuthorization
}
