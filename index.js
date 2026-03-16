// Optional strict canonicalizer:
// npm install json-canonicalize
// https://github.com/cyberphone/json-canonicalization

import crypto from "crypto"

let strictCanonicalize = null

try {
  strictCanonicalize = require("json-canonicalize").canonicalize
} catch {}

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

export class OpenClaim {

  static canonicalize(claim) {

    const obj = { ...claim }
    delete obj.sig

    if (strictCanonicalize) {
      return strictCanonicalize(obj)
    }

    return JSON.stringify(normalize(obj))
  }

  static sign(claim, privateKeyPem) {

    const canon = OpenClaim.canonicalize(claim)

    const hash = crypto
      .createHash("sha256")
      .update(canon)
      .digest()

    const signer = crypto.createSign("SHA256")

    signer.update(hash)
    signer.end()

    const sig = signer
      .sign(privateKeyPem)
      .toString("base64")

    return { ...claim, sig }
  }

  static verify(claim, publicKeyPem) {

    if (!claim.sig) return false

    const canon = OpenClaim.canonicalize(claim)

    const hash = crypto
      .createHash("sha256")
      .update(canon)
      .digest()

    const verifier = crypto.createVerify("SHA256")

    verifier.update(hash)
    verifier.end()

    return verifier.verify(
      publicKeyPem,
      Buffer.from(claim.sig, "base64")
    )
  }
}