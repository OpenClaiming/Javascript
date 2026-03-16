const crypto = require("crypto");

class OpenClaim {

	static canonicalize(obj) {
		const clone = JSON.parse(JSON.stringify(obj));
		delete clone.sig;
		return JSON.stringify(clone, Object.keys(clone).sort());
	}

	static sign(claim, privateKey) {
		const canon = this.canonicalize(claim);
		const sign = crypto.createSign("SHA256");
		sign.update(canon);
		const signature = sign.sign(privateKey, "base64");
		claim.sig = signature;
		return claim;
	}

	static verify(claim, publicKey) {
		const sig = claim.sig;
		if (!sig) return false;
		const canon = this.canonicalize(claim);
		const verify = crypto.createVerify("SHA256");
		verify.update(canon);
		return verify.verify(publicKey, sig, "base64");
	}

}

module.exports = OpenClaim;