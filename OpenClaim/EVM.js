// OpenClaim/EVM.js
// Requires:
// - OpenClaim already loaded on globalThis
// - ethers available on globalThis

(function () {

	if (typeof globalThis.OpenClaim === "undefined") {
		throw new Error("OpenClaim must be loaded before OpenClaim/EVM.js")
	}

	function requireEthers() {
		if (typeof globalThis.ethers === "undefined") {
			throw new Error("ethers.js must be loaded before OpenClaim/EVM.js")
		}
		return globalThis.ethers
	}

	function requireObject(value, name) {
		if (!value || typeof value !== "object") {
			throw new Error(name + " must be an object")
		}
	}

	function requireChainId(value) {
		if (value == null || value === "") {
			throw new Error("claim.chainId is required for EIP712")
		}
	}

	function requireAddress(value, name) {
		const e = requireEthers()
		if (!e.isAddress(value)) {
			throw new Error(name + " must be a valid address")
		}
	}

	function requireVerifyingContract(value) {
		if (!value) {
			throw new Error("claim.contract is required for EIP712")
		}
		requireAddress(value, "claim.contract")
	}

	function toArray(value) {
		if (value == null) return []
		return Array.isArray(value) ? value : [value]
	}

	function lower(value) {
		return String(value).toLowerCase()
	}

	function coder() {
		return requireEthers().AbiCoder.defaultAbiCoder()
	}

	function keccak256Bytes(value) {
		const e = requireEthers()
		return e.keccak256(value)
	}

	function keccak256Utf8(value) {
		const e = requireEthers()
		return e.keccak256(e.toUtf8Bytes(String(value)))
	}

	function keccak256Abi(types, values) {
		return keccak256Bytes(coder().encode(types, values))
	}

	function readField(claim, key, fallback) {
		if (claim && claim[key] != null) return claim[key]
		if (claim && claim.stm && claim.stm[key] != null) return claim.stm[key]
		return fallback
	}

	function readAddress(claim, key) {
		return readField(claim, key, null)
	}

	function readUint(claim, key, fallback) {
		const value = readField(claim, key, null)
		return value == null ? fallback : value
	}

	const PAYMENT_TYPEHASH =
		keccak256Utf8("Payment(address payer,address token,bytes32 recipientsHash,uint256 max,uint256 line,uint256 nbf,uint256 exp)")

	const AUTHORIZATION_TYPEHASH =
		keccak256Utf8("Authorization(address authority,address subject,bytes32 actorsHash,bytes32 rolesHash,bytes32 actionsHash,bytes32 constraintsHash,bytes32 contextsHash,uint256 nbf,uint256 exp)")

	const AUTHORIZATION_CONSTRAINT_TYPEHASH =
		keccak256Utf8("Constraint(string key,string op,string value)")

	const AUTHORIZATION_CONTEXT_TYPEHASH =
		keccak256Utf8("Context(string type,string value)")

	function hashBytes32Array(values) {
		return keccak256Abi(["bytes32[]"], [values])
	}

	function hashStringArray(values) {
		const hashes = toArray(values).map(function (value) {
			return keccak256Utf8(value)
		})
		return hashBytes32Array(hashes)
	}

	function hashRecipients(recipients) {
		return keccak256Abi(["address[]"], [toArray(recipients)])
	}

	function hashActors(actors) {
		return keccak256Abi(["address[]"], [toArray(actors)])
	}

	function hashConstraint(constraint) {
		requireObject(constraint, "constraint")

		return keccak256Abi(
			["bytes32", "bytes32", "bytes32", "bytes32"],
			[
				AUTHORIZATION_CONSTRAINT_TYPEHASH,
				keccak256Utf8(constraint.key || ""),
				keccak256Utf8(constraint.op || ""),
				keccak256Utf8(constraint.value || "")
			]
		)
	}

	function hashConstraints(constraints) {
		const hashes = toArray(constraints).map(function (constraint) {
			return hashConstraint(constraint)
		})
		return hashBytes32Array(hashes)
	}

	function hashContext(context) {
		requireObject(context, "context")

		return keccak256Abi(
			["bytes32", "bytes32", "bytes32"],
			[
				AUTHORIZATION_CONTEXT_TYPEHASH,
				keccak256Utf8(context.fmt || ""),
				keccak256Utf8(context.value || "")
			]
		)
	}

	function hashContexts(contexts) {
		const hashes = toArray(contexts).map(function (context) {
			return hashContext(context)
		})
		return hashBytes32Array(hashes)
	}

	function detectExtension(claim) {
		const payer = readAddress(claim, "payer")
		const token = readAddress(claim, "token")
		const line = readField(claim, "line", null)
		if (payer && token != null && line != null) {
			return "payment"
		}

		const authority = readAddress(claim, "authority")
		const subject = readAddress(claim, "subject")
		if (authority && subject) {
			return "authorization"
		}

		return null
	}

	const paymentTypes = {
		Payment: [
			{ name: "payer", type: "address" },
			{ name: "token", type: "address" },
			{ name: "recipientsHash", type: "bytes32" },
			{ name: "max", type: "uint256" },
			{ name: "line", type: "uint256" },
			{ name: "nbf", type: "uint256" },
			{ name: "exp", type: "uint256" }
		]
	}

	const authorizationTypes = {
		Authorization: [
			{ name: "authority", type: "address" },
			{ name: "subject", type: "address" },
			{ name: "actorsHash", type: "bytes32" },
			{ name: "rolesHash", type: "bytes32" },
			{ name: "actionsHash", type: "bytes32" },
			{ name: "constraintsHash", type: "bytes32" },
			{ name: "contextsHash", type: "bytes32" },
			{ name: "nbf", type: "uint256" },
			{ name: "exp", type: "uint256" }
		]
	}

	const EVM = {}

	EVM.PAYMENT_TYPEHASH = PAYMENT_TYPEHASH
	EVM.AUTHORIZATION_TYPEHASH = AUTHORIZATION_TYPEHASH
	EVM.AUTHORIZATION_CONSTRAINT_TYPEHASH = AUTHORIZATION_CONSTRAINT_TYPEHASH
	EVM.AUTHORIZATION_CONTEXT_TYPEHASH = AUTHORIZATION_CONTEXT_TYPEHASH

	EVM.paymentTypes = paymentTypes
	EVM.authorizationTypes = authorizationTypes

	EVM.hashRecipients = hashRecipients
	EVM.hashActors = hashActors
	EVM.hashStringArray = hashStringArray
	EVM.hashConstraint = hashConstraint
	EVM.hashConstraints = hashConstraints
	EVM.hashContext = hashContext
	EVM.hashContexts = hashContexts
	EVM.detectExtension = detectExtension

	EVM.toPaymentPayload = function (claim) {
		requireObject(claim, "claim")
		requireChainId(claim.chainId)
		requireVerifyingContract(claim.contract)

		const payer = readAddress(claim, "payer")
		const token = readAddress(claim, "token")
		const recipients = toArray(readField(claim, "recipients", []))

		requireAddress(payer, "claim.payer")
		requireAddress(token, "claim.token")

		return {
			primaryType: "Payment",
			domain: {
				name: "OpenClaiming.payments",
				version: "1",
				chainId: claim.chainId,
				verifyingContract: claim.contract
			},
			types: paymentTypes,
			value: {
				payer: payer,
				token: token,
				recipientsHash: hashRecipients(recipients),
				max: readUint(claim, "max", 0),
				line: readUint(claim, "line", 0),
				nbf: readUint(claim, "nbf", 0),
				exp: readUint(claim, "exp", 0)
			},
			data: {
				recipients: recipients
			}
		}
	}

	EVM.toAuthorizationPayload = function (claim) {
		requireObject(claim, "claim")
		requireChainId(claim.chainId)
		requireVerifyingContract(claim.contract)

		const authority = readAddress(claim, "authority")
		const subject = readAddress(claim, "subject")
		const actors = toArray(readField(claim, "actors", []))
		const roles = toArray(readField(claim, "roles", []))
		const actions = toArray(readField(claim, "actions", []))
		const constraints = toArray(readField(claim, "constraints", []))
		const contexts = toArray(readField(claim, "contexts", []))

		requireAddress(authority, "claim.authority")
		requireAddress(subject, "claim.subject")

		return {
			primaryType: "Authorization",
			domain: {
				name: "OpenClaiming.authorizations",
				version: "1",
				chainId: claim.chainId,
				verifyingContract: claim.contract
			},
			types: authorizationTypes,
			value: {
				authority: authority,
				subject: subject,
				actorsHash: hashActors(actors),
				rolesHash: hashStringArray(roles),
				actionsHash: hashStringArray(actions),
				constraintsHash: hashConstraints(constraints),
				contextsHash: hashContexts(contexts),
				nbf: readUint(claim, "nbf", 0),
				exp: readUint(claim, "exp", 0)
			},
			data: {
				actors: actors,
				roles: roles,
				actions: actions,
				constraints: constraints,
				contexts: contexts
			}
		}
	}

	EVM.toPayload = function (claim) {
		const ext = detectExtension(claim)

		if (ext === "payment") {
			return EVM.toPaymentPayload(claim)
		}
		if (ext === "authorization") {
			return EVM.toAuthorizationPayload(claim)
		}

		throw new Error("Unable to detect EIP712 claim extension")
	}

	EVM.signPayment = async function (claim, signer) {
		const payload = EVM.toPaymentPayload(claim)

		return await signer.signTypedData(
			payload.domain,
			payload.types,
			payload.value
		)
	}

	EVM.signAuthorization = async function (claim, signer) {
		const payload = EVM.toAuthorizationPayload(claim)

		return await signer.signTypedData(
			payload.domain,
			payload.types,
			payload.value
		)
	}

	EVM.sign = async function (claim, signer) {
		const ext = detectExtension(claim)

		if (ext === "payment") {
			return await EVM.signPayment(claim, signer)
		}
		if (ext === "authorization") {
			return await EVM.signAuthorization(claim, signer)
		}

		throw new Error("Unable to detect EIP712 claim type")
	}

	EVM.verifyPayment = function (claim, signature, expectedAddress) {
		const e = requireEthers()
		const payload = EVM.toPaymentPayload(claim)

		const recovered = e.verifyTypedData(
			payload.domain,
			payload.types,
			payload.value,
			signature
		)

		return lower(recovered) === lower(expectedAddress)
	}

	EVM.verifyAuthorization = function (claim, signature, expectedAddress) {
		const e = requireEthers()
		const payload = EVM.toAuthorizationPayload(claim)

		const recovered = e.verifyTypedData(
			payload.domain,
			payload.types,
			payload.value,
			signature
		)

		return lower(recovered) === lower(expectedAddress)
	}

	EVM.verify = function (claim, signature, expectedAddress) {
		const ext = detectExtension(claim)

		if (ext === "payment") {
			return EVM.verifyPayment(claim, signature, expectedAddress)
		}
		if (ext === "authorization") {
			return EVM.verifyAuthorization(claim, signature, expectedAddress)
		}

		return false
	}

	EVM.verifyKey = function (claim, keyObj, signature) {
		if (!keyObj || keyObj.fmt !== "EIP712") return false
		return EVM.verify(claim, signature, keyObj.value)
	}

	globalThis.OpenClaim.EVM = EVM

})()