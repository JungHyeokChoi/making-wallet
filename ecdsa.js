import key from "./key.js"
import crypto from "crypto"
import secp256k1 from "secp256k1"
import keccak from "keccak"

// Message must be hashed to 32 Bytes(SHA-256, keccak etc..) for sign
function sign(message, privateKey){
	const hash = crypto.createHash("sha256").update(message).digest()
	
	return secp256k1.ecdsaSign(hash, privateKey)
}

// Return public key of private key
function recover(message, signature){
	const hash = crypto.createHash("sha256").update(message).digest()

	return Buffer.from(secp256k1.ecdsaRecover(signature.signature, signature.recid, hash, false))
}

//Add prefix "0x19" for Signature in Ethereum 
function ethSign(message, privateKey){
	const prefix = "\x19Ethereum signed Message : \n" + message.length
	const buffer = Buffer.from(prefix + message)
	const hash = keccak("keccak256").update(buffer).digest();

	return secp256k1.ecdsaSign(hash, privateKey)
}

function ethRecover(message, signature){
	const prefix = "\x19Ethereum signed Message : \n" + message.length
	const buffer = Buffer.from(prefix + message)
	const hash = keccak("keccak256").update(buffer).digest();
	const publicKey = Buffer.from(secp256k1.ecdsaRecover(signature.signature, signature.recid, hash, false))
	const address = key.createAddress(publicKey)

	return key.toChecksumAddress(address)
}

function testCreateKey(){
	const privateKey = key.createPrivateKey()
	const publicKey = key.createPublicKey(privateKey)
	const message = "Hello World"
	const signature = sign(message, privateKey)
	const recoveredkey = recover(message, signature)

	const address = key.privateKeyToAddress(privateKey)
	const ethSignature = ethSign(message, privateKey)
	const ethRecoveredkey = ethRecover(message, ethSignature)

	console.log("Common\n")
	console.log("Private Key : ", privateKey.toString("hex"))
	console.log("Public key : ", publicKey.toString("hex"))
	console.log("Recovered Key : ", recoveredkey.toString("hex"))
	console.log("Signature : ", signature)
	console.log("Message : ", message)
	console.log("\n")

	console.log("Ethereum\n")
	console.log("Private Key : ", privateKey.toString("hex"))
	console.log("Public key : ", publicKey.toString("hex"))
	console.log("Recovered Key : ", ethRecoveredkey.toString("hex"))
	console.log("Signature : ", ethSignature)
	console.log("Message : ", message)
}

testCreateKey()

