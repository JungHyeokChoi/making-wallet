import key from "./key.js"
import crypto from "crypto"
import secp256k1 from "secp256k1"
import keccak from "keccak"
import Web3 from "web3"

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

//Returns to the address upon recovering in Ethereum
function ethRecover(message, signature){
	const prefix = "\x19Ethereum signed Message : \n" + message.length
	const buffer = Buffer.from(prefix + message)
	const hash = keccak("keccak256").update(buffer).digest();
	const publicKey = Buffer.from(secp256k1.ecdsaRecover(signature.signature, signature.recid, hash, false))
	const address = key.createAddress(publicKey)

	return key.toChecksumAddress(address)
}

//Test Create Key
function test(){
	const privateKey = key.createPrivateKey()
	const publicKey = key.createPublicKey(privateKey)
	const message = "Hello World"
	const signature = sign(message, privateKey)
	const recoveredkey = recover(message, signature)

	const address = key.privateKeyToAddress(privateKey)
	const ethSignature = ethSign(message, privateKey)
	const ethRecoveredkey = ethRecover(message, ethSignature)

	const web3 = new Web3()
	const account = web3.eth.accounts.privateKeyToAccount("0x" + privateKey.toString("hex"))

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
	console.log("\n")

	console.log("Compare function make by self with ethereum\n")
	console.log("Account Address : " ,account.address)
	console.log("Account Private Key : ", account.privateKey)
	console.log("Account Signature : ", web3.eth.accounts.sign(message, account.privateKey))
	console.log("Account Recovered Key : ", web3.eth.accounts.recover(message, web3.eth.accounts.sign(message, account.privateKey).signature))
}

export default {
	sign,
	recover,
	ethSign,
	ethRecover
}

