import crypto from "crypto"
import secp256k1 from "secp256k1"
import keccak from "keccak"
import Mnemonic from "bitcore-mnemonic"

/* Making Wallet */


//Create Private Key with crypto.randomBytees()
function createPrivateKey(){
	//let is Reusable constants
	let privateKey
	do {
		privateKey = crypto.randomBytes(32)
	}while(secp256k1.privateKeyVerify(privateKey) == false)

	return privateKey
}

//Create Public Key with secp256k1
function createPublicKey(privateKey, compressed = false){
	return Buffer.from(secp256k1.publicKeyCreate(privateKey, compressed))
}

//Create Address
function createAddress(publicKey) {
	const hash = keccak("keccak256").update(publicKey.slice(1)).digest("hex")	
	
	return "0x" + hash.slice(24)
}

/*
Mixed-case checksum address encoding in Ethereum
https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
*/
function toChecksumAddress (address) {
  address = address.toLowerCase().replace('0x', '')
  var hash = keccak('keccak256').update(address).digest('hex')
  var ret = '0x'

  for (var i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase()
    } else {
      ret += address[i]
    }
  }

  return ret
}

// Making ChecksumAddress from privateKey
function privateKeyToAddress(privateKey){
	const publicKey = createPublicKey(privateKey)
	const address = createAddress(publicKey)

	return toChecksumAddress(address)
}

//Create Mnemonic
function createMnemonic(wordsCount = 12) {
	if(wordsCount < 12 || wordsCount > 24 || wordsCount % 3 !== 0) {
		throw new Error("invalid number of words")
	}

	const entropy = (16 + (wordsCount -12) / 3 * 4) * 8 
	
	return new Mnemonic(entropy)
}

/* Making  Mnemonic from privateKey
   0 = BitCoin,60 = Ethereum
   https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
   ` is what use lower value for same value
*/
function mnemonicToPrivateKey(mnemonic){
	const privateKey = mnemonic.toHDPrivateKey().derive("m/44'/60'/0'/0/0").privateKey

	return Buffer.from(privateKey.toString(), "hex")
}

function test(){
	//Mnemonic of the private key in use
	const mnemonic = new Mnemonic("")
	console.log(mnemonic.toString())

	//Create Mnemonic
	//const mnemonic = createMnemonic(24)
	//console.log(createMnemonic().toString())

	const privateKey = mnemonicToPrivateKey(mnemonic)
	console.log("Private Key : ", privateKey.toString("hex"))

	const address = privateKeyToAddress(privateKey)
	console.log("Address : ", address)
}

export default {
	createPrivateKey,
	createPublicKey,
	createAddress,
	toChecksumAddress,
	privateKeyToAddress,
	createMnemonic,
	mnemonicToPrivateKey,
}
