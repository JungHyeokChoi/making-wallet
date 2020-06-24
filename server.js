import express from "express"
import bodyParser from "body-parser"
import key from "./key.js"
import secp256k1 from "secp256k1"
import ecdsa from "./ecdsa.js"

const port = 3000
const host = "127.0.0.1"

const app = express()

let privateKey

app.use(bodyParser.json())

app.post("/", (_, response) => {
	response.send("Success")
})

app.post("/create_key", (_, response) => {
	const mnemonic = key.createMnemonic()
	const privateKey = key.mnemonicToPrivateKey(mnemonic)
	const address = key.privateKeyToAddress(privateKey)

	
	response.json({
		privateKey : privateKey.toString("hex"),
		address : address,
		mnemonic : mnemonic.toString()
	})
})

app.post("/import_key", (request, response) => {
	try{
		if(!("privateKey" in request.body)){
			throw new Error("'privateKey' is requried")
		}
		const temp = Buffer.from(request.body.privateKey, "hex")
		if(secp256k1.privateKeyVerify(temp) == false) {
			throw new Error("Invaild length of private key")
		}
		privateKey = temp
		const address = key.privateKeyToAddress(privateKey)
		response.json({
			importedAddress : privateKey
		})
	} catch(error){
		console.error(error)
		response.status(500).json({
			error : error.message
		})
		return
	}	
})

app.post("/current_address", (_,response) => {
	try{
		if(!privateKey){
			throw new Error("privateKey is not set")
		}
		const addresss = key.privateKeyToAddress(privateKey)
		response.json({
			currentAddress : address
		})
	} catch (error) {
		console.error(error)
		response.status(500).json({
			error : error.message
		})
	}
})

app.post("/sign", (request, response) => {
	try{
		if(!privateKey){
			throw new Error("privateKey is not set")
		}
		if(!("message" in request.body)){
			throw new Error("'message' is required")
		}
		const signature = ecdsa.sign(request.body.message, privateKey)
		response.json({
			signature : Buffer.from(signature.signature).toString("hex"),
			recid : signature.recid
		})

	} catch(error) {
		console.error(error)
		response.status(500).json({
			error : error.message
		})
	}
})

app.listen(port,host)
