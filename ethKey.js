import Web3 from "web3"

const web3 = new Web3()

const privateKey = "0xC4A466BEF05A58AF7155404611BF7712479B5AC60F3D4F9D118DD7D9164C7CAD"
const account = web3.eth.accounts.privateKeyToAccount(privateKey)

console.log(account)
