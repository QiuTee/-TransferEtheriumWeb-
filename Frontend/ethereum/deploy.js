const HDWalletProvider = require("@truffle/hdwallet-provider");
const { Web3 } = require("web3");
const fs = require("fs-extra");
const compiledFactory = require("../../Backend/backend_project/backend_app/blockchain/build/TransactionFactory.json");
const provider = new HDWalletProvider(
  "party rather gain total fly marine grid comic glow cat stem couple",
  "https://sepolia.infura.io/v3/181747e4369542ea9234457068381e8b"
);
const web3 = new Web3(provider);

const deploy = async () => {
  const accounts = await web3.eth.getAccounts();

  console.log("Attempting to deploy from account", accounts[0]);

  const result = await new web3.eth.Contract(compiledFactory.abi)
    .deploy({ data: compiledFactory.evm.bytecode.object })
    .send({ gas: "1400000", from: accounts[0] });
  console.log("Contract deployed successfully to", result.options.address);
  // write the contract address to a file
  fs.writeFileSync(
    "../../Backend/backend_project/backend_app/blockchain/contractAddress.txt",
    result.options.address
  );
  provider.engine.stop();
};
deploy();
