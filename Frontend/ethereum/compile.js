const path = require("path");
const solc = require("solc");
const fs = require("fs-extra");

const buildPath = path.resolve(
  __dirname,
  "../../Backend/backend_project/backend_app/blockchain/build"
);
fs.removeSync(buildPath);
console.log("buildPath", buildPath);
const TransactionPath = path.resolve(__dirname, "contracts", "Transaction.sol");
const source = fs.readFileSync(TransactionPath, "utf8");

const input = {
  language: "Solidity",
  sources: {
    "Transaction.sol": {
      content: source,
    },
  },
  settings: {
    outputSelection: {
      "*": {
        "*": ["*"],
      },
    },
  },
};

const output = JSON.parse(solc.compile(JSON.stringify(input))).contracts[
  "Transaction.sol"
];

fs.ensureDirSync(buildPath);

for (let contract in output) {
  fs.outputJsonSync(
    path.resolve(buildPath, contract.replace(":", "") + ".json"),
    output[contract]
  );
}
