from web3 import Web3

from functions import *

provided_link = 'https://sepolia.infura.io/v3/181747e4369542ea9234457068381e8b'
w3 = Web3(Web3.HTTPProvider(provided_link)) # create web3 object
abi , abi2 = open_transaction_factory()
contract_address = read_contract_address()
contract_instance = w3.eth.contract(address=contract_address, abi=abi)
def print_deployed_transactions(contract_instance):
    # print("Deployed Contracts: ",contract_instance.functions.getDeployedTransactions().call())
    # print("Deployed Contracts: ",contract_instance.functions.getDeployedTransactions().call()[-1])
    last_item = contract_instance.functions.getDeployedTransactions().call()[-1]
    return last_item

print_deployed_transactions(contract_instance)