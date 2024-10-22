from web3 import Web3

# to connect to an Ethereum node using the Web3 library.
def connect_to_w3() : 
    provided_link = 'https://sepolia.infura.io/v3/181747e4369542ea9234457068381e8b'
    w3 = Web3(Web3.HTTPProvider(provided_link))
    return w3 
