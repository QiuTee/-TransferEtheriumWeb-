import json
import datetime
from web3.exceptions import ContractLogicError
import os
import requests
def get_user_info(w3, user_address):
    try:
        wallet = w3.to_checksum_address(user_address) # make sure address is in valid format
    except Exception as e:
        print("Error:", e)
def check_fee(w3 ,user_address , amount):
    wallet = w3.to_checksum_address(user_address)
    balance = w3.from_wei(w3.eth.get_balance(wallet), "ether")
    if amount > balance :
        return False
    return True
def open_transaction_factory():
    blockchain_dir = os.path.join(os.path.dirname(__file__), 'blockchain')
    transaction_factory_path = os.path.join(blockchain_dir, 'build/TransactionFactory.json')
    transaction_path = os.path.join(blockchain_dir, 'build/Transaction.json')

    try:
        with open(transaction_factory_path, "r") as f:
            file = json.load(f)
        abi = file["abi"]

        with open(transaction_path, "r") as f2:
            file2 = json.load(f2)
        abi2 = file2["abi"]

        return abi, abi2
    except Exception as e:
        print("Error:", e)

def read_contract_address():
    try:
        # This line gets the current directory path of the Python script file containing this function.
        current_dir = os.path.dirname(__file__)
        # This line creates the path to the directory "blockchain" inside the current directory by combining the current directory path with the directory name "blockchain"
        blockchain_dir = os.path.join(current_dir, 'blockchain')
        contract_address_file = os.path.join(blockchain_dir, 'contractAddress.txt')
        # This line opens the contract address file in read mode using a management context. The file object is assigned to variable f.
        with open(contract_address_file, "r") as f:
            contract_address = f.read()
        return contract_address
    except Exception as e:
        print("Error:", e)

# Get information about the last transaction deployed
def get_last_transaction(contract_instance):
    return contract_instance.functions.getDeployedTransactions().call()[-1]

# Get the list of deployed transactions
def get_deployed_transactions(contract_instance):
    return contract_instance.functions.getDeployedTransactions().call()


def getTransactionContract(contract_instance, index):
    try:
        return contract_instance.functions.getDeployedTransactions().call()[index]
    except Exception as e:
        print("Error:", e)

# Create a new transaction in the smart contract.
def createTransaction(w3, contract_instance, receiver, private_key, amount, transaction_detail = {}):
    success = False
    try:
        # Build a transaction using the createTransaction function in the smart contract
        transaction = contract_instance.functions.createTransaction(amount, receiver).build_transaction(transaction_detail)
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)

        transaction_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        # Wait to receive transaction notification
        transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)

        success = True
        return transaction_receipt, success # return transaction receipt from web3
    except ContractLogicError as e:
        # # Exception handling related to smart contracts
        error_message = str(e)
        if "execution reverted: Transaction already completed" in error_message:
            print("Error: Transaction already completed.")
            return ("Error: Transaction already completed." , success)
        else:
            message = "Error:", error_message
            print("Error:", error_message)
            return (message, success)

# Execute a transaction created in a smart contract
def executeTransaction(w3, transaction_contract_instance, private_key, transaction_detail={}):
    success = False
    try:
        # Build the transaction using the send function in the smart contract version of the transaction
        transaction = transaction_contract_instance.functions.send().build_transaction(transaction_detail)
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)
        transaction_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
        success = True
        return transaction_receipt,success
    except ContractLogicError as e:
        error_message = str(e)
        if "execution reverted: Transaction already completed" in error_message:
            print("Error: Transaction already completed.")
            return ("Error: Transaction already completed." , success)
        else:
            message = "Error:", error_message
            print("Error:", error_message)
            return (message, success)
def withdrawTransaction(w3, transaction_contract_instance, private_key, transaction_detail={}):
    success = False
    try:
        transaction = transaction_contract_instance.functions.withdraw().build_transaction(transaction_detail)
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)
        transaction_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)

        success = True
        return transaction_receipt,success
    except ContractLogicError as e:
        error_message = str(e)
        if "execution reverted: Transaction already completed" in error_message:
            print("Error: Transaction already completed.")
            return ("Error: Transaction already completed." , success)
        else:
            message = "Error:", error_message
            print("Error:", error_message)
            return (message, success)
def getTransactionInformation( w3, transaction_contract_instance): # 
    contract_info = transaction_contract_instance.functions.returnInformation().call()
    return contract_info

def get_all_event(w3, transaction_contract_instance):
    event_filter = transaction_contract_instance.events.TransactionCompleted.create_filter(fromBlock='latest')
    past_events = event_filter.get_all_entries()
    result = {"sender":"","receiver":"","amount":"","timestamp":""}
    for event in past_events:
        time = convert_to_time(event['args']['timestamp'])
        result["sender"] = event['args']['sender']
        result["receiver"] = event['args']['receiver']
        result["amount"] = w3.from_wei(event['args']['amount'], 'ether')
        result["timestamp"] = time
        print("Result: ", result)
    return result
def create_user(w3):
    # Create a new account using the Web3 object
    created_account = w3.eth.account.create()
    return created_account , created_account.address
def encrypt_private_key(account, encrypted_key):
    # Encrypt the account's private key using the account's `encrypt` method
    keystore = account.encrypt(encrypted_key)
    return keystore
def decrypt_private_key(w3, keystore, encrypted_key):
    # Decrypt the keystore using the Web3 object's `decrypt` method
    key_store = w3.eth.account.decrypt(keystore, encrypted_key)
    return key_store
def convert_to_time(time):
    dt_object = datetime.datetime.fromtimestamp(time)
    formatted_datetime = dt_object.strftime('%Y-%m-%d %H:%M:%S')
    return formatted_datetime
def transaction_json( w3, sender, value):
    # Create a JSON object representing a transaction
    return {
        "from": sender,
        "value": value,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
        "nonce": w3.eth.get_transaction_count(sender)
    }
def get_transaction_history(w3, user_address):
    try:
        # Get the transaction count of the user's address
        transactions = w3.eth.get_transaction_count(user_address)
        for i in range(transactions):
            # Get transaction information by index from 0 to transaction amount - 1
            transaction = w3.eth.get_transaction_by_index(user_address, i)
            
    except Exception as e:
        print("Error:", e)

def get_data_api(params):
    url = 'https://api-sepolia.etherscan.io/api'
    # Send a GET request to the API with the parameters provided
    response = requests.get(url, params=params)
    if response.status_code == 200:
        # Convert data received from API into JSON format
        data = response.json()
        # Returns results from JSON data
        return data['result']
    else:
        # Print an error if an error occurred during the API request
        print("Error:", response.status_code)
        return response.status_code
