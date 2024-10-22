from backend_app.models import HistoryModel
from .functions import *


def process_transaction(action, user, transaction_address, w3, abi2, private_key, send_transaction , user_address):
    
    history_objects = HistoryModel.objects.filter(user_address=user_address)
    history = []
    balance = 0

    for user_his in history_objects:
        if user_his.contract_address == w3.to_checksum_address(transaction_address) and w3.is_address(transaction_address):
            transaction_contract_instance = w3.eth.contract(address=user_his.contract_address, abi=abi2)
            receipt, success = execute_or_withdraw_transaction(action, w3, transaction_contract_instance, private_key, send_transaction)
            balance = w3.from_wei(w3.eth.get_balance(user_address), "ether")

            if success:
                hash_block = receipt.blockHash.hex()
                user_his.hash_block_transaction = hash_block
                transaction_hash = receipt.transactionHash.hex()
                user_his.execute_transaction_hash = transaction_hash
                user_his.is_send = True
                user_his.save()
                id = 0
                user_history = HistoryModel.objects.filter(user_address=user_address)

                for user_his in user_history:
                    if not user_his.is_send:
                        id += 1
                        abi, abi2 = open_transaction_factory()
                        transaction_contract_instance = w3.eth.contract(address=user_his.contract_address, abi=abi2)
                        contract_info = getTransactionInformation(w3, transaction_contract_instance)
                        amount_eth = w3.from_wei(contract_info[2], 'ether')
                        amount_decimal = "{:.50f}".format(amount_eth).rstrip('0')
                        history_item = {
                            'id': id,
                            'transaction_hash': user_his.transaction_hash,
                            'receiver': contract_info[1],
                            'amount': amount_decimal,
                            'contract_address': user_his.contract_address,
                            'timestamp': convert_to_time(contract_info[4])
                        }
                        history.append(history_item)

    return history, balance

def execute_or_withdraw_transaction(action, w3, transaction_contract_instance, private_key, send_transaction):
    if action == 'execute':
        return executeTransaction(w3, transaction_contract_instance, private_key, send_transaction)
    elif action == 'withdraw':
        return withdrawTransaction(w3, transaction_contract_instance, private_key, send_transaction)
    else:
        return None, False