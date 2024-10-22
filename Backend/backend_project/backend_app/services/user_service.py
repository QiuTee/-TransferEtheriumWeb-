from rest_framework_simplejwt.tokens import RefreshToken , AccessToken
from decimal import Decimal

class UserService : 
    @staticmethod 
    def generate_token_for_user(user , username) : 
        refresh = RefreshToken.for_user(user)
        refresh['username'] = username
        return refresh
    
    @staticmethod
    def get_account_balance_from_user_add( w3, wallet): 
        balance = w3.from_wei(w3.eth.get_balance(wallet), "ether")
        return balance
    
    @staticmethod
    def format_balance(balance):
        amount = Decimal(balance)
        amount_decimal = "{:.50f}".format(amount).rstrip('0') 
        return amount_decimal
    
    @staticmethod
    def decoding_and_information_extraction_from_token(token , user_info):
        access_token = AccessToken(token)
        if user_info == 'username' : 
            return access_token['username']
        if user_info == 'user_id':
            return access_token['user_id']

