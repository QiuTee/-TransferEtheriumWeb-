from rest_framework.decorators import APIView , action
from rest_framework import  viewsets
from response.responses import Responses 
from backend_app.serializer import *
from .emails import send_otp_via_email , send_otp_via_email_for_reset , sending_email , generate_OTP
from .services.user_service import UserService 
from .services.otp_service import OTPService
from email import *
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
import bcrypt
from .functions import *
from .connect_w3 import connect_to_w3
from decouple import config
from .pending import get_pending_transactions
from .process import process_transaction
from rest_framework.parsers import JSONParser
from django.conf import settings

class AuthenticateManager(viewsets.ModelViewSet) : 
    queryset = User.objects.all() 
    serializer_class = UserInfoSerializer
    @action(detail = False , methods = ['POST'])
    def login_api(self, request):
        w3 = connect_to_w3()
        serializer = LoginSerializer(data=request.data)
        try :
            # Check the validity of input data from the serializer
            if serializer.is_valid(raise_exception=True) :
                # lấy dữ liệu đã được xác thực từ serializer
                username = serializer.validated_data['username']
                password = serializer.validated_data['password']
                # Get user information from login name
                user = User.objects.get(username=username)
                # authenticate username and password
                verify_user = authenticate(username = username,  password = password )
                if user.is_verified : 
                # Check the password is correct
                    if verify_user is None :
                        return Responses.response_api('You have enter an invalid username or password' , '401 Unauthorized')
                    else :  
                        user_profile = UserProfile.objects.get(user_id = user.id)
                        refresh = UserService.generate_token_for_user(user , username)
                        wallet = w3.to_checksum_address(user.user_address)
                        balance = UserService.get_account_balance_from_user_add(w3, wallet)
                        amount_decimal = UserService.format_balance(balance)
                        data = {
                                'id': user.id,
                                'username': user.username,
                                'email': user.email,
                                'lastname': user_profile.last_name,
                                'name': user_profile.first_name + " " + user_profile.last_name,
                                'balance': amount_decimal,
                                'address': user.user_address,
                                'refresh': str(refresh),
                                'token': str(refresh.access_token)
                            }
                        return Responses.response_api('Login successful' , '200 OK' , data = data) 
                else : 
                    return Responses.response_api('Invalid username or password', '401 Unauthorized')
                
            else :
                return Responses.response_api('Username is not valid', '401 Unauthorized')
        except Exception as e :
            return Responses.response_api('You have enter an invalid username or password','401 Unauthorized', data=str(e))

    @action(detail = False , methods = ['POST'])
    def resigter_api(self, request) :
        data = JSONParser().parse(request)
        password = data.get('password')
        retypePassword = data.get('retypePassword')

        # check if user exists but not verified
        try: 
            user_exists = User.objects.filter(username = data.get('username')).first()
            if user_exists and not user_exists.is_verified :
                user_exists.delete()
        except Exception as e : 
            print(str(e))

        # Check the match of the password and re-entered password
        if not password == retypePassword :
            return Responses.response_api('Password and Retype Password is not match','401 Unauthorized')
        serializers = UserInfoSerializer( data = data )
        # print(data)
        try :
            # Check the validity of input data from serializers
            if serializers.is_valid(raise_exception= True) :
                user = serializers.save()
                refresh = UserService.generate_token_for_user(user , data.get('username') )
                send_otp_via_email(serializers.data['email'])
                data = {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email, 
                        'lastname': user.profile.last_name,
                        'name': user.profile.first_name + " " + user.profile.last_name,
                        'phone': user.profile.phoneNumber,
                        'refresh' : str(refresh) , 
                        'token' : str(refresh.access_token) ,
                        'message': 'Please do not skip the last step to verify your account.'
                    }
                return Responses.response_api('Register Successfull','200 OK' , data = data)

        except Exception as e:
            return Responses.response_api('str(e)','401 Unauthorized' , data = data)


        

#verify otp 
class VerifyView(viewsets.ModelViewSet): 
    queryset = User.objects.all() 
    serializer_class = UserInfoSerializer
    
    @action(detail=False, methods=['post'])
    def verify_otp(self, request):
        w3 = connect_to_w3()
        code = request.data.get('otp')
        token = request.data.get('token')
        token_id = UserService.decoding_and_information_extraction_from_token(token , user_info = 'user_id')
        user = User.objects.get(id=token_id)
        check_otp = OTPService.check_OTP(user, code)
        if not check_otp['success'] : 
            return  Responses.response_api(
                check_otp['message'],
                check_otp['status_code'],
                error=check_otp['error']
            )

        verify_result = OTPService.complete_verification(user, w3)
        if verify_result['success']:
            return Responses.response_api(
                verify_result['message'] , 
                verify_result['status_code'],
                data = verify_result['data']
            )
        else : 
           return Responses.response_api(
                verify_result['message'] , 
                verify_result['status_code'],
                error = verify_result['error']
            ) 

        

    @action(detail=False, methods=['POST'])
    def resend_otp(self, request):
        token = request.data.get('token')
        user_id = UserService.decoding_and_information_extraction_from_token(token, user_info='user_id')
        user = User.objects.get(id=user_id)

        if user.otp_max_out > timezone.now() and int(user.max_otp_try) == 0:
            return Responses.response_api(
                'Max tries reached, try again after 1 hour',
                '400 Bad Request'
            )

        new_otp = generate_OTP()
        user.otp = new_otp
        user.expiration_time = timezone.now() + timezone.timedelta(minutes=1)
        max_otp_try = int(user.max_otp_try) - 1
        user.max_otp_try = max_otp_try

        if max_otp_try == 0:
            user.otp_max_out = timezone.now() + timezone.timedelta(hours=1)
        elif max_otp_try == -1:
            user.max_otp_try = settings.MAX_OTP_TRY

        user.save()
        sending_email(new_otp, user.email)

        return Responses.response_api(
            'Successfully generated new OTP.',
            '200 OK'
        )




# update profile
class updateProfile(APIView):
    permissions = [IsAuthenticated]

    def put(self, request):
        data = request.data
        token = request.data.get('token')
        user_id = UserService.decoding_and_information_extraction_from_token(token , user_info='user_id')
        user = User.objects.get(id=user_id)
        password = request.data.get('password')
        confirm_password = request.data.get('confirmPassword')
        # print(confirm_password)
        if password is None and confirm_password is None:
            return self.update_profile_without_password(user, data)
        else:
            return self.update_profile_combine_password(user, data, password, confirm_password, user.fix_update)


    def update_profile_without_password(self, user, data):
        serializers = UserInfoSerializer(user, data, partial=True)
        if not serializers.is_valid():
            return Responses.response_api('Update unsuccessful', '401 Unauthorized')
        else:
            serializers.save()
            return Responses.response_api('Updated profile successfully', '200 OK')

    def update_profile_combine_password(self, user, data, password, confirm_password, fix_update):
        if user.fix_update < timezone.now():
            if password == confirm_password:
                serializers = UserInfoSerializer(user, data, partial=True)
                if not serializers.is_valid():
                    return Responses.response_api('Update unsuccessful', '401 Unauthorized')
                else:
                    user.fix_update = timezone.now() + datetime.timedelta(days=30)
                    serializers.save()
                    return Responses.response_api('Updated profile successfully', '200 OK')
            else:
                return Responses.response_api('Password does not match', '401 Unauthorized')
        else:
            return self.set_remaining_time_for_update_password(fix_update)

    def set_remaining_time_for_update_password(self, fix_update):
        time_remaining = fix_update - timezone.now()
        days_remaining = int(time_remaining.total_seconds() // 86400)
        remaining_seconds_after_days = time_remaining.total_seconds() % 86400
        minutes_remaining = int(remaining_seconds_after_days // 60)
        return Responses.response_api(
            f"Please wait {days_remaining} days and {minutes_remaining} minutes before updating.",
            '401 Unauthorized'
        )


# forget password
class UpdatePassword(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserInfoSerializer

    @action(detail=False, methods=['POST'])
    def forget_password(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        if not User.objects.filter(username=username, email=email).exists():
            return Responses.response_api(
                'User with the given username and email does not exist', '401 Unauthorized'
            )
        else:
            if not SaveEmailModel.objects.filter(username=username, email=email).exists():
                otp_code, expiration_time = send_otp_via_email_for_reset(email)
                request_data = request.data.copy()
                request_data['code'] = otp_code
                request_data['expiration_time'] = expiration_time
                serializers = SaveEmailSerializer(data=request_data)
                if serializers.is_valid():
                    serializers.save()
                    return Responses.response_api('OTP sent successfully', '200 OK')
            else:
                user = SaveEmailModel.objects.get(username=username, email=email)
                if user.otp_max_try == 0 and user.otp_max_try_time > timezone.now():
                    return Responses.response_api(
                        'You have used up all the allowed attempts to change your password, please try again after 1 hour.',
                        '401 Unauthorized'
                    )
                otp_code, expiration_time = send_otp_via_email_for_reset(email)
                user.code = otp_code
                user.expiration_time = expiration_time
                user.otp_max_try = int(user.otp_max_try) - 1
                if user.otp_max_try == 0:
                    user.otp_max_try_time = timezone.now() + datetime.timedelta(hours=1)
                elif user.otp_max_try == -1:
                    user.otp_max_try = settings.MAX_OTP_TRY
                user.save()
                return Responses.response_api('OTP sent successfully', '200 OK')

    @action(detail=False, methods=['POST'])
    def reset_password(self, request):
        first_data = SaveEmailModel.objects.first()
        user = User.objects.get(email=first_data.email)
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        otp = request.data.get('otp')
        if not first_data.check_run_time():
            if otp == first_data.code:
                if confirm_password == password:
                    user.set_password(password)
                    user.save()
                    SaveEmailModel.objects.all().delete()
                    return Responses.response_api('Password changed successfully', '200 OK')
                return Responses.response_api('Password does not match', '401 Unauthorized')
            return Responses.response_api('OTP does not match', '401 Unauthorized')
        else:
            send_otp_via_email_for_reset(first_data.email)
            return Responses.response_api('OTP is no longer valid', '401 Unauthorized')


class TestPin(APIView):
    def post(self, request):
        email = request.data.get('email')
        print(email)
        pin = request.data.get('pin')
        print(pin)
        data = User.objects.get(email=email)
        if bcrypt.checkpw(pin.encode('utf-8'), data.pin):
            print(True)
        else:
            print(False)
        print(f"{data.pin}")
        return Responses.response_api('PIN check result', '200 OK')


class TransactionView(APIView):
    def post(self, request):
        try:
            w3 = connect_to_w3()
            token = request.data.get('token')
            to_address = request.data.get('to_address')
            amount = request.data.get('amount')
            pin = request.data.get('pin')
            username_from_token = UserService.decoding_and_information_extraction_from_token(token, user_info='username')
            data = User.objects.get(username=username_from_token)
            if not w3.is_address(to_address):
                return Responses.response_api('Invalid to_address', '400 Bad Request')

            receiver = w3.to_checksum_address(to_address)
            if not bcrypt.checkpw(pin.encode('utf-8'), data.pin):
                return Responses.response_api('Invalid PIN', '401 Unauthorized')

            contract_address = read_contract_address()
            abi, abi2 = open_transaction_factory()
            contract_instance = w3.eth.contract(address=contract_address, abi=abi)
            private_key = decrypt_private_key(w3, data.data, data.pin)
            amount_in_wei = w3.to_wei(amount, 'ether')
            transaction = transaction_json(w3, data.user_address, amount_in_wei)

            if check_fee(w3, data.user_address, amount_in_wei):
                return Responses.response_api('Not enough fee to complete transaction', '400')

            receipt, success = createTransaction(
                w3, contract_instance, receiver, private_key, amount_in_wei, transaction
            )
            hash_block = receipt.blockHash.hex()
            transaction_hash = receipt.transactionHash.hex()

            if success:
                balance = w3.from_wei(w3.eth.get_balance(data.user_address), "ether")
                transaction_address = get_last_transaction(contract_instance)
                history = HistoryModel(
                    user_address=data.user_address, username=data.username, hash_block=hash_block,
                    contract_address=transaction_address, transaction_hash=transaction_hash
                )
                history.save()
                return Responses.response_api(
                    'Transaction completed successfully', '200 OK', {'balance': balance}
                )
            else:
                return Responses.response_api('Transaction failed', '400', receipt)
        except Exception as e:
            return Responses.response_api(str(e), '500 Internal Server Error')


class PendingView(APIView):
    def post(self, request):
        w3 = connect_to_w3()
        token = request.data.get('token')
        username_from_token =UserService.decoding_and_information_extraction_from_token(token, user_info='username')
        user_address = User.objects.get(username=username_from_token)
        user_add = user_address.user_address
        history = get_pending_transactions(w3, user_add)
        return Responses.response_api(
            'Successfully retrieved pending transactions', '200 OK', history
        )
    


class HistoryView(APIView):
    def post(self, request):
        w3 = connect_to_w3()
        token = request.data.get('token')
        username_from_token = UserService.decoding_and_information_extraction_from_token(token, user_info='username')
        user = User.objects.get(username=username_from_token)
        actions = ['txlist', 'txlistinternal']  # List of actions
        history = []
        id = 0
        for action in actions:
            params = {
                'module': 'account',
                'action': action,
                'address': user.user_address,
                'startblock': 0,
                'endblock': 99999999,
                "page": 1,
                "offset": 10,
                'sort': 'asc',
                'apikey': config('API_KEY')
            }
            offset = 0
            while True:
                params['offset'] = 10  # Set the offset
                params['page'] = offset + 1  # Set the page number

                data_result = get_data_api(params)
                if not data_result:
                    break  # If the result is empty, break the loop

                for each_result in data_result:
                    id += 1
                    time = convert_to_time(int(each_result['timeStamp']))
                    amount_wei = int(each_result['value'])
                    amount_eth = w3.from_wei(amount_wei, "ether")
                    amount_decimal = UserService.format_balance(amount_eth)
                    if user.user_address == w3.to_checksum_address(each_result['to']):
                        amount = f"+{amount_decimal}"
                    else:
                        amount = f"-{amount_decimal}"
                    valid = each_result['isError'] == "0"
                    item = {
                        "id": id,
                        "timestamp": time,
                        "amount": amount,
                        "valid": valid,
                        "from": each_result['from'],
                        "to": each_result['to']
                    }
                    history.append(item)

                offset += 1

        return Responses.response_api('Successfully retrieved history', '200 OK', data=history)


class ExecuteView(APIView):
    def post(self, request):
        w3 = connect_to_w3()
        token = request.data.get('token')
        username_from_token = UserService.decoding_and_information_extraction_from_token(token, user_info='username')
        pin = request.data.get('pin')
        transaction_address = request.data.get('item')
        action = request.data.get('action')
        user = User.objects.get(username=username_from_token)
        user_address = user.user_address
        abi, abi2 = open_transaction_factory()
        private_key = decrypt_private_key(w3, user.data, user.pin)
        send_transaction = transaction_json(w3, user.user_address, 0)

        if bcrypt.checkpw(pin.encode('utf-8'), user.pin):
            history, balance = process_transaction(action, user, transaction_address, w3, abi2, private_key, send_transaction, user_address)

            return Responses.response_api('Successfully retrieved pending transactions', '200 OK', data={'history': history, 'balance': balance})
        else:
            return Responses.response_api('Invalid PIN', '401 Unauthorized')


class AllBlockView(APIView):
    def get(self, request):
        w3 = connect_to_w3()
        block_chain = []
        unique_block = []
        return_block = []

        blocks = HistoryModel.objects.all()
        for bl in blocks:
            if bl is not None:
                block_chain.append(bl.hash_block)
                block_chain.append(bl.hash_block_transaction)

        for unique in block_chain:
            if unique not in unique_block:
                unique_block.append(unique)

        for block in unique_block:
            block = w3.eth.get_block(block, True)
            block_item = {
                'number': block.number,
                'hash': block.hash.hex(),
                'previous_hash': block.parentHash.hex(),
                'nonce': int(block.nonce.hex(), 16),
                'timestamp': block.timestamp
            }
            return_block.append(block_item)

        return Responses.response_api('Fetch all blocks successfully', '200 OK', data=return_block)


class BlockDetailView(APIView):
    def get(self, request, block_id):
        w3 = connect_to_w3()
        transactions_hash = []
        return_transactions = []
        blocks = HistoryModel.objects.all()

        id = 0

        fetch_block = w3.eth.get_block(block_id, True)
        all_transaction = fetch_block.transactions
        for db_trans in blocks:
            transactions_hash.append(db_trans.transaction_hash)
            transactions_hash.append(db_trans.execute_transaction_hash)
        for trans in all_transaction:
            if trans.hash.hex() in transactions_hash:
                id += 1
                amount_decimal = UserService.format_balance(w3.from_wei(trans.value, 'ether'))
                return_transactions.append({
                    'id': id,
                    'from': trans['from'],
                    'to': trans['to'],
                    'hash': trans.hash.hex(),
                    'value': amount_decimal
                })

        return Responses.response_api('Block detail fetched successfully', '200 OK', data=return_transactions)