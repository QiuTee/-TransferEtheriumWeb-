from django.utils import timezone
from backend_app.pin import create_pin 
from backend_app.functions import create_user , encrypt_private_key, decrypt_private_key
class OTPService:
    
    @staticmethod
    def check_OTP(user , code): 
        if user.otp != code: 
            return {
                'success' : False , 
                'message': 'OTP is no longer valid',
                'status_code': '401 Unauthorized',
                'error': 'otp wrong'
            }

        if timezone.now() > user.expiration_time:
            return {
                'success': False,
                'message': 'OTP is no longer valid. Please generate a new OTP',
                'status_code': '401 Unauthorized',
                'error': 'otp expired'
            }
        return {'success' : True}
    
    @staticmethod
    def complete_verification(user , w3) : 
        if not user.is_verified:
            user.is_verified = True
            pin = create_pin(user.username)
            create_account, address = create_user(w3)
            user.user_address = address
            user.save()

            # Encrypt account information with PIN and save
            data = encrypt_private_key(create_account, pin)
            user.data = data
            user.save()

            decrypt = decrypt_private_key(w3, user.data, pin)
            
            return {
                'success': True,
                'message': 'Account verified successfully',
                'status_code': '200 OK',
                'data': 'Please check and remember your pin is being sent to your email'
            }

        return {
            'success': False,
            'message': 'Code is invalid',
            'status_code': '400 Bad Request',
            'error': 'otp wrong'
        }
         