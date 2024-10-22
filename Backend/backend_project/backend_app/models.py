from django.db import models
from django.contrib.auth.models import AbstractUser , PermissionsMixin ,User
from backend_app.manager import UserManager
from django.utils import timezone
from django.conf import settings
import random 

def generate_random_pin():
    pin = str(random.randint(1000000, 9999999))
    return pin

class User(AbstractUser , PermissionsMixin):
    pin = models.CharField(max_length = 255, unique=True, null = True)
    user_address = models.CharField( max_length = 255 )
    data = models.JSONField(default=dict)
    max_otp_try = models.CharField(max_length=2 , default= settings.MAX_OTP_TRY)
    otp = models.CharField(max_length= 6 , null = True , blank = True)
    otp_max_out = models.DateTimeField(default= timezone.now)
    expiration_time = models.DateTimeField(default=timezone.now)
    fix_update = models.DateTimeField(default= timezone.now)
    is_verified = models.BooleanField(default=False)
    is_superuser = models.BooleanField( default= False ) 
    is_active = models.BooleanField( default= False ) 
    is_staff = models.BooleanField( default= False ) 
    date_joined = models.DateTimeField(auto_now_add = True)
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    objects = UserManager()
    
    @property
    def name(self):
        return self.first_name + ' ' + self.last_name

    def __str__(self):
        return self.email

    def token(self):
        pass

class UserProfile(models.Model): 
    user = models.OneToOneField(
        User , 
        related_name='profile',
        on_delete=models.CASCADE, 
        primary_key = True 
    )
    last_name = models.CharField( max_length = 100 )
    first_name = models.CharField( max_length = 100 )
    phoneNumber = models.CharField( max_length = 20 )
    last_login = models.DateTimeField(auto_now = True )

class SaveEmailModel(models.Model):
    username = models.CharField(max_length = 255)
    email = models.EmailField(unique=True)
    code = models.CharField(max_length=6, unique=True)
    expiration_time = models.DateTimeField(default=timezone.now)
    otp_max_try =  models.CharField(max_length= 6 , default = settings.MAX_OTP_TRY)
    otp_max_try_time = models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.email
    def check_run_time(self) : 
        return timezone.now() > self.expiration_time

class HistoryModel(models.Model):
    user_address = models.CharField(max_length = 255 , default='' )
    username = models.CharField(max_length = 255 , default='' )
    hash_block = models.CharField(max_length= 255 ,default= 'default' ,blank = True) 
    contract_address = models.CharField(max_length = 255 , default = "default" , blank = True)
    transaction_hash = models.CharField(max_length = 255 , default= "default"  ,blank = True)
    hash_block_transaction = models.CharField(max_length = 255 , default = "" , blank = True)
    execute_transaction_hash = models.CharField(max_length = 255 , default = "" , blank = True)
    receiver_address  = models.CharField(max_length = 255 , default = "" , blank = True)
    is_send = models.BooleanField(default=False)

    def __str__(self) : 
        return self.username