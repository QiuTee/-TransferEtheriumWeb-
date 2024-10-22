from random import randint
from .models import User
import bcrypt
from django.conf import settings 
from django.core.mail import EmailMessage
from .connect_w3 import connect_to_w3
def random_number():
    return str(randint(1000000 , 9999999) ) 

def create_pin(username): 
    w3 = connect_to_w3()
    user = User.objects.get(username=username )
    pin = random_number() 
    hash_pin = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt())
    print(f"Hash pin : {hash_pin}")
    user.pin = str(hash_pin) 
    user.save()

    subject = "Your pin code: "
    email_body = f"""
    Hi {user.first_name},

    Thank you for using Digicode ! We have generated a new pin code for your recent transaction. Please ensure the confidentiality of this pin code and do not share it with anyone.

    IMPORTANT: Your transaction pin code is: {pin}
    """
    from_email = settings.EMAIL_HOST
    d_mail = EmailMessage(subject=subject, body=email_body, from_email=from_email, to=[user.email])
    d_mail.send(fail_silently=True)
    return hash_pin
    