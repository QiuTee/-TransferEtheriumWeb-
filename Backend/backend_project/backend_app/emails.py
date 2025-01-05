from random import choice
from django.conf import settings
from .models import *
from django.core.mail import EmailMessage


# Used to create an OTP code consisting of 5 digits
from django.core.mail import EmailMessage
from django.conf import settings
from .models import User
from django.utils import timezone
import random


def generate_OTP():
    otp_code = "".join(random.choices("123456789", k=5))
    return otp_code


def send_otp_via_email(email):
    subject = "Your account verification email:"
    otp_code = generate_OTP()
    print(otp_code)
    try:
        user = User.objects.get(email=email)
        if not user.is_verified:
            user.otp = otp_code
            user.expiration_time = timezone.now() + timezone.timedelta(minutes=1)
            print(user.expiration_time)
            user.save()
        current_site = "Digicode"
        email_body = (
            f"Dear {user.first_name},\n\nThank you for signing up on {current_site}. We appreciate your registration.\n\n"
            f"To verify your email and complete the registration process, please use the following one-time passcode: {otp_code}.\n\n"
            f"If you have any questions or need assistance, feel free to contact our support team.\n\n"
            f"Best regards,\n{current_site}"
        )
        from_email = settings.EMAIL_HOST_USER
        d_mail = EmailMessage(
            subject=subject, body=email_body, from_email=from_email, to=[email]
        )
        d_mail.send(fail_silently=True)
    except Exception as e:
        print(str(e))


def send_otp_via_email_for_reset(email):
    subject = "Your account verification email: "
    otp_code = generate_OTP()
    user = User.objects.get(email=email)
    expiration_time = timezone.now() + timezone.timedelta(minutes=1)
    current_site = "Digicode"
    email_body = f"Hi {user.first_name}, thank you for signing up on {current_site}. Please verify your email with the one-time passcode: {otp_code}."
    from_email = settings.EMAIL_HOST
    d_mail = EmailMessage(
        subject=subject, body=email_body, from_email=from_email, to=[email]
    )
    d_mail.send(fail_silently=True)
    return otp_code, expiration_time


def sending_email(otp_code, email):
    subject = "Your account verification email:"
    current_site = "Digicode"
    email_body = (
        f"Thank you for signing up on {current_site}. We appreciate your registration.\n\n"
        f"To verify your email and complete the registration process, please use the following one-time passcode: {otp_code}.\n\n"
        f"If you have any questions or need assistance, feel free to contact our support team.\n\n"
        f"Best regards,\n{current_site}"
    )
    from_email = settings.EMAIL_HOST
    d_mail = EmailMessage(
        subject=subject, body=email_body, from_email=from_email, to=[email]
    )

    try:
        d_mail.send(fail_silently=True)
        print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")
