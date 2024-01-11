# Django import
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site

# File import
from users.models import User, OneTimePassword

# Other import
import random


def send_generated_otp_to_email(email, request): 
    # Create subject, otp, current site
    subject = "One time passcode for Email verification"
    otp = random.randint(100000, 999999) 
    current_site = get_current_site(request).domain

    # Retrieve user data based on email and create email body
    user = User.objects.get(email=email)
    email_body = f"Hi {user.first_name} thanks for signing up on {current_site} please verify your email with the \n one time passcode {otp}"
    # from_email = settings.EMAIL_HOST
    from_email = settings.DEFAULT_FROM_EMAIL

    # Save otp to otp model. Variable is intentionally not used
    otp_obj = OneTimePassword.objects.create(user=user, otp=otp)

    # Create email and send 
    d_email = EmailMessage(subject=subject, body=email_body, from_email=from_email, to=[user.email])
    # d_email.send()
    d_email.send(fail_silently=True)


def send_normal_email(data):
    email=EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send()














# from django.conf import settings
# from datetime import datetime, timedelta
# import jwt


# def generate_access_token(user):
# 	payload = {
# 		'user_id': user.user_id,
# 		'exp': datetime.utcnow() + timedelta(days=1, minutes=0),
# 		'iat': datetime.utcnow(),
# 	}

# 	access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
# 	return access_token