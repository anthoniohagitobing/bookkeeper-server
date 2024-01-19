# Django import
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_str, force_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import reverse

# Rest import
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

# File import
from user.models import User
from user.utils import send_normal_email

# Other import
import json
from dataclasses import field
from string import ascii_lowercase, ascii_uppercase
from dotenv import load_dotenv, find_dotenv
import os

# Load environment variables
load_dotenv(find_dotenv())
FRONT_END_URL = os.getenv('FRONT_END_URL')

# Retrieve user model, not used for this project as simple User model can be used
# UserModel = get_user_model()

class UserRegisterSerializer(serializers.ModelSerializer):
    # Custom fields validation
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)

    # Fields validation from table. Note that password2 does not exist on table, but added through custom field validation
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password2']

    # Password matching validation. This is custom object validation. Note that both table validation, field validation, custom validation are automatically triggered when serializer is run
    def validate(self, attrs):
        password = attrs.get('password', '')
        password2 = attrs.get('password2', '')
        if password != password2:
            raise serializers.ValidationError("passwords do not match")
        # return data back if password match
        return attrs

    # Create User. This is a custom create. This is invoke be serializer.save()
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name'),
            password=validated_data.get('password'),

            # This is for bypassing email auth. To bypass, set to True. Otherwise, set to False
            is_verified=True,
            # is_verified=False,
            )
        return user


class LoginSerializer(serializers.ModelSerializer):
    # Custom fields validation. Note that password is only validated on write only, while the read_only is only validated when getting from database
    # email = serializers.EmailField(max_length=255, min_length=6)
    email = serializers.EmailField(max_length=255, min_length=6, write_only=True)
    password = serializers.CharField(max_length=68, write_only=True)
    # full_name = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    # Fields validation from table. Note that access_token and refresh_token does not exist on table, but added through custom field validation
    class Meta:
        model = User
        # fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']
        fields = ['email', 'password', 'access_token', 'refresh_token']

    # Email and password matching validation.
    def validate(self, attrs):
        # Authenticate email, password and request
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request, email=email, password=password)

        # Check result. If not user, invalid credential. If not verified, email is not verified
        if not user:
            raise AuthenticationFailed("invalid credential try again")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")
        
        # If authentication sucess, we invoke the tokens() method in the user model to generate token. 
        tokens = user.tokens()

        # Return dictionary. Note that get_full_name is a property in the model.
        return {
            # 'email': user.email,
            # 'full_name': user.get_full_name,
            "access_token": str(tokens.get('access')),
            "refresh_token": str(tokens.get('refresh'))
        }


class ForgotPasswordSerializer(serializers.Serializer):
    # Custom fields validation.
    email = serializers.EmailField(max_length=255)

    # Fields validation.
    class Meta:
        fields = ['email']

    # Validate
    def validate(self, attrs):
        # Extract email
        email = attrs.get('email')

        # Check if user exists
        if User.objects.filter(email=email).exists():
            # Generate custom url for reseting password, composing of user.id, token, domain
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            request = self.context.get('request')
            # current_site = get_current_site(request).domain
            current_site = FRONT_END_URL
            relative_link = reverse('reset-password', kwargs={'uidb64':uidb64, 'token':token})
            # relative_link = reverse('reset-password-confirm', kwargs={'uidb64':uidb64, 'token':token})
            # abslink = f"http://{current_site}{relative_link}"
            abslink = f"{current_site}{relative_link}"

            # Create email link and data
            email_body=f"Hi {user.first_name} use the link below to reset your password {abslink}"
            data = {
                'email_body':email_body, 
                'email_subject':"Reset your Password", 
                'to_email':user.email
            }
            
            # Use utility function to send email
            send_normal_email(data)

        return super().validate(attrs)

    
class SetNewPasswordSerializer(serializers.Serializer):
    # Custom fields validation. Data validation is only for write only, so when data is first inserted
    password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64=serializers.CharField(min_length=1, write_only=True)
    token=serializers.CharField(min_length=3, write_only=True)

    # Fields validation.
    class Meta:
        fields = ['password', 'confirm_password', 'uidb64', 'token']

    # Validate if token and uid64 are valid, also validate if password and confirm_password match 
    def validate(self, attrs):
        try:
            # Breakdown the data
            token=attrs.get('token')
            uidb64=attrs.get('uidb64')
            password=attrs.get('password')
            confirm_password=attrs.get('confirm_password')

            # decode the user id and get user
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            # reverify token based on user and token
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("reset link is invalid or has expired", 401)
            
            # check password and confirm_password
            if password != confirm_password:
                raise AuthenticationFailed("passwords do not match")
            
            # if all checks passed, set password and then save
            user.set_password(password)
            user.save()
            return user
        
        # if anything fail, return authentication failed
        except Exception as e:
            return AuthenticationFailed("link is invalid or has expired")


    
class LogoutUserSerializer(serializers.Serializer):
    # Custom fields validation
    refresh_token=serializers.CharField()

    # Create error message dictionary
    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    # this validate and retrieve the refresh token data, 
    def validate(self, attrs):
        # assign token to self so that it can be passed on later
        self.token = attrs.get('refresh_token')
        return attrs

    def save(self, **kwargs):
        try:
            # Reconvert token and blacklist
            token = RefreshToken(self.token)
            token.blacklist()
        # Throw error if token cannot be blacklisted
        except TokenError:
            # This will return message error from default_error_message
            return self.fail('bad_token')

    

    
    


# from rest_framework import serializers
# from django.contrib.auth import get_user_model, authenticate

# UserModel = get_user_model()

# class UserRegisterSerializer(serializers.ModelSerializer):
# 	password = serializers.CharField(max_length=100, min_length=8, style={'input_type': 'password'})
# 	class Meta:
# 		# model = get_user_model()
# 		model = UserModel
# 		# fields = '__all__'
# 		fields = ['email', 'password']
# 		# fields = ['email', 'username', 'password']

# 	def create(self, validated_data):
# 		user_obj = UserModel.objects.create_user(email=validated_data['email'], password=validated_data['password'])
# 		user_obj.save()
# 		return user_obj
# 		# user_password = validated_data.get('password', None)
# 		# db_instance = self.Meta.model(email=validated_data.get('email'), username=validated_data.get('username'))
# 		# db_instance.set_password(user_password)
# 		# db_instance.save()
# 		# return db_instance



# class UserLoginSerializer(serializers.Serializer):
# 	email = serializers.CharField(max_length=100)
# 	# username = serializers.CharField(max_length=100, read_only=True)
# 	password = serializers.CharField(max_length=100, min_length=8, style={'input_type': 'password'})
# 	token = serializers.CharField(max_length=255, read_only=True)

