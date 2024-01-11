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
from users.models import User
from users.utils import send_normal_email

# Other import
import json
from dataclasses import field
from string import ascii_lowercase, ascii_uppercase

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

    # Create User. This is invoke be serializer.save()
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name'),
            password=validated_data.get('password')
            )
        return user


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password=serializers.CharField(max_length=68, write_only=True)
    full_name=serializers.CharField(max_length=255, read_only=True)
    access_token=serializers.CharField(max_length=255, read_only=True)
    refresh_token=serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']

    

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request=self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("invalid credential try again")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")
        tokens=user.tokens()
        return {
            'email':user.email,
            'full_name':user.get_full_name,
            "access_token":str(tokens.get('access')),
            "refresh_token":str(tokens.get('refresh'))
        }


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user= User.objects.get(email=email)
            uidb64=urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            request=self.context.get('request')
            current_site=get_current_site(request).domain
            relative_link =reverse('reset-password-confirm', kwargs={'uidb64':uidb64, 'token':token})
            abslink=f"http://{current_site}{relative_link}"
            print(abslink)
            email_body=f"Hi {user.first_name} use the link below to reset your password {abslink}"
            data={
                'email_body':email_body, 
                'email_subject':"Reset your Password", 
                'to_email':user.email
                }
            send_normal_email(data)

        return super().validate(attrs)

    
class SetNewPasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64=serializers.CharField(min_length=1, write_only=True)
    token=serializers.CharField(min_length=3, write_only=True)

    class Meta:
        fields = ['password', 'confirm_password', 'uidb64', 'token']

    def validate(self, attrs):
        try:
            token=attrs.get('token')
            uidb64=attrs.get('uidb64')
            password=attrs.get('password')
            confirm_password=attrs.get('confirm_password')

            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("reset link is invalid or has expired", 401)
            if password != confirm_password:
                raise AuthenticationFailed("passwords do not match")
            user.set_password(password)
            user.save()
            return user
        except Exception as e:
            return AuthenticationFailed("link is invalid or has expired")


    
class LogoutUserSerializer(serializers.Serializer):
    refresh_token=serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')

        return attrs

    def save(self, **kwargs):
        try:
            token=RefreshToken(self.token)
            token.blacklist()
        except TokenError:
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

