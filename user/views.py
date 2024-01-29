# Django import
from django.shortcuts import render
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Rest framework import
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token

# File import
from user.serializers import ForgotPasswordSerializer,LogoutUserSerializer, UserRegisterSerializer, LoginSerializer, SetNewPasswordSerializer, checkViewSerializer
from user.models import OneTimePassword, User
from user.utils import send_generated_otp_to_email

# Other import
from ast import Expression
from multiprocessing import context


# Create User
class UserRegisterView(GenericAPIView):
    '''
		This view creates new user
    '''
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user = request.data
        
		# Assign serializer 
        serializer = self.serializer_class(data=user)
        
		# Invoke validation method, use raise_exception to throw error if validation fail
        if serializer.is_valid(raise_exception=True):
            # Run save method 
            serializer.save()
            
			# For no otp path,
            return Response({
                'message':'thanks for signing up, please log-in'
			}, status=status.HTTP_201_CREATED)

			# For otp path,
			# # Use serializer data to generate otp
            # user_data = serializer.data
            # send_generated_otp_to_email(user_data['email'], request)
            
			# # Return response
            # return Response({
            #     'data': user_data,
            #     'message':'thanks for signing up a passcode has be sent to verify your email'
            # }, status=status.HTTP_201_CREATED)
        
        # If validate did not pass, it will return error
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
			# this is actually not required as we already have raise_exception


class VerifyEmailView(GenericAPIView):
    '''
    	This view takes in otp and change the user verified to try if otp is correct
    '''
    def post(self, request):
        try:
            passcode = request.data.get('otp')
            
			# Retrieve otp from otp model, based on OTP and extract user. This is possible as they are one to one model 
            # TODO: need to get based on id as well to avoid duplicate otp
            # TODO: need to recreate OTP url
            user_pass_obj = OneTimePassword.objects.get(otp=passcode) 
            user = user_pass_obj.user
            
			# check if user is verified, if not proceed
            if not user.is_verified:
                # modify is_verified, then save
                user.is_verified=True
                user.save()
                
				# return ok message
                return Response({
                    'message':'account email verified successfully'
                }, status=status.HTTP_200_OK)
            
            # if already verified, return verified message
            return Response({'message':'passcode is invalid user is already verified'}, status=status.HTTP_204_NO_CONTENT)
        
		# If fail to find passcode, return error
        except OneTimePassword.DoesNotExist as identifier:
            return Response({'message':'passcode not provided'}, status=status.HTTP_400_BAD_REQUEST)
        

class UserLoginView(GenericAPIView):
    '''
    	This view allow user to log in
    '''
    serializer_class = LoginSerializer
    
    def post(self, request):
        # Assigng serializer
        serializer = self.serializer_class(data=request.data, context={'request': request})
        
		# Invoke validation method, use raise_exception to throw error if validation fail
        serializer.is_valid(raise_exception=True)
        
    	# Return data if is valid, this is for local storage use
        return Response(serializer.data, status=status.HTTP_200_OK)

        # This is for using session storage and cookies, but disabled for now
        # # Prepare sent_data, create response and set cookies
        # sent_data = {
        #     "email": serializer.data.get("email"),
        #     "full_name": serializer.data.get("full_name"),
        #     "access_token": serializer.data.get("access_token"),
        #     "refresh_token": serializer.data.get("refresh_token")
        # }
        # response: Response = Response(sent_data, status=status.HTTP_200_OK)
        # response.set_cookie(
        #     key='refresh_token', 
        #     value=serializer.data.get("refresh_token"), 
        #     # httponly=True,
        #     # secure=True,
        #     # max_age= 1 * 24 * 60 * 60 * 1000, # 1 day
        #     # max_age= 60 * 1000, # 1 minute
        #     # samesite='Strict'
        #     )
        
        # return response


class CheckView(GenericAPIView):
    '''
		This view verify if user is log-in by checking their token
        If token is valid, status code will be 200
        If token is not valid, then user is rejected. Status code will be 401
        Access should be done by attaching the request in the header, key: authorization, value: Bearer Access_token
    '''
    # Set permission to IsAuthenticated. 
    permission_classes=[IsAuthenticated]

    serializer_class = checkViewSerializer
    # queryset = User.objects

    def post(self, request):
        try:
            serializer=self.serializer_class(data=request.data)
            if serializer.is_valid(raise_exception=True):
                return Response(serializer.data, status=status.HTTP_200_OK)
            
            # data = {
            #     'message':'User is log-in'
            # }  
            # return Response(data, status=status.HTTP_200_OK)
        except:
            # Return error if access token is invalid
            return Response(status=status.HTTP_404_NOT_FOUND)
        



class LogoutView(GenericAPIView):
    '''
		This view will blacklist the token, enforcing a pseudo-logout
    '''
    serializer_class = LogoutUserSerializer
    
	# Set permission to IsAuthenticated. 
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Assign serializer
        serializer=self.serializer_class(data=request.data)
        
		# Invoke validation method, use raise_exception to throw error if validation fail
        serializer.is_valid(raise_exception=True)
        
		# if validate success, save 
        serializer.save()
        
		# send success response
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class ForgotPasswordView(GenericAPIView):
    '''
		This view allow you to submit reset password request, if password is forgotten.
    '''
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        # Assign serializer
        serializer=self.serializer_class(data=request.data, context={'request':request})
        
		# Invoke validation method, use raise_exception to throw error if validation fail
        serializer.is_valid(raise_exception=True)
        
        return Response({'message':'we have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        # return Response({'message':'user with that email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
    
class ResetPasswordView(GenericAPIView):
    '''
		This view verify password reset link
    '''
    def get(self, request, uidb64, token):
        try:
            # decode the user id and get user from the parameter
            user_id=smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=user_id)

			# verify token based on user and token, return error if invalid or expired
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message':'token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)
			# if success, return the uidb and token which will be used later to actually reset the password
            return Response({'success':True, 'message':'credentials is valid', 'uidb64':uidb64, 'token':token}, status=status.HTTP_200_OK)

		# if user decode fail, return error message
        except DjangoUnicodeDecodeError as identifier:
            return Response({'message':'token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordView(GenericAPIView):
    '''
		This view reset the password
    '''
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        # Assign serializer
        serializer=self.serializer_class(data=request.data)
        
		# Invoke validation method, use raise_exception to throw error if validation fail
        serializer.is_valid(raise_exception=True)
        
		# Return success message
        return Response({'success':True, 'message':"password reset is succesful"}, status=status.HTTP_200_OK)



 




# from django.shortcuts import render
# from users.serializers import UserRegisterSerializer, UserLoginSerializer
# from rest_framework.views import APIView
# from rest_framework.authentication import TokenAuthentication
# from rest_framework.permissions import AllowAny, IsAuthenticated
# from rest_framework.response import Response
# from rest_framework import status
# from rest_framework.exceptions import AuthenticationFailed
# from django.contrib.auth import authenticate
# from django.conf import settings
# from django.contrib.auth import get_user_model
# from .utils import generate_access_token
# import jwt
# from .validations import custom_validation, validate_email, validate_password


# class UserRegister(APIView):
# 	serializer_class = UserRegisterSerializer
# 	authentication_classes = (TokenAuthentication,)
# 	permission_classes = (AllowAny,)

# 	# def get(self, request):
# 	# 	content = { 'message': 'Hello!' }
# 	# 	return Response(content)

# 	def post(self, request):
# 		validated_data = custom_validation(request.data)
# 		serializer = self.serializer_class(data=validated_data)
# 		if serializer.is_valid(raise_exception=True):
# 			# new_user = serializer.save()
# 			new_user = serializer.create(validated_data)
# 			if new_user:
# 				access_token = generate_access_token(new_user)
# 				data = { 'access_token': access_token }
# 				response = Response(data, status=status.HTTP_201_CREATED)
# 				response.set_cookie(key='access_token', value=access_token, httponly=True)
# 				return response
# 		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# class UserLogin(APIView):
# 	serializer_class = UserLoginSerializer
# 	authentication_classes = (TokenAuthentication,)
# 	permission_classes = (AllowAny,)

# 	def post(self, request):
# 		data = request.data
# 		assert validate_email(data)
# 		assert validate_password(data)
# 		user_instance = authenticate(username=data['email'], password=data['password'])

# 		# email = request.data.get('email', None)
# 		# user_password = request.data.get('password', None)

# 		# if not user_password:
# 		# 	raise AuthenticationFailed('A user password is needed.')

# 		# if not email:
# 		# 	raise AuthenticationFailed('An user email is needed.')

# 		# user_instance = authenticate(username=email, password=user_password)

# 		if not user_instance:
# 			raise AuthenticationFailed('User not found.')

# 		if user_instance.is_active:
# 			user_access_token = generate_access_token(user_instance)
# 			response = Response()
# 			response.set_cookie(key='access_token', value=user_access_token, httponly=True)
# 			response.data = {
# 				'access_token': user_access_token
# 			}
# 			return response

# 		return Response({
# 			'message': 'Something went wrong.'
# 		})



# class UserView(APIView):
# 	authentication_classes = (TokenAuthentication,)
# 	permission_classes = (AllowAny,)

# 	def get(self, request):
# 		user_token = request.COOKIES.get('access_token')

# 		if not user_token:
# 			raise AuthenticationFailed('Unauthenticated user.')

# 		payload = jwt.decode(user_token, settings.SECRET_KEY, algorithms=['HS256'])

# 		user_model = get_user_model()
# 		user = user_model.objects.filter(user_id=payload['user_id']).first()
# 		user_serializer = UserRegistrationSerializer(user)
# 		return Response(user_serializer.data)



# class UserLogout(APIView):
# 	authentication_classes = (TokenAuthentication,)
# 	permission_classes = (AllowAny,)

# 	def get(self, request):
# 		user_token = request.COOKIES.get('access_token', None)
# 		if user_token:
# 			response = Response()
# 			response.delete_cookie('access_token')
# 			response.data = {
# 				'message': 'Logged out successfully.'
# 			}
# 			return response
# 		response = Response()
# 		response.data = {
# 			'message': 'User is already logged out.'
# 		}
# 		return response


