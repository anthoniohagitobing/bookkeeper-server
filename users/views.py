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

# File import
from users.serializers import PasswordResetRequestSerializer,LogoutUserSerializer, UserRegisterSerializer, LoginSerializer, SetNewPasswordSerializer
from users.models import OneTimePassword, User
from users.utils import send_generated_otp_to_email

# Other import
from ast import Expression
from multiprocessing import context


# Create User
class UserRegister(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user = request.data
        
		# Verify data with serializer
        serializer=self.serializer_class(data=user)
        # If valid
        if serializer.is_valid(raise_exception=True):
            # Save
            serializer.save()
            
			# Use serializer data to generate otp
            user_data = serializer.data
            send_generated_otp_to_email(user_data['email'], request)
            
			# Return response
            return Response({
                'data':user_data,
                'message':'thanks for signing up a passcode has be sent to verify your email'
            }, status=status.HTTP_201_CREATED)
        # If error
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserEmail(GenericAPIView):
    def post(self, request):
        try:
            passcode = request.data.get('otp')
            user_pass_obj=OneTimePassword.objects.get(otp=passcode)
            user=user_pass_obj.user
            if not user.is_verified:
                user.is_verified=True
                user.save()
                return Response({
                    'message':'account email verified successfully'
                }, status=status.HTTP_200_OK)
            return Response({'message':'passcode is invalid user is already verified'}, status=status.HTTP_204_NO_CONTENT)
        except OneTimePassword.DoesNotExist as identifier:
            return Response({'message':'passcode not provided'}, status=status.HTTP_400_BAD_REQUEST)
        

class LoginUserView(GenericAPIView):
    serializer_class=LoginSerializer
    def post(self, request):
        serializer= self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetRequestView(GenericAPIView):
    serializer_class=PasswordResetRequestSerializer

    def post(self, request):
        serializer=self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response({'message':'we have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        # return Response({'message':'user with that email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
    



class PasswordResetConfirm(GenericAPIView):

    def get(self, request, uidb64, token):
        try:
            user_id=smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message':'token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success':True, 'message':'credentials is valid', 'uidb64':uidb64, 'token':token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'message':'token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordView(GenericAPIView):
    serializer_class=SetNewPasswordSerializer

    def patch(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success':True, 'message':"password reset is succesful"}, status=status.HTTP_200_OK)


class TestingAuthenticatedReq(GenericAPIView):
    permission_classes=[IsAuthenticated]

    def get(self, request):

        data={
            'msg':'its works'
        }
        return Response(data, status=status.HTTP_200_OK)

class LogoutApiView(GenericAPIView):
    serializer_class=LogoutUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
 




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


