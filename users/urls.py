from django.urls import path
from . import views
# from users.views import (
# 	UserRegistrationAPIView,
# 	UserLoginAPIView,
# 	UserViewAPI,
# 	UserLogoutViewAPI
# )
from rest_framework_simplejwt.views import (TokenRefreshView,)

urlpatterns = [
    # Standard auth
	path('register/', views.UserRegisterView.as_view(), name='register'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify'),
	path('login/', views.UserLoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    
	# Token check
    path('check/', views.CheckView.as_view(), name='check'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Reset Password 
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/<uidb64>/<token>/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('set-new-password/', views.SetNewPasswordView.as_view(), name='set-new-password'),
]




# urlpatterns = [
# 	path('register/', UserRegistrationAPIView.as_view()),
# 	path('login/', UserLoginAPIView.as_view()),
# 	path('view/', UserViewAPI.as_view()),
# 	path('logout/', UserLogoutViewAPI.as_view()),
# ]
