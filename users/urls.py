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
	path('register/', views.UserRegister.as_view(), name='register'),
    path('verify-email/', views.VerifyEmail.as_view(), name='verify'),
	path('login/', views.UserLogin.as_view(), name='login'),
    # path('logout/', LogoutApiView.as_view(), name='logout')
    
	# Token check
    path('check/', views.Check.as_view(), name='check'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Password reset
    path('password-reset/', views.PasswordResetRequest.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', views.PasswordResetConfirm.as_view(), name='password-reset-confirm'),
    path('set-new-password/', views.SetNewPassword.as_view(), name='set-new-password'),
]




# urlpatterns = [
# 	path('register/', UserRegistrationAPIView.as_view()),
# 	path('login/', UserLoginAPIView.as_view()),
# 	path('view/', UserViewAPI.as_view()),
# 	path('logout/', UserLogoutViewAPI.as_view()),
# ]
