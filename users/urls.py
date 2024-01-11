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
	path('register/', views.UserRegister.as_view(), name='register'),
	# path('login/', views.UserLogin.as_view(), name='login'),
	# path('logout/', views.UserLogout.as_view(), name='logout'),
	# path('view/', views.UserView.as_view(), name='user'),
    
	# path('register/', RegisterView.as_view(), name='register'),
    # path('verify-email/', VerifyUserEmail.as_view(), name='verify'),
    # path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # path('login/', LoginUserView.as_view(), name='login-user'),
    # path('get-something/', TestingAuthenticatedReq.as_view(), name='just-for-testing'),
    # path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    # path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirm.as_view(), name='reset-password-confirm'),
    # path('set-new-password/', SetNewPasswordView.as_view(), name='set-new-password'),
    # path('logout/', LogoutApiView.as_view(), name='logout')
]

# urlpatterns = [
# 	path('register/', UserRegistrationAPIView.as_view()),
# 	path('login/', UserLoginAPIView.as_view()),
# 	path('view/', UserViewAPI.as_view()),
# 	path('logout/', UserLogoutViewAPI.as_view()),
# ]
