from django.urls import path
from . import views
# from members.views import (
# 	UserRegistrationAPIView,
# 	UserLoginAPIView,
# 	UserViewAPI,
# 	UserLogoutViewAPI
# )

urlpatterns = [
	path('register/', views.UserRegisteration.as_view(), name='register'),
	path('login/', views.UserLogin.as_view(), name='login'),
	path('logout/', views.UserLogout.as_view(), name='logout'),
	path('view/', views.UserView.as_view(), name='user'),
]

# urlpatterns = [
# 	path('register/', UserRegistrationAPIView.as_view()),
# 	path('login/', UserLoginAPIView.as_view()),
# 	path('view/', UserViewAPI.as_view()),
# 	path('logout/', UserLogoutViewAPI.as_view()),
# ]
