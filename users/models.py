from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken

from users.managers import UserManager

AUTH_PROVIDERS ={'email':'email', 'google':'google', 'github':'github', 'linkedin':'linkedin'}

class User(AbstractBaseUser, PermissionsMixin):
	id = models.AutoField(primary_key=True, editable=False)
	email = models.EmailField(max_length=255, unique=True, verbose_name=_("Email Address"))
	# username = models.CharField(max_length=100)
	first_name = models.CharField(max_length=100, verbose_name=_("First Name"))
	last_name = models.CharField(max_length=100, verbose_name=_("Last Name"))

	is_staff = models.BooleanField(default=False)
	is_superuser = models.BooleanField(default=False)
	is_verified=models.BooleanField(default=False)
	is_active = models.BooleanField(default=True)
	date_joined = models.DateField(auto_now_add=True)
	last_login = models.DateTimeField(auto_now=True)
	auth_provider=models.CharField(max_length=50, blank=False, null=False, default=AUTH_PROVIDERS.get('email'))
	
	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ["first_name", "last_name"]
	# REQUIRED_FIELDS = ['username']

	objects = UserManager()
  
	def tokens(self):    
		refresh = RefreshToken.for_user(self)
		return {
			"refresh": str(refresh),
			"access": str(refresh.access_token)
		}
	
	def __str__(self):
		return self.email
	
	@property
	def get_full_name(self):
  		return f"{self.first_name.title()} {self.last_name.title()}"

class OneTimePassword(models.Model):
  user=models.OneToOneField(User, on_delete=models.CASCADE)
  otp=models.CharField(max_length=6)

  def __str__(self):
  	return f"{self.user.first_name} - otp code"




