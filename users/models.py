# Django and rest import
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken

# Manager import
from users.managers import UserManager

# Available auth provider object
AUTH_PROVIDERS = {'email':'email', 'google':'google', 'github':'github', 'linkedin':'linkedin'}

# User model
class User(AbstractBaseUser, PermissionsMixin):
	"""
		Custom user model where email is the unique identifiers for authentication instead of usernames.
	"""
	# Main fields. Note that password is automatically available
	id = models.AutoField(primary_key=True, editable=False)
	email = models.EmailField(max_length=255, unique=True, verbose_name=_("Email Address"))
	# username = models.CharField(max_length=100)
	first_name = models.CharField(max_length=100, verbose_name=_("First Name"))
	last_name = models.CharField(max_length=100, verbose_name=_("Last Name"))

	# Supplementary fields
	is_staff = models.BooleanField(default=False)
	is_superuser = models.BooleanField(default=False)
	is_verified=models.BooleanField(default=False)
	is_active = models.BooleanField(default=True)
	date_joined = models.DateField(auto_now_add=True)
	last_login = models.DateTimeField(auto_now=True)
	auth_provider=models.CharField(max_length=50, blank=False, null=False, default=AUTH_PROVIDERS.get('email'))
	
	# Designate email as username field, this is a unique field, used as identifier
	USERNAME_FIELD = 'email'

	# Designate required fields. Note that field used as username is not required.
	REQUIRED_FIELDS = ["first_name", "last_name"]
	# REQUIRED_FIELDS = ['username']

	# Import User manager
	objects = UserManager()
  
	# Create token function
	def tokens(self):    
		refresh = RefreshToken.for_user(self)
		return {
			"refresh": str(refresh),
			"access": str(refresh.access_token)
		}

	# Change display name in admin panel
	def __str__(self):
		return self.email
	
	# Create property field. Note this can be invoke as a property, not as a function. Ex: "User.get_full_name", instead of "User.get_full_name()"
	@property
	def get_full_name(self):
  		return f"{self.first_name.title()} {self.last_name.title()}"

# OTP model
class OneTimePassword(models.Model):
	"""
		Supplementary for user model to hold OTP. Has one to one relationship
  	"""
	# Main fields
	user=models.OneToOneField(User, on_delete=models.CASCADE)
	otp=models.CharField(max_length=6)
	
	# Change display name in admin panel
	def __str__(self):
		return f"{self.user.first_name} - otp code"




