from django.contrib.auth.base_user import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
	"""
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
  """
	def email_validator(self, email):
		try:
			validate_email(email)
		except ValidationError:
			ValueError(_("please enter a valid email address"))

	def create_user(self, email, first_name, last_name, password, **extra_fields):
		"""
      Create and save a user with the given email and password.
    """
		if email:
			email = self.normalize_email(email)
			self.email_validator(email)
		else:
			raise ValueError(_('A user email is required.'))

		if not password:
			raise ValueError(_('A user password is required.'))
		if not first_name:
			raise ValueError(_("First name is required"))
		if not last_name:
			raise ValueError(_("Last name is required"))

		user = self.model(email=email, first_name=first_name, last_name=last_name, **extra_fields)
		user.set_password(password)
		user.save(using=self._db)
		return user

	def create_superuser(self, email, first_name, last_name, password, **extra_fields):
		"""
      Create and save a SuperUser with the given email and password.
			This create extra fields, and then send it to create user function
    """
		extra_fields.setdefault("is_staff", True)
		extra_fields.setdefault("is_superuser", True)
		extra_fields.setdefault("is_active", True)
		
		if extra_fields.get("is_staff") is not True:
			raise ValueError(_("Superuser must have is_staff=True."))
		if extra_fields.get("is_superuser") is not True:
			raise ValueError(_("Superuser must have is_superuser=True."))
		
		superuser = self.create_user(email, first_name, last_name, password, **extra_fields)
		superuser.save(using=self._db)
		return superuser

		# if not email:
		# 	raise ValueError('A user email is needed.')

		# if not password:
		# 	raise ValueError('A user password is needed.')

		# user = self.create_user(email, password)
		# user.is_superuser = True
		# user.is_staff = True
		# user.is_active = True
		# user.save()
		# return user