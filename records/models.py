from django.db import models
from users.models import User

# Create your models here.
class Account(models.Model):
    def __str__(self):
        return self.account_name
    
    id = models.AutoField(primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    account_name = models.CharField(max_length=255, verbose_name="Account Name")
    currency = models.CharField(max_length=5)
    account_type = models.CharField(max_length=50, verbose_name="Account Type")
    note = models.TextField(max_length=200, null=False, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "account_name"], name='unique account name for each user')
        ]

class Transaction(models.Model):
    def __str__(self):
        return self.transaction_type
    
    id = models.AutoField(primary_key=True, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    transaction_type = models.CharField(max_length=10)
    title = models.CharField(max_length=255)
    date_time = models.DateTimeField()
    category = models.CharField(max_length=50)
    input_type = models.CharField(max_length=15)
    amount = models.DecimalField(max_digits=19, decimal_places=10)
    note = models.TextField(max_length=200, null=False, blank=True)
