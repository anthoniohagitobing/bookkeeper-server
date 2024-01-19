# Rest import
from rest_framework import serializers, validators

# File import
from record.models import Account, Transaction

class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        # fields = '__all__'
        fields = ["id", "user", "account_name", "currency", "account_type", "note"]
        # validators = [
        #     validators.UniqueTogetherValidator(
        #         queryset=model.objects.all(),
        #         fields=('user', 'account_name'),
        #         message="Account name must be unique"
        #     )
        # ]
            # this is alternative method for doing unique together in validate
    
    def validate(self, attrs):
        user = attrs.get('user',None)
        account_name = attrs.get('account_name',None)

        try:
            obj = self.Meta.model.objects.get(user=user, account_name=account_name)
        except self.Meta.model.DoesNotExist:
            return attrs
        if self.instance and obj.id == self.instance.id:
            return attrs
        else:
            raise serializers.ValidationError('Account name must be unique')

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ["id", "account", "transaction_type", "title", "date_time", "category", "input_type", "amount", "note"]


    #         id = models.AutoField(primary_key=True, editable=False)
    # account = models.ForeignKey(Account, on_delete=models.CASCADE)
    # transaction_type = models.CharField(max_length=10)
    # title = models.CharField(max_length=255)
    # date_time = models.DateTimeField()
    # category = models.CharField(max_length=50)
    # input_type = models.CharField(max_length=15)
    # amount = models.DecimalField(max_digits=19, decimal_places=10)
    # note = models.TextField(max_length=200, null=False, blank=True)