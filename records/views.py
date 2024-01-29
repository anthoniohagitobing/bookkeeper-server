# Django import
from django.shortcuts import render
from django.db.models import Sum

# Rest framework import
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status

# File import 
from records.serializers import AccountSerializer, TransactionSerializer
from records.models import Account, Transaction

# Create Account
class CreateAccountView(GenericAPIView):
    """
        This view creates account
    """

        
# Get Account
class CreateAccountView(GenericAPIView):
    """
        This view handle creating new account
    """
    serializer_class = AccountSerializer
    
    def post(self, request):
        account = request.data

        # Assign serializer
        serializer = self.serializer_class(data=account)

        # Invoke validation method, use raise_exception to throw error if validation fail
        if serializer.is_valid(raise_exception=True):
            # Run save method 
            serializer.save()

            # Return success message
            return Response({
                "messsage": "account successfully created"
            }, status=status.HTTP_201_CREATED)
    
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            # this is not required as it already has raise_exception
        
class FindAccountView(GenericAPIView):
    """
        This view handles account manipulation
    """
    serializer_class = AccountSerializer
    queryset = Account.objects

    def get(self, request, account_id):
        """
            This path allows detail search on one specific account
        """
        try:
            # Set query, process data with serializer and return
            queryset = self.queryset.get(id = account_id)
            serializer = self.serializer_class(queryset)

            return Response(serializer.data)
        except:
            # Return error if account id is invalid
            return Response(status=status.HTTP_404_NOT_FOUND)


class FindAllAccountsView(GenericAPIView):
    """
        This view will return all account belonging to a user id
    """
    serializer_class = AccountSerializer
    queryset = Account.objects

    def get(self, request, user_id):
        try:
            # Get all account and serialized 
            queryset = self.queryset.filter(user_id = user_id)
            serializer = self.serializer_class(queryset, many=True)

            # Get balance and create a new account summary
            # print(serializer.data)
            new_accounts = []
            for account in serializer.data:
                #  Find total sum of transaction
                balance = Transaction.objects.filter(account_id = account['id']).values('account_id').annotate(total=Sum('amount'))
                print(balance[0]['total'])
                new_account = {}
                new_account['id'] = account['id']
                new_account['account_name'] = account['account_name']
                new_account['currency'] = account['currency']
                new_account['account_type'] = account['account_type']
                new_account['balance'] = float(balance[0]['total'])
                new_accounts.append(new_account)
            # print(new_accounts)
                
            return Response(new_accounts, status=status.HTTP_200_OK)

        except:
            # Return error if user id is invalid
            return Response(status=status.HTTP_404_NOT_FOUND)

class CreateTransactionView(GenericAPIView):
    """
        This view handle creating new transaction
    """
    serializer_class = TransactionSerializer

    def post(self, request):
        transaction = request.data

        # Assign serializer
        serializer = self.serializer_class(data=transaction)

        # Invoke validation method, use raise_exception to throw error if validation fail
        if serializer.is_valid(raise_exception=True):
            # Run save method 
            serializer.save()

            # Return success message
            return Response({
                "messsage": "transaction successfully recorded"
            }, status=status.HTTP_201_CREATED)
        
class FindAllTransactionsView(GenericAPIView):
    """
        This view will return all transaction belonging to an account id
    """
    serializer_class = TransactionSerializer
    queryset = Transaction.objects

    def get(self, request, account_id):
        try:
            # Get all account and serialized 
            queryset = self.queryset.filter(account_id = account_id).order_by('-date_time')
            serializer = self.serializer_class(queryset, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except:
            # Return error if user id is invalid
            return Response(status=status.HTTP_404_NOT_FOUND)