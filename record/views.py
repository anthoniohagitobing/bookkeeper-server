# Django import
from django.shortcuts import render

# Rest framework import
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# File import 
from record.serializers import AccountSerializer
from record.models import Account, Transaction

# Create Account
class CreateAccountView(GenericAPIView):
    """
        This view creates account
    """

        
# Get Account
class CreateAccountView(GenericAPIView):
    """
        This view specifically handle creating new account
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
            # account_id = request.GET.get("account-id", "")
            queryset = self.queryset.get(id = account_id)

            # Process data with serializer and return
            serializer = self.serializer_class(queryset)
            return Response(serializer.data)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)


class FindAllAccountsView(GenericAPIView):
    serializer_class = AccountSerializer
    queryset = Account.objects

    def get(self, request, user_id):
        try:

            queryset = self.queryset.filter(user_id = user_id)
            serializer = self.serializer_class(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)

class CreateTransaction(GenericAPIView):
    serializer_class = TransactionSerializer
    queryset = Transaction.objects