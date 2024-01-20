from django.urls import path
from . import views

urlpatterns = [
    path("account/", views.CreateAccountView.as_view(), name="create-account"),
    path("account/<int:account_id>/", views.FindAccountView.as_view(), name="find-account"),
    path("accounts/<int:user_id>/", views.FindAllAccountsView.as_view(), name="find-all-accounts"),
    path("transaction/", views.CreateTransactionView.as_view(), name="create-transaction"),
    path("transactions/<int:account_id>", views.FindAllTransactionsView.as_view(), name="find-all-transactions"),

]