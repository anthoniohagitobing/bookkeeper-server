from django.urls import path
from . import views 

urlpatterns = [
  path('', views.test),
  path('get/', views.getData),
  path('add/', views.addItem),
  path('drinks/', views.drink_list),
  path('drinks/<int:id>/', views.drink_detail)
]