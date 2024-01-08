from django.http import JsonResponse

from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status

from trial.models import ItemTrial
from trial.models import DrinkTrial
from .serializers import ItemTrialSerializer, DrinkTrialSerializer

@api_view(['GET'])
def getData(request):
  # person = {'name':'Dennis', 'age':28}
  # return Response(person)

  items = ItemTrial.objects.all()
  serializer = ItemTrialSerializer(items, many=True)
  return Response(serializer.data)

@api_view(['POST'])
def addItem(request):
  serializer = ItemTrialSerializer(data=request.data)
  if serializer.is_valid():
    serializer.save()
  return Response(serializer.data)
                  
  # {
  #   "name":"Item created from post request"
  # }

@api_view(['GET', 'POST'])
def drink_list(request):
  # get all the drinks
  # serialize them
  # return JSON

  if request.method == 'GET':
    drinks = DrinkTrial.objects.all()
    serializer = DrinkTrialSerializer(drinks, many=True)
    return Response(serializer.data)
  
  if request.method == 'POST':
    serializer = DrinkTrialSerializer(data=request.data)
    if serializer.is_valid():
      serializer.save()
      return Response(serializer.data, status=status.HTTP_201_CREATED)

    # {
    #   "name": "Strawberry Soda",
    #   "description": "Very good"
    # }

@api_view(['GET', 'PUT', 'DELETE'])
def drink_detail(request, id):
  try:
    drink = DrinkTrial.objects.get(pk=id)
  except DrinkTrial.DoesNotExist:
    return Response(status=status.HTTP_404_NOT_FOUND)

  # to get just JSON: http://localhost:8000/trial/drinks/?format=json

  if request.method == 'GET':
    serializer = DrinkTrialSerializer(drink)
    return Response(serializer.data)
  elif request.method == 'PUT':
    serializer = DrinkTrialSerializer(drink, data=request.data)
    if serializer.is_valid():
      serializer.save()
      return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
  elif request.method == 'DELETE':
    drink.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)