from rest_framework.response import Response
from rest_framework.decorators import api_view

from trialsetting.models import ItemTrial
from .serializers import ItemTrialSerializer

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
  #   'name':'Item created from post request'
  # }