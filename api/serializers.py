from rest_framework import serializers
from trial.models import ItemTrial, DrinkTrial

class ItemTrialSerializer(serializers.ModelSerializer):
  class Meta:
    model = ItemTrial
    fields = '__all__'

class DrinkTrialSerializer(serializers.ModelSerializer):
  class Meta:
    model = DrinkTrial
    fields = ['id', 'name', 'description']
