from rest_framework import serializers
from trialsetting.models import ItemTrial

class ItemTrialSerializer(serializers.ModelSerializer):
  class Meta:
    model = ItemTrial
    fields = '__all__'