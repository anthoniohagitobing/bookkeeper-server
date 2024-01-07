from django.db import models

# Create your models here.
class ItemTrial(models.Model):
  name = models.CharField(max_length=200)
  created = models.DateTimeField(auto_now_add=True)

# adding item
  # from trialsetting.models import ItemTrial
  # ItemTrial.objects.create(name="Item #1")
  # ItemTrial.objects.create(name="Item #2")
  # ItemTrial.objects.create(name="Item #3")
  # items = ItemTrial.objects.all()
  # print(items)