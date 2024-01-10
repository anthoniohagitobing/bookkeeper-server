from django.db import models

# Create your models here.
class ItemTrial(models.Model):
  name = models.CharField(max_length=200)
  created = models.DateTimeField(auto_now_add=True)

# adding item
  # from trial.models import ItemTrial
  # ItemTrial.objects.create(name="Item #1")
  # ItemTrial.objects.create(name="Item #2")
  # ItemTrial.objects.create(name="Item #3")
  # items = ItemTrial.objects.all()
  # print(items)
# test

class DrinkTrial(models.Model):
  name = models.CharField(max_length=200)
  description = models.CharField(max_length=500)

  def __str__(self):
    # this allows you to apply name in the admin dashboard
    return self.name + ' ' + self.description
  
   