# Generated by Django 5.0.1 on 2024-01-19 08:36

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('record', '0002_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddConstraint(
            model_name='account',
            constraint=models.UniqueConstraint(fields=('user', 'account_name'), name='unique account name for each user'),
        ),
    ]