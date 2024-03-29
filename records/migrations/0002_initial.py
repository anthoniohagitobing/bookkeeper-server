# Generated by Django 5.0.1 on 2024-01-29 16:27

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('records', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='account',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='transaction',
            name='account',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='records.account'),
        ),
        migrations.AddConstraint(
            model_name='account',
            constraint=models.UniqueConstraint(fields=('user', 'account_name'), name='unique account name for each user'),
        ),
    ]
