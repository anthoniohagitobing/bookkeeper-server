# Generated by Django 5.0.1 on 2024-01-19 07:47

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Account',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('account_name', models.CharField(max_length=255, verbose_name='Account Name')),
                ('currency', models.CharField(max_length=5)),
                ('account_type', models.CharField(max_length=50, verbose_name='Account Type')),
                ('note', models.TextField(blank=True, max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='Record',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_type', models.CharField(max_length=10)),
                ('title', models.CharField(max_length=255)),
                ('date_time', models.DateTimeField()),
                ('category', models.CharField(max_length=50)),
                ('input_type', models.CharField(max_length=15)),
                ('amount', models.DecimalField(decimal_places=10, max_digits=19)),
                ('note', models.TextField(blank=True, max_length=200)),
            ],
        ),
    ]