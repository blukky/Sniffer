# Generated by Django 4.2 on 2023-04-23 17:43

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("snf", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="packet",
            name="date",
            field=models.DateTimeField(
                auto_now=True, verbose_name="Время получения пакета"
            ),
        ),
    ]
