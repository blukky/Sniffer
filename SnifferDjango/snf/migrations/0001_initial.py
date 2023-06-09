# Generated by Django 4.2 on 2023-04-16 19:31

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AvgNetworkInfo",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("date", models.DateTimeField(auto_now=True)),
                ("packets", models.IntegerField(verbose_name="Количество пакетов")),
                (
                    "packets_bytes",
                    models.IntegerField(verbose_name="Общее количество байт"),
                ),
                (
                    "packets_size",
                    models.DecimalField(
                        decimal_places=50, max_digits=100, verbose_name="Длина пакетов"
                    ),
                ),
                (
                    "packets_interval",
                    models.DecimalField(
                        decimal_places=50,
                        max_digits=100,
                        verbose_name="Интервал между пакетами",
                    ),
                ),
            ],
            options={
                "verbose_name": "Среднее значения информация о сети",
                "verbose_name_plural": "Среднее значения информация о сети",
            },
        ),
        migrations.CreateModel(
            name="NetworkInfo",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("date", models.DateTimeField(auto_now=True)),
                ("packets", models.IntegerField(verbose_name="Количество пакетов")),
                (
                    "packets_bytes",
                    models.IntegerField(verbose_name="Общее количество байт"),
                ),
                (
                    "packets_size",
                    models.DecimalField(
                        decimal_places=50, max_digits=100, verbose_name="Длина пакетов"
                    ),
                ),
                (
                    "packets_interval",
                    models.DecimalField(
                        decimal_places=50,
                        max_digits=100,
                        verbose_name="Интервал между пакетами",
                    ),
                ),
            ],
            options={
                "verbose_name": "Информация о сети",
                "verbose_name_plural": "Информации о сети",
            },
        ),
        migrations.CreateModel(
            name="Signature",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "name",
                    models.CharField(max_length=255, verbose_name="Название сигнатуры"),
                ),
                ("signature", models.TextField(verbose_name="Сигнатура")),
            ],
            options={
                "verbose_name": "Сигнатура",
                "verbose_name_plural": "Сигнатуры",
            },
        ),
        migrations.CreateModel(
            name="SniffRun",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "start_time",
                    models.DateTimeField(
                        auto_now=True, verbose_name="Время запуска сниффера"
                    ),
                ),
            ],
            options={
                "verbose_name": "Запуск сниффера",
                "verbose_name_plural": "Запуски сниффера",
            },
        ),
        migrations.CreateModel(
            name="Packet",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("date", models.DateTimeField(verbose_name="Время получения пакета")),
                ("packet", models.TextField(verbose_name="Декодированный пакет")),
                ("raw_packet", models.TextField(verbose_name="Сырой пакет")),
                (
                    "start_sniffer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="snf.sniffrun",
                        verbose_name="Старт снифера",
                    ),
                ),
            ],
            options={
                "verbose_name": "Пакет",
                "verbose_name_plural": "Пакеты",
            },
        ),
        migrations.CreateModel(
            name="CheckedPackets",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "packet",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="snf.packet"
                    ),
                ),
                (
                    "signature",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="snf.signature"
                    ),
                ),
            ],
            options={
                "verbose_name": "Обнаруженные сигнатуры",
                "verbose_name_plural": "Обнаруженные сигнатуры",
            },
        ),
    ]
