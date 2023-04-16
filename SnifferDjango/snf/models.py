from enum import auto

from django.db import models


# Create your models here.

class SniffRun(models.Model):
    start_time = models.DateTimeField(auto_now=True, verbose_name="Время запуска сниффера")

    class Meta:
        verbose_name = "Запуск сниффера"
        verbose_name_plural = "Запуски сниффера"

    def __str__(self):
        return f"Запуск сниффера в {self.start_time}"


class Packet(models.Model):
    start_sniffer = models.ForeignKey(SniffRun, on_delete=models.CASCADE, verbose_name="Старт снифера")
    date = models.DateTimeField(verbose_name="Время получения пакета")
    packet = models.TextField(verbose_name="Декодированный пакет")
    raw_packet = models.TextField(verbose_name="Сырой пакет")

    class Meta:
        verbose_name = "Пакет"
        verbose_name_plural = "Пакеты"

    def __str__(self):
        return f"Пакет {self.date.strftime('%m/%d/%Y, %H:%M:%S')}"


class Signature(models.Model):
    name = models.CharField(max_length=255, verbose_name="Название сигнатуры")
    signature = models.TextField(verbose_name="Сигнатура")

    class Meta:
        verbose_name = "Сигнатура"
        verbose_name_plural = "Сигнатуры"

    def __str__(self):
        return self.name


class NetworkInfo(models.Model):
    date = models.DateTimeField(auto_now=True)
    packets = models.IntegerField(verbose_name="Количество пакетов")
    packets_bytes = models.IntegerField(verbose_name="Общее количество байт")
    packets_size = models.DecimalField(decimal_places=50, max_digits=100, verbose_name="Длина пакетов")
    packets_interval = models.DecimalField(decimal_places=50, max_digits=100, verbose_name="Интервал между пакетами")

    class Meta:
        verbose_name = "Информация о сети"
        verbose_name_plural = "Информации о сети"

    def __str__(self):
        return self.date.strftime("%m/%d/%Y, %H:%M:%S")


class AvgNetworkInfo(models.Model):
    date = models.DateTimeField(auto_now=True)
    packets = models.IntegerField(verbose_name="Количество пакетов")
    packets_bytes = models.IntegerField(verbose_name="Общее количество байт")
    packets_size = models.DecimalField(decimal_places=50, max_digits=100, verbose_name="Длина пакетов")
    packets_interval = models.DecimalField(decimal_places=50, max_digits=100, verbose_name="Интервал между пакетами")

    class Meta:
        verbose_name = "Среднее значения информация о сети"
        verbose_name_plural = "Среднее значения информация о сети"

    def __str__(self):
        return self.date


class CheckedPackets(models.Model):
    packet = models.ForeignKey(Packet, on_delete=models.CASCADE)
    signature = models.ForeignKey(Signature, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Обнаруженные сигнатуры"
        verbose_name_plural = "Обнаруженные сигнатуры"

    def __str__(self):
        return f"{self.packet} - {self.signature}"
