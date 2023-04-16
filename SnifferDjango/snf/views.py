from django.shortcuts import render
from .models import *
from django.http import JsonResponse
# Create your views here.
from scapy.all import sniff


def main(request):
    return render(request, "sniffer.html")


def journal(request):
    packets = Packet.objects.all()
    return render(request, "journal.html", {"packets": packets})


def anomal(request):
    return render(request, "anomal.html")


def create_portrait(request):
    max_iteral = 10
    iteral = 0
    start_time = time.time()
    # Записываем данные в базу данных
    while iteral < max_iteral and time.time() < start_time + 15:
        # Собираем информацию о сетевом трафике
        packets = sniff(count=10)
        packet_sizes = [len(packet) for packet in packets]
        packet_intervals = [packets[i + 1].time - packets[i].time for i in range(len(packets) - 1)]
        bytes = sum(packet_sizes)
        print(packets, packet_sizes, packet_intervals, bytes)
        network_info = NetworkInfo.objects.create(packets=len(packets),
                                                  packsets_bytes=bytes,
                                                  packets_size=pickle.dumps(packet_sizes).decode('latin1'),
                                                  packets_interval=pickle.dumps(packet_intervals).decode('latin1'))

        iteral += 1

        # Ждем 1 секунду перед повторным сбором информации
        time.sleep(1)

    # Вычисляем средние значения каждого параметра

    # avg_packets = result[0]
    # avg_bytes = result[1]
    # avg_packet_size = result[2]
    # avg_packet_interval = result[3]
    #
    # # Записываем средние значения в базу данных
    # timestamp = int(time.time())
    #
    # # Выводим результаты
    # print("Среднее количество пакетов в секунду: ", avg_packets)
    # print("Средний объем трафика в секунду (в байтах): ", avg_bytes)
    # print("Среднее распределение размеров пакетов: ", avg_packet_size)
    # print("Средний интервал между пакетами (в секундах): ", avg_packet_interval)
    return JsonResponse({"ok": "ok"})


def show_portrait(request):
    last_network_info = NetworkInfo.objects.last()
    return JsonResponse({"data": {"date": last_network_info.date,
                                  "packets": last_network_info.packets,
                                  "bytes": last_network_info.packets_bytes,
                                  "size": last_network_info.packets_size,
                                  "interval": last_network_info.packets_interval}})
