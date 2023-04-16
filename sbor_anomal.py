from scapy.all import *
import sqlite3
import time
import pickle

# Создаем базу данных
conn = sqlite3.connect('network_info.db')
c = conn.cursor()

# Создаем таблицу для записи данных
c.execute('''CREATE TABLE IF NOT EXISTS network_data
             (timestamp INTEGER, packets INTEGER, bytes INTEGER, packet_size REAL, packet_interval REAL)''')

# Создаем таблицу для записи средних значений
c.execute('''CREATE TABLE IF NOT EXISTS avg_network_data
             (timestamp INTEGER, avg_packets REAL, avg_bytes REAL, avg_packet_size REAL, avg_packet_interval REAL)''')

max_iteral = 10
iteral = 0
start_time = time.time()

# Записываем данные в базу данных
while iteral < max_iteral and time.time() < start_time + 15:
    # Собираем информацию о сетевом трафике
    packets = sniff(count=10)
    packet_sizes = [len(packet) for packet in packets]
    packet_intervals = [packets[i+1].time - packets[i].time for i in range(len(packets)-1)]
    bytes = sum(packet_sizes)
    print(packets, packet_sizes, packet_intervals, bytes)
    # Записываем данные в базу данных
    timestamp = int(time.time())
    c.execute("INSERT INTO network_data VALUES (?, ?, ?, ?, ?)",
              (timestamp, len(packets), bytes, pickle.dumps(packet_sizes).decode('latin1'), pickle.dumps(packet_intervals).decode('latin1')))
    conn.commit()
    
    iteral += 1
    
    # Ждем 1 секунду перед повторным сбором информации
    time.sleep(1)

# Вычисляем средние значения каждого параметра
c.execute("SELECT AVG(packets), AVG(bytes), AVG(packet_size), AVG(packet_interval) FROM network_data")
result = c.fetchone()
avg_packets = result[0]
avg_bytes = result[1]
avg_packet_size = result[2]
avg_packet_interval = result[3]

# Записываем средние значения в базу данных
timestamp = int(time.time())
c.execute("INSERT INTO avg_network_data VALUES (?, ?, ?, ?, ?)",
          (timestamp, avg_packets, avg_bytes, pickle.dumps(avg_packet_size), pickle.dumps(avg_packet_interval)))
conn.commit()

# Выводим результаты
print("Среднее количество пакетов в секунду: ", avg_packets)
print("Средний объем трафика в секунду (в байтах): ", avg_bytes)
print("Среднее распределение размеров пакетов: ", avg_packet_size)
print("Средний интервал между пакетами (в секундах): ", avg_packet_interval)

# Закрываем базу данных
conn.close()

