import sqlite3
import time

# подключение к базе данных signatures.db
sig_conn = sqlite3.connect('signatures.db')
sig_cursor = sig_conn.cursor()

# подключение к базе данных с пакетами packets.db
pkt_conn = sqlite3.connect('packets.db')
pkt_cursor = pkt_conn.cursor()

# создание таблицы для хранения информации о проверенных пакетах
try:
    check_conn = sqlite3.connect('checked_packets.db')
    check_cursor = check_conn.cursor()
    check_cursor.execute('CREATE TABLE IF NOT EXISTS checked_packets (table_name TEXT, packet TEXT, signature TEXT, PRIMARY KEY(table_name, packet, signature))')
except sqlite3.Error as e:
    print(f'Error: {e.args[0]}')

# получение списка таблиц с пакетами из packets.db
table_names = []
for row in pkt_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'SNIFF_%' ORDER BY name"):
    table_names.append(row[0])

# получение списка сигнатур из signatures.db
signatures = []
for row in sig_cursor.execute("SELECT signature, name FROM signatures"):
    signatures.append((row[0], row[1]))

# проверка наличия сигнатур в каждой таблице в packets.db
for table_name in table_names:
    # проверка, была ли уже проверена данная таблица
    check_result = check_cursor.execute("SELECT COUNT(*) FROM checked_packets WHERE table_name=?", (table_name,)).fetchone()
    if check_result[0] > 0:
        continue
    # получение пакетов из таблицы в packets.db
    for row in pkt_cursor.execute(f"SELECT packet, raw_packet FROM {table_name}"):
        packet = row[0]
        raw_packet = row[1]
        # проверка, был ли уже проверен данный пакет
        check_result = check_cursor.execute("SELECT COUNT(*) FROM checked_packets WHERE table_name=? AND packet=?", (table_name, packet)).fetchone()
        if check_result[0] > 0:
            continue
        # проверка наличия сигнатур в данном пакете


# закрытие соединений с базами данных
sig_cursor.close()
sig_conn.close()
pkt_cursor.close()
pkt_conn.close()
check_cursor.close()
check_conn.close()

