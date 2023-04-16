import sqlite3

print("Введите название таблицы: ")

name = input()

# установка соединения с базой данных
conn = sqlite3.connect(f'{name}.db')
cursor = conn.cursor()

# получение списка таблиц в базе данных
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

# вывод списка таблиц на экран с порядковыми номерами
print("Список таблиц:")
for i, table in enumerate(tables):
    print(f"{i+1}. {table[0]}")

# запрос порядкового номера нужной таблицы у пользователя
table_num = int(input("Введите номер таблицы: "))

# выбор нужной таблицы по номеру
table_name = tables[table_num-1][0]

# запрос данных из выбранной таблицы и вывод на экран
cursor.execute(f"SELECT * FROM {table_name}")
rows = cursor.fetchall()
print(f"Данные из таблицы {table_name}:")
for row in rows:
    print(row)
    print("-"*50)
# закрытие соединения с базой данных
conn.close()

