import sqlite3
import os

# имя базы данных с сигнатурами
DATABASE_NAME = "signatures.db"

# SQL-запрос для создания таблицы с сигнатурами
CREATE_TABLE_QUERY = """
    CREATE TABLE IF NOT EXISTS signatures (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        signature TEXT NOT NULL
    );
"""

# SQL-запрос для добавления сигнатуры в таблицу
INSERT_SIGNATURE_QUERY = """
    INSERT INTO signatures (name, signature) VALUES (:name, :signature);
"""

# SQL-запрос для получения всех сигнатур из таблицы
SELECT_ALL_SIGNATURES_QUERY = """
    SELECT name, signature FROM signatures;
"""

def create_database():
    """Создает базу данных, если она не создана."""
    if not os.path.exists(DATABASE_NAME):
        try:
            connection = sqlite3.connect(DATABASE_NAME)
            cursor = connection.cursor()
            cursor.execute(CREATE_TABLE_QUERY)
            connection.commit()
            print("База данных успешно создана!")
        except sqlite3.Error as error:
            print("Ошибка создания базы данных: ", error)
        finally:
            connection.close()
    else:
        print("База данных уже существует!")

def add_signature(name, signature):
    """Добавляет сигнатуру в базу данных."""
    try:
        connection = sqlite3.connect(DATABASE_NAME)
        cursor = connection.cursor()
        cursor.execute(INSERT_SIGNATURE_QUERY, {'name': name, 'signature': signature})
        connection.commit()
        print("Сигнатура успешно добавлена!")
    except sqlite3.Error as error:
        print("Ошибка добавления сигнатуры: ", error)
    finally:
        connection.close()

def view_signatures():
    """Просматривает все сигнатуры в базе данных."""
    try:
        connection = sqlite3.connect(DATABASE_NAME)
        cursor = connection.cursor()
        cursor.execute(SELECT_ALL_SIGNATURES_QUERY)
        signatures = cursor.fetchall()
        for name, signature in signatures:
            print(f"{name}: {signature}")
    except sqlite3.Error as error:
        print("Ошибка просмотра сигнатур: ", error)
    finally:
        connection.close()

# создать базу данных, если она не создана
create_database()

while True:
    # показать меню
    print("\n=== Меню ===")
    print("1. Просмотреть сигнатуры")
    print("2. Добавить сигнатуру")
    print("3. Выход")

    # получить выбор пользователя
    choice = input("Выберите действие (1-3): ")

    if choice == "1":
        # просмотреть сигнатуры
        view_signatures()
    elif choice == "2":
        # добавить сигнатуру
        name = input("Введите название атаки: ")
        signature = input("Введите сигнатуру: ")
        add_signature(name, signature)
        print("Сигнатура успешно добавлена!")
    elif choice == "3":
        # выход из программы
        break
    else:
        print("Неверный выбор. Пожалуйста, попробуйте еще раз.") 

