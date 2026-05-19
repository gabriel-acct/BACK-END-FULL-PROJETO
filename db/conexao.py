import mysql.connector
from settings import HOST, USER, PORT, PASSWORD, DB, require_db_config

def conexao():
    require_db_config()
    try:
        conn = mysql.connector.connect(
            host=HOST,
            user=USER,
            port=PORT,
            password=PASSWORD,
            database=DB
        )
        return conn
    except mysql.connector.Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

