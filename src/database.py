import sqlite3

DB_PATH = "database/nidrs.db"

def create_database():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            signature TEXT,
            severity INTEGER,
            signature_id INTEGER,
            event_key TEXT UNIQUE
        )
    """)

    cursor.execute("PRAGMA table_info(alerts)")
    columns = [column[1] for column in cursor.fetchall()]

    if "event_key" not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN event_key TEXT")

    connection.commit()
    connection.close()

    print("NIDRS database updated successfully.")

if __name__ == "__main__":
    create_database()
