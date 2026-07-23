import os
import psycopg2
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

def test_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME", "waf_db"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", ""),
            host=os.getenv("DB_HOST", "localhost")
        )
        cur = conn.cursor()

        # Test d'insertion
        cur.execute("INSERT INTO attack_logs (ip_address, attack_type) VALUES ('1.1.1.1', 'TEST')")
        conn.commit()

        # Test de lecture
        cur.execute("SELECT * FROM attack_logs WHERE ip_address = '1.1.1.1'")
        assert cur.fetchone() is not None, "Test failed: No row inserted"

        # Cleanup
        cur.execute("DELETE FROM attack_logs WHERE ip_address = '1.1.1.1'")
        conn.commit()

        print("✅ Test DB: Success")
        return True
    except Exception as e:
        print(f"❌ Test DB: Failed - {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    test_db_connection()