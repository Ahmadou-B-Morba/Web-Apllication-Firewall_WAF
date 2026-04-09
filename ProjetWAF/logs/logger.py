import psycopg2
from datetime import datetime
import os

def log_attack(ip, attack_type, payload, method, uri, user_agent):
    conn = None
    try:
        # Connexion à la base de données
        conn = psycopg2.connect(
            dbname="waf_db",
            user="postgres",
            password="123@mo",
            host="localhost",
            port="5432"
        )
        cur = conn.cursor()

        # Requête d'insertion
        insert_query = """
        INSERT INTO attack_logs (ip_address, attack_type, payload, request_method, request_uri, user_agent)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        # On force la conversion en string pour éviter les erreurs de format SQL
        cur.execute(insert_query, (
            str(ip), 
            str(attack_type), 
            str(payload), 
            str(method), 
            str(uri), 
            str(user_agent)
        ))
        
        conn.commit()
        cur.close()
        print(f"✅ [LOG DB] Menace enregistrée : {attack_type}")

    except Exception as e:
        print(f"❌ [ERREUR DB] Échec de l'insertion : {e}")
        
        # --- SYSTÈME DE SECOURS (LOG FICHIER) ---
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        with open(os.path.join(log_dir, "fallback_logs.txt"), "a", encoding="utf-8") as f:
            f.write(f"--- {datetime.now()} ---\n")
            f.write(f"IP: {ip} | Type: {attack_type} | URI: {uri}\n")
            f.write(f"Payload: {payload}\n")
            f.write("-" * 30 + "\n")
    
    finally:
        if conn:
            conn.close()

# TEST : Exécution directe pour validation
if __name__ == "__main__":
    print("🚀 Test du logger en cours...")
    log_attack(
        "127.0.0.1", 
        "TEST_VINAL_FINAL", 
        "<script>alert('test')</script>", 
        "POST", 
        "/login", 
        "TestBot/1.0"
    )