import psycopg2

try:
    conn = psycopg2.connect(dbname="waf_db", user="postgres", password="123@mo", host="localhost")
    cur = conn.cursor()
    
    # 1. On insère un test unique
    print("Insertion d'un test spécial...")
    cur.execute("INSERT INTO attack_logs (ip_address, attack_type) VALUES ('9.9.9.9', 'VERIF_FINALE')")
    conn.commit()
    
    # 2. On relit immédiatement
    cur.execute("SELECT id, timestamp, attack_type FROM attack_logs WHERE attack_type = 'VERIF_FINALE'")
    row = cur.fetchone()
    
    if row:
        print(f"🎉 SUCCÈS ! Trouvé dans la base : ID={row[0]}, Type={row[2]}")
    else:
        print("❌ INCROYABLE : L'insertion a réussi mais la relecture est vide.")
        
    cur.close()
    conn.close()
except Exception as e:
    print(f"💥 ERREUR : {e}")