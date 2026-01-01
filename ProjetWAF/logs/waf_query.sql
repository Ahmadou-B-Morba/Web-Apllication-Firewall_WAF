-- 1. Supprimer l'ancienne table si elle existe
DROP TABLE IF EXISTS attack_logs;
\c waf_db;
-- 2. Créer la nouvelle table avec des types de données flexibles
CREATE TABLE if not exists attack_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,       
    attack_type TEXT,             
    request_method TEXT,
    request_uri TEXT,
    payload TEXT,
    user_agent TEXT
);

-- 3. Vérification des données insérées 
SELECT * FROM attack_logs;


-- Voir le nombre d'attaques par type
SELECT attack_type, COUNT(*) as total 
FROM attack_logs 
GROUP BY attack_type 
ORDER BY total DESC;

-- Voir les 5 IPs les plus agressives
SELECT ip_address, COUNT(*) as nb_attaques 
FROM attack_logs 
GROUP BY ip_address 
ORDER BY nb_attaques DESC 
LIMIT 5;