-- 1. Supprimer l'ancienne table si elle existe
DROP TABLE IF EXISTS attack_logs;
\c waf_db;
-- 2. Créer la nouvelle table avec des types de données flexibles
CREATE TABLE IF NOT EXISTS attack_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    session_id VARCHAR(255),
    attack_type VARCHAR(100) NOT NULL,
    payload TEXT,
    method VARCHAR(10),
    uri TEXT,
    user_agent TEXT,
    risk_score FLOAT,
    action VARCHAR(20) DEFAULT 'blocked'
);


-- Index pour optimiser les requêtes
CREATE INDEX IF NOT EXISTS idx_attack_logs_ip ON attack_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_logs_attack_type ON attack_logs(attack_type);
CREATE INDEX IF NOT EXISTS idx_attack_logs_session ON attack_logs(session_id);


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