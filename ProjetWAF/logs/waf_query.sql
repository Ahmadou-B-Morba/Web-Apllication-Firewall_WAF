-- transfère carrément la propriété de la table à o_user
ALTER TABLE attack_logs OWNER TO o_user;

-- 1. Créer la base de données si elle n'existe pas
CREATE DATABASE waf_bd;

-- 2. Se connecter à la base de données
/c waf_bd;

-- 3. Créer la table attack_logs avec une structure optimisée pour un WAF (Web Application Firewall)
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
    action VARCHAR(20) DEFAULT 'blocked',
    headers JSONB,
    is_obfuscated BOOLEAN DEFAULT FALSE
);

-- 4. Créer des index pour optimiser les requêtes fréquentes
CREATE INDEX IF NOT EXISTS idx_attack_logs_ip ON attack_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_logs_attack_type ON attack_logs(attack_type);
CREATE INDEX IF NOT EXISTS idx_attack_logs_session ON attack_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_risk_score ON attack_logs(risk_score);

-- 5. Créer une vue pour les statistiques par type d'attaque
CREATE OR REPLACE VIEW attack_stats_by_type AS
SELECT
    attack_type,
    COUNT(*) as total_attacks,
    AVG(risk_score) as avg_risk_score,
    MAX(timestamp) as last_occurrence
FROM attack_logs
GROUP BY attack_type
ORDER BY total_attacks DESC;

-- 6. Créer une vue pour les IPs malveillantes
CREATE OR REPLACE VIEW malicious_ips AS
SELECT
    ip_address,
    COUNT(*) as attack_count,
    MAX(timestamp) as last_attack,
    STRING_AGG(DISTINCT attack_type, ', ') as attack_types
FROM attack_logs
GROUP BY ip_address
HAVING COUNT(*) > 3
ORDER BY attack_count DESC;

-- 7. Créer une fonction pour insérer une attaque
CREATE OR REPLACE FUNCTION log_attack(
    p_ip_address VARCHAR(45),
    p_attack_type VARCHAR(100),
    p_payload TEXT,
    p_method VARCHAR(10),
    p_uri TEXT,
    p_user_agent TEXT,
    p_risk_score FLOAT DEFAULT NULL,
    p_action VARCHAR(20) DEFAULT 'blocked',
    p_headers JSONB DEFAULT NULL,
    p_is_obfuscated BOOLEAN DEFAULT FALSE
) RETURNS VOID AS $$
BEGIN
    INSERT INTO attack_logs (
        ip_address, attack_type, payload, method, uri, user_agent,
        risk_score, action, headers, is_obfuscated
    ) VALUES (
        p_ip_address, p_attack_type, p_payload, p_method, p_uri, p_user_agent,
        p_risk_score, p_action, p_headers, p_is_obfuscated
    );
END;
$$ LANGUAGE plpgsql;

-- 8. Exemple de requêtes utiles

-- Requête pour obtenir les 10 dernières attaques
SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 10;

-- Requête pour obtenir les attaques par type (pour un dashboard)
SELECT
    attack_type,
    COUNT(*) as count,
    ROUND(AVG(risk_score), 2) as avg_risk
FROM attack_logs
GROUP BY attack_type
ORDER BY count DESC;

-- Requête pour obtenir les IPs les plus actives
SELECT
    ip_address,
    COUNT(*) as attack_count,
    MAX(timestamp) as last_attack
FROM attack_logs
GROUP BY ip_address
ORDER BY attack_count DESC
LIMIT 10;

-- Requête pour obtenir les attaques récentes (dernière heure)
SELECT * FROM attack_logs
WHERE timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC;