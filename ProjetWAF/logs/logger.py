import os
import psycopg2
import json
from datetime import datetime
from dotenv import load_dotenv
import logging
from typing import Optional, Dict, Any, Union

# Charger les variables d'environnement
load_dotenv()

# Configurer le logging pour les erreurs
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='logs/waf_logger_errors.log'
)
logger = logging.getLogger(__name__)

# Chemin du fichier de backup local
LOCAL_LOG_FILE = "logs/attacks.jsonl"

def get_db_connection():
    """
    Établit une connexion sécurisée à la base de données PostgreSQL waf_bd.
    Les identifiants sont chargés depuis les variables d'environnement.

    Returns:
        psycopg2.connection: Connexion à la base de données ou None en cas d'erreur.
    """
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME", "waf_bd"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432")
        )
        return conn
    except psycopg2.OperationalError as e:
        logger.error(f"❌ Échec de la connexion à PostgreSQL (waf_bd): {e}")
        return None

def ensure_log_directory():
    """
    Vérifie que le répertoire de logs existe, sinon le crée.
    """
    log_dir = os.path.dirname(LOCAL_LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

def sanitize_payload(payload: Union[str, bytes, None], max_length: int = 1000) -> str:
    """
    Nettoie et tronque le payload pour éviter les problèmes de stockage.
    Args:
        payload (str/bytes/None): Payload à nettoyer.
        max_length (int): Longueur maximale autorisée.
    Returns:
        str: Payload nettoyé et tronqué.
    """
    if payload is None:
        return ""

    if isinstance(payload, bytes):
        try:
            payload = payload.decode('utf-8', errors='replace')
        except Exception:
            payload = str(payload)

    if not isinstance(payload, str):
        payload = str(payload)

    # Tronquer si trop long
    if len(payload) > max_length:
        payload = payload[:max_length] + " [TRUNCATED]"

    # Remplacer les caractères non imprimables
    payload = ''.join(c if 32 <= ord(c) <= 126 else '?' for c in payload)
    return payload

def log_attack(
    ip: str,
    attack_type: str,
    payload: Union[str, bytes, None] = None,
    method: Optional[str] = None,
    uri: Optional[str] = None,
    user_agent: Optional[str] = None,
    risk_score: Optional[float] = None,
    action: str = "blocked",
    session_id: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    is_obfuscated: bool = False
) -> bool:
    """
    Journalise une attaque détectée dans PostgreSQL (waf_bd) et un fichier local.
    Utilise la fonction PostgreSQL `log_attack` si elle existe, sinon INSERT direct.

    Args:
        ip (str): Adresse IP de l'attaquant.
        attack_type (str): Type d'attaque détectée.
        payload (str/bytes/None): Payload malveillant.
        method (Optional[str]): Méthode HTTP (GET, POST, etc.).
        uri (Optional[str]): URI de la requête.
        user_agent (Optional[str]): User-Agent du client.
        risk_score (Optional[float]): Score de risque (0-1).
        action (str): Action prise (blocked/allowed).
        session_id (Optional[str]): ID de session pour la corrélation.
        headers (Optional[Dict]): Headers HTTP de la requête.
        is_obfuscated (bool): Indique si le payload est obfusqué.

    Returns:
        bool: True si la journalisation a réussi, False sinon.
    """
    try:
        ensure_log_directory()  # S'assurer que le répertoire existe

        # Nettoyer le payload
        sanitized_payload = sanitize_payload(payload)

        # Préparer les données pour PostgreSQL
        conn = get_db_connection()
        if conn is None:
            logger.error("❌ Impossible de se connecter à PostgreSQL (waf_bd).")
            return False

        cur = conn.cursor()
        try:
            # Vérifier si la fonction log_attack existe
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.routines
                    WHERE routine_schema = 'public'
                    AND routine_name = 'log_attack'
                );
            """)
            use_function = cur.fetchone()[0]

            if use_function:
                # Appeler la fonction PostgreSQL
                cur.callproc('log_attack', [
                    ip,
                    attack_type,
                    sanitized_payload,
                    method,
                    uri,
                    user_agent,
                    risk_score,
                    action,
                    headers,
                    is_obfuscated
                ])
            else:
                # INSERT direct si la fonction n'existe pas
                cur.execute(
                    """
                    INSERT INTO attack_logs
                    (ip_address, attack_type, payload, method, uri, user_agent, risk_score, action, session_id, headers, is_obfuscated)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        ip,
                        attack_type,
                        sanitized_payload,
                        method,
                        uri,
                        user_agent,
                        risk_score,
                        action,
                        session_id,
                        json.dumps(headers) if headers else None,
                        is_obfuscated
                    )
                )
            conn.commit()
        except psycopg2.Error as e:
            conn.rollback()
            logger.error(f"❌ Erreur PostgreSQL: {e}")
            return False
        finally:
            cur.close()
            conn.close()

        # Sauvegarder dans un fichier local (backup)
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "attack_type": attack_type,
            "payload": sanitized_payload,
            "method": method,
            "uri": uri,
            "user_agent": user_agent,
            "risk_score": risk_score,
            "action": action,
            "session_id": session_id,
            "headers": headers,
            "is_obfuscated": is_obfuscated
        }

        try:
            with open(LOCAL_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except IOError as e:
            logger.error(f"❌ Impossible d'écrire dans {LOCAL_LOG_FILE}: {e}")
            return False

        return True

    except Exception as e:
        logger.error(f"❌ Erreur inattendue lors de la journalisation: {e}")
        return False

def get_attack_stats(limit: int = 10) -> Dict[str, Any]:
    """
    Récupère les statistiques des attaques depuis la base de données.

    Args:
        limit (int): Nombre maximum de résultats à retourner.

    Returns:
        Dict[str, Any]: Statistiques des attaques (par type et par IP).
    """
    stats = {
        "by_type": [],
        "by_ip": [],
        "recent": []
    }

    conn = get_db_connection()
    if conn is None:
        logger.error("❌ Impossible de se connecter à PostgreSQL pour les stats.")
        return stats

    cur = conn.cursor()
    try:
        # Statistiques par type d'attaque
        cur.execute("""
            SELECT
                attack_type,
                COUNT(*) as count,
                AVG(risk_score) as avg_risk,
                MAX(timestamp) as last_occurrence
            FROM attack_logs
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT %s
        """, (limit,))
        stats["by_type"] = cur.fetchall()

        # Statistiques par IP
        cur.execute("""
            SELECT
                ip_address,
                COUNT(*) as attack_count,
                MAX(timestamp) as last_attack,
                STRING_AGG(DISTINCT attack_type, ', ') as attack_types
            FROM attack_logs
            GROUP BY ip_address
            ORDER BY attack_count DESC
            LIMIT %s
        """, (limit,))
        stats["by_ip"] = cur.fetchall()

        # Attacks récentes
        cur.execute("""
            SELECT * FROM attack_logs
            ORDER BY timestamp DESC
            LIMIT %s
        """, (limit,))
        stats["recent"] = cur.fetchall()

    except psycopg2.Error as e:
        logger.error(f"❌ Erreur lors de la récupération des stats: {e}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return stats

def get_malicious_ips(limit: int = 5) -> list:
    """
    Récupère les IPs malveillantes les plus actives.

    Args:
        limit (int): Nombre maximum d'IPs à retourner.

    Returns:
        list: Liste des IPs malveillantes avec leurs stats.
    """
    conn = get_db_connection()
    if conn is None:
        logger.error("❌ Impossible de se connecter à PostgreSQL pour les IPs malveillantes.")
        return []

    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT
                ip_address,
                COUNT(*) as attack_count,
                MAX(timestamp) as last_attack,
                STRING_AGG(DISTINCT attack_type, ', ') as attack_types
            FROM attack_logs
            GROUP BY ip_address
            HAVING COUNT(*) > 1
            ORDER BY attack_count DESC
            LIMIT %s
        """, (limit,))
        return cur.fetchall()
    except psycopg2.Error as e:
        logger.error(f"❌ Erreur lors de la récupération des IPs malveillantes: {e}")
        return []
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()