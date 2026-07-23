import os
import psycopg2
import json
from datetime import datetime
from dotenv import load_dotenv
import logging
from typing import Optional, Dict, Any

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
    Établit une connexion sécurisée à la base de données PostgreSQL.
    Les identifiants sont chargés depuis les variables d'environnement.

    Returns:
        psycopg2.connection: Connexion à la base de données ou None en cas d'erreur.
    """
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME", "waf_db"),
            user=os.getenv("DB_USER", "waf_user"),
            password=os.getenv("DB_PASSWORD", ""),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432")
        )
        return conn
    except psycopg2.OperationalError as e:
        logger.error(f"❌ Échec de la connexion à PostgreSQL: {e}")
        return None

def ensure_log_directory():
    """
    Vérifie que le répertoire de logs existe, sinon le crée.
    """
    log_dir = os.path.dirname(LOCAL_LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

def sanitize_payload(payload: str, max_length: int = 1000) -> str:
    """
    Nettoie et tronque le payload pour éviter les problèmes de stockage.
    Args:
        payload (str): Payload à nettoyer.
        max_length (int): Longueur maximale autorisée.
    Returns:
        str: Payload nettoyé et tronqué.
    """
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
    payload: str,
    method: str,
    uri: str,
    user_agent: str,
    risk_score: Optional[float] = None,
    action: str = "blocked",
    session_id: Optional[str] = None
) -> bool:
    """
    Journalise une attaque détectée dans PostgreSQL et un fichier local.

    Args:
        ip (str): Adresse IP de l'attaquant.
        attack_type (str): Type d'attaque détectée.
        payload (str): Payload malveillant.
        method (str): Méthode HTTP (GET, POST, etc.).
        uri (str): URI de la requête.
        user_agent (str): User-Agent du client.
        risk_score (Optional[float]): Score de risque (0-1).
        action (str): Action prise (blocked/allowed).
        session_id (Optional[str]): ID de session pour la corrélation.

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
            logger.error("❌ Impossible de se connecter à PostgreSQL.")
            return False

        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO attack_logs
                (ip_address, attack_type, payload, method, uri, user_agent, timestamp, risk_score, action, session_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    ip,
                    attack_type,
                    sanitized_payload,
                    method,
                    uri,
                    user_agent,
                    datetime.now(),
                    risk_score,
                    action,
                    session_id
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
            "session_id": session_id
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