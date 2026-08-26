"""Tests d'intégration base de données (conversion de ``test_db.py``).

Ces tests vérifient que la table ``attack_logs`` accepte les insertions et
que les données sont relisibles. Ils nécessitent une instance PostgreSQL
réelle (configurée via les variables d'environnement ``DB_*``) ainsi que le
schéma défini dans ``logs/waf_query.sql``.

Comme PostgreSQL n'est pas disponible dans l'environnement de test par
défaut, ces tests sont marqués ``@pytest.mark.db`` et sont automatiquement
ignorés si la connexion échoue (``skip`` plutôt qu'échec).
"""
import os

import pytest

from dotenv import load_dotenv

load_dotenv()


def _db_disponible() -> bool:
    """Tente une connexion à PostgreSQL ; retourne True si elle réussit."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME", "waf_db"),
            user=os.getenv("DB_USER", "o_user"),
            password=os.getenv("DB_PASSWORD", ""),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432"),
        )
        conn.close()
        return True
    except Exception:
        return False


# Skip au niveau du module si aucune DB n'est joignable.
pytestmark = pytest.mark.skipif(
    not _db_disponible(),
    reason="PostgreSQL non disponible : définir les variables DB_* et appliquer logs/waf_query.sql",
)


@pytest.mark.db
def test_db_connection():
    """Vérifie qu'une connexion à la base peut être établie."""
    import psycopg2
    conn = psycopg2.connect(
        dbname=os.getenv("DB_NAME", "waf_db"),
        user=os.getenv("DB_USER", "o_user"),
        password=os.getenv("DB_PASSWORD", ""),
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
    )
    try:
        assert conn is not None
    finally:
        conn.close()


@pytest.mark.db
def test_insertion_lecture_cleanup():
    """Insère une ligne de test, la relit, puis la supprime.

    Reprend la logique du fichier ``test_db.py`` original.
    """
    import psycopg2
    conn = psycopg2.connect(
        dbname=os.getenv("DB_NAME", "waf_db"),
        user=os.getenv("DB_USER", "o_user"),
        password=os.getenv("DB_PASSWORD", ""),
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
    )
    cur = conn.cursor()
    try:
        # Insertion
        cur.execute(
            "INSERT INTO attack_logs (ip_address, attack_type) "
            "VALUES ('1.1.1.1', 'TEST')"
        )
        conn.commit()

        # Lecture
        cur.execute(
            "SELECT * FROM attack_logs WHERE ip_address = '1.1.1.1'"
        )
        row = cur.fetchone()
        assert row is not None, "Aucune ligne insérée"

        # Cleanup
        cur.execute("DELETE FROM attack_logs WHERE ip_address = '1.1.1.1'")
        conn.commit()
    finally:
        cur.close()
        conn.close()