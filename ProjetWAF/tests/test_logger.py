"""Tests du module de journalisation (``logs/logger.py``).

``log_attack`` dépend d'une connexion PostgreSQL. Pour que la suite de tests
soit exécutable sans base de données, la connexion est mockée via
``unittest.mock``. Les tests couvrent :

- la sanitisation des payloads (troncature, caractères non imprimables) ;
- la création du répertoire de logs ;
- la journalisation complète (DB mockée + fichier JSONL de backup) ;
- le comportement en cas d'échec de connexion DB ;
- le format et le contenu des entrées écrites dans le fichier de backup.

Les tests nécessitant une PostgreSQL réelle sont marqués ``@pytest.mark.db``
et ignorés par défaut (``-m "not db"``).
"""
import json
import os
from unittest import mock

import pytest

from logs import logger as logger_module
from logs.logger import (
    log_attack,
    sanitize_payload,
    ensure_log_directory,
    get_db_connection,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_cursor():
    """Un faux curseur qui enregistre le SQL et les params exécutés."""
    calls = []

    class _Cursor:
        def execute(self, sql, params=None):
            calls.append({"sql": sql, "params": params})

        def close(self):
            pass

    cur = _Cursor()
    cur.calls = calls
    return cur


@pytest.fixture
def fake_conn():
    """Mock d'une connexion PostgreSQL avec un curseur simulé.

    Le curseur est créé une seule fois et réutilisé à chaque appel de
    ``cursor()`` (comme le fait un vrai psycopg2.connection), afin que
    ``fake_conn.cursor().calls`` reflète bien tous les execute() passés,
    et non un nouveau curseur vide à chaque fois.
    """
    class _Cursor:
        def __init__(self):
            self.calls = []  # Stocke les appels à execute()
            self._last_query = None

        def execute(self, query, params=None):
            self.calls.append({"query": query, "params": params})
            self._last_query = query

        def fetchone(self):
            # Simule la vérification "la fonction log_attack existe-t-elle ?"
            # faite par logs/logger.py avant de choisir INSERT direct vs
            # cur.callproc(). On simule qu'elle N'EXISTE PAS -> chemin INSERT.
            if self._last_query and "information_schema.routines" in self._last_query:
                return (False,)
            return None

        def close(self):
            pass

    class _Conn:
        def __init__(self):
            self.committed = False
            self.rolled_back = False
            self._cursor = _Cursor()

        def cursor(self):
            return self._cursor

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

        def close(self):
            pass

    return _Conn()


@pytest.fixture
def patch_log_file(monkeypatch, tmp_path):
    """Redirige LOCAL_LOG_FILE vers un fichier temporaire et le répertoire
    associé vers un dossier de test (pour ne pas polluer logs/ du projet)."""
    log_file = tmp_path / "attacks.jsonl"
    monkeypatch.setattr(logger_module, "LOCAL_LOG_FILE", str(log_file))
    return log_file


# ---------------------------------------------------------------------------
# sanitize_payload
# ---------------------------------------------------------------------------

class TestSanitizePayload:
    def test_texte_normal_inchange(self):
        assert sanitize_payload("hello world") == "hello world"

    def test_tronque_les_payloads_trop_longs(self):
        long_payload = "A" * 2000
        result = sanitize_payload(long_payload, max_length=100)
        assert len(result) <= 200
        assert result.endswith("[TRUNCATED]")
        assert result.startswith("A" * 100)

    def test_remplace_caracteres_non_imprimables(self):
        # Caractère de contrôle (ASCII 1) et tabulation (ASCII 9) -> tabulation
        # est imprimable (9 < 32 ? non, 9 < 32 donc remplacée), le test vérifie
        # que les caractères < 32 ou > 126 deviennent '?'.
        result = sanitize_payload("ok\x01\x1fok")
        assert result == "ok??ok"

    def test_garde_caracteres_imprimables_etendus(self):
        # Les caractères 32..126 sont conservés
        result = sanitize_payload("ABCabc123!@#")
        assert result == "ABCabc123!@#"

    def test_convertit_non_str_en_str(self):
        assert sanitize_payload(42) == "42"

    def test_objet_complexe_converti_en_str(self):
        result = sanitize_payload({"a": 1})
        # str(dict) contient au moins '{'
        assert "{" in result

    def test_seuil_par_defaut_1000(self):
        # Sans max_length explicite, le défaut est 1000
        result = sanitize_payload("A" * 1500)
        assert "[TRUNCATED]" in result
        # La partie conservée (avant le marqueur) fait 1000 caractères
        assert result.split(" [TRUNCATED]")[0] == "A" * 1000


# ---------------------------------------------------------------------------
# ensure_log_directory
# ---------------------------------------------------------------------------

class TestEnsureLogDirectory:
    def test_cree_le_repertoire_sil_nexiste_pas(self, monkeypatch, tmp_path):
        log_file = tmp_path / "subdir" / "attacks.jsonl"
        monkeypatch.setattr(logger_module, "LOCAL_LOG_FILE", str(log_file))
        ensure_log_directory()
        assert os.path.isdir(str(tmp_path / "subdir"))

    def test_ne_plante_pas_si_repertoire_existe_deja(self, monkeypatch, tmp_path):
        log_file = tmp_path / "attacks.jsonl"
        monkeypatch.setattr(logger_module, "LOCAL_LOG_FILE", str(log_file))
        ensure_log_directory()
        ensure_log_directory()  # deuxième appel : idempotent
        assert os.path.isdir(str(tmp_path))


# ---------------------------------------------------------------------------
# log_attack (avec DB mockée)
# ---------------------------------------------------------------------------

class TestLogAttack:
    def test_journalisation_reussit(self, monkeypatch, fake_conn, patch_log_file):
        monkeypatch.setattr(logger_module, "get_db_connection", lambda: fake_conn)

        ok = log_attack(
            ip="192.168.1.10",
            attack_type="[SQLI-001] SQL Injection",
            payload="' OR '1'='1",
            method="GET",
            uri="/login",
            user_agent="Mozilla/5.0",
        )
        assert ok is True
        assert fake_conn.committed is True
        # 2 requêtes exécutées : la vérification d'existence de la fonction
        # PostgreSQL log_attack(), puis l'INSERT direct (fonction absente ici).
        calls = fake_conn.cursor().calls
        assert len(calls) == 2
        insert_call = next(c for c in calls if "INSERT INTO attack_logs" in c["query"])
        assert insert_call["params"] is not None
        # Le fichier de backup contient une entrée JSON
        assert patch_log_file.exists()
        ligne = patch_log_file.read_text(encoding="utf-8").strip()
        entree = json.loads(ligne)
        assert entree["ip"] == "192.168.1.10"
        assert entree["attack_type"] == "[SQLI-001] SQL Injection"
        assert entree["method"] == "GET"
        assert entree["uri"] == "/login"
        assert entree["action"] == "blocked"

    def test_parametres_optionnels(self, monkeypatch, fake_conn, patch_log_file):
        monkeypatch.setattr(logger_module, "get_db_connection", lambda: fake_conn)
        ok = log_attack(
            ip="10.0.0.1",
            attack_type="test",
            payload="payload",
            method="POST",
            uri="/api",
            user_agent="UA",
            risk_score=0.87,
            action="allowed",
            session_id="sess-123",
        )
        assert ok is True
        entree = json.loads(patch_log_file.read_text(encoding="utf-8").strip())
        assert entree["risk_score"] == 0.87
        assert entree["action"] == "allowed"
        assert entree["session_id"] == "sess-123"

    def test_echec_connexion_db_retourne_false(self, monkeypatch, patch_log_file):
        monkeypatch.setattr(logger_module, "get_db_connection", lambda: None)
        ok = log_attack(
            ip="1.2.3.4",
            attack_type="x",
            payload="y",
            method="GET",
            uri="/",
            user_agent="ua",
        )
        assert ok is False
        # Aucune entrée de backup ne doit être écrite si la DB a échoué
        assert not patch_log_file.exists()

    def test_erreur_postgres_retourne_false(self, monkeypatch, patch_log_file):
        import psycopg2

        class _Conn:
            def __init__(self):
                self.rolled_back = False

            def cursor(self):
                class _Cur:
                    def execute(self, *a, **k):
                        raise psycopg2.Error("simulated insert failure")

                    def close(self):
                        pass
                return _Cur()

            def commit(self):
                pass

            def rollback(self):
                self.rolled_back = True

            def close(self):
                pass

        conn = _Conn()
        monkeypatch.setattr(logger_module, "get_db_connection", lambda: conn)
        ok = log_attack(
            ip="1.2.3.4", attack_type="x", payload="y",
            method="GET", uri="/", user_agent="ua",
        )
        assert ok is False
        assert conn.rolled_back is True

    def test_payload_sanitise_avant_ecriture(self, monkeypatch, fake_conn, patch_log_file):
        monkeypatch.setattr(logger_module, "get_db_connection", lambda: fake_conn)
        long_payload = "X" * 5000
        log_attack(
            ip="1.2.3.4", attack_type="x", payload=long_payload,
            method="GET", uri="/", user_agent="ua",
        )
        # Vérifier que le payload passé au curseur (dans l'appel INSERT,
        # pas dans la vérification d'existence de la fonction PostgreSQL
        # qui précède) est bien tronqué.
        calls = fake_conn.cursor().calls
        insert_call = next(c for c in calls if "INSERT INTO attack_logs" in c["query"])
        params = insert_call["params"]
        # params[2] est le payload (3ème colonne après ip, attack_type)
        stored_payload = params[2]
        assert "[TRUNCATED]" in stored_payload
        assert len(stored_payload) < len(long_payload)

    def test_timestamp_present_dans_backup(self, monkeypatch, fake_conn, patch_log_file):
        monkeypatch.setattr(logger_module, "get_db_connection", lambda: fake_conn)
        log_attack(
            ip="1.2.3.4", attack_type="x", payload="y",
            method="GET", uri="/", user_agent="ua",
        )
        entree = json.loads(patch_log_file.read_text(encoding="utf-8").strip())
        assert "timestamp" in entree
        # Format ISO 8601
        assert "T" in entree["timestamp"]


# ---------------------------------------------------------------------------
# get_db_connection (tests unitaires, sans serveur réel)
# ---------------------------------------------------------------------------

class TestGetDbConnection:
    def test_retourne_none_si_connexion_echoue(self, monkeypatch):
        import psycopg2

        def _raise(*a, **k):
            raise psycopg2.OperationalError("connection refused")

        monkeypatch.setattr(psycopg2, "connect", _raise)
        assert get_db_connection() is None

    def test_utilise_les_variables_denvironnement(self, monkeypatch):
        captured = {}

        import psycopg2

        def _capture(**kwargs):
            captured.update(kwargs)
            # Simuler un échec pour ne pas dépendre d'un serveur
            raise psycopg2.OperationalError("stop")

        monkeypatch.setattr(psycopg2, "connect", _capture)
        monkeypatch.setenv("DB_NAME", "ma_base")
        monkeypatch.setenv("DB_USER", "mon_user")
        monkeypatch.setenv("DB_HOST", "mon_host")
        monkeypatch.setenv("DB_PORT", "5433")
        get_db_connection()
        assert captured["dbname"] == "ma_base"
        assert captured["user"] == "mon_user"
        assert captured["host"] == "mon_host"
        assert captured["port"] == "5433"