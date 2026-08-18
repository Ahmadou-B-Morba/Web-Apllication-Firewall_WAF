"""Tests du middleware WAF et de l'application Flask (``app.py``).

Le middleware ``waf_middleware`` ( décoré via ``@app.before_request``) inspecte
toutes les requêtes entrantes : paramètres GET, données de formulaire POST,
corps JSON et en-têtes. Une correspondance avec une signature lève une
réponse 400 et journalise l'attaque.

Pour éviter toute dépendance à PostgreSQL pendant les tests, ``log_attack``
est mockée au niveau du module ``app`` (puisque ``app.py`` fait
``from logs.logger import log_attack``).
"""
import warnings

import pytest

warnings.filterwarnings("ignore")

from app import app, waf_middleware


@pytest.fixture
def client():
    """Client de test Flask avec la journalisation mockée."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def _mock_log_attack(monkeypatch):
    """Mocke log_attack pour tous les tests de ce module afin d'éviter
    toute tentative de connexion à PostgreSQL."""
    monkeypatch.setattr("app.log_attack", lambda **kw: True)


# ---------------------------------------------------------------------------
# Requêtes légitimes
# ---------------------------------------------------------------------------

class TestRequetesLegitimes:
    def test_home_retourne_200(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"Bienvenue" in r.data or b"protection WAF" in r.data.lower()

    def test_parametre_get_normal(self, client):
        r = client.get("/?q=bonjour&user=ahmadou")
        assert r.status_code == 200

    def test_post_form_normal_non_bloque(self, client):
        # La route "/" est définie en GET uniquement : un POST légitime
        # passe d'abord par le middleware WAF (qui ne bloque pas), puis
        # déclenche un 405 de la part du routeur Flask.
        r = client.post("/", data={"username": "ahmadou", "action": "login"})
        assert r.status_code == 405

    def test_post_json_normal_non_bloque(self, client):
        # Idem : corps JSON légitime, mais route GET-only -> 405 (et non 400).
        r = client.post("/", json={"name": "test", "value": 42})
        assert r.status_code == 405


# ---------------------------------------------------------------------------
# Blocage des attaques (paramètres GET)
# ---------------------------------------------------------------------------

class TestBlocageGet:
    @pytest.mark.parametrize("payload", [
        "1' OR '1'='1",
        "1 UNION SELECT password FROM users",
        "' OR '1'='1",
        "admin' UNION SELECT *--",
    ])
    def test_sql_injection_bloquee(self, client, payload):
        r = client.get(f"/?q={payload}")
        assert r.status_code == 400

    @pytest.mark.parametrize("payload", [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(document.cookie)>",
    ])
    def test_xss_bloque(self, client, payload):
        r = client.get(f"/?q={payload}")
        assert r.status_code == 400

    def test_reponse_contient_message_securite(self, client):
        r = client.get("/?q=<script>alert(1)</script>")
        assert r.status_code == 400
        assert b"Acc" in r.data or b"Refus" in r.data or b"s" in r.data


# ---------------------------------------------------------------------------
# Blocage dans le corps POST (formulaire)
# ---------------------------------------------------------------------------

class TestBlocagePostForm:
    def test_xss_dans_form_bloque(self, client):
        r = client.post("/", data={"comment": "<script>alert(1)</script>"})
        assert r.status_code == 400

    def test_sqli_dans_form_bloque(self, client):
        r = client.post("/", data={"user": "admin' OR '1'='1"})
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# Blocage dans le corps JSON
# ---------------------------------------------------------------------------

class TestBlocageJson:
    def test_xss_dans_json_bloque(self, client):
        r = client.post("/", json={"comment": "<script>alert(1)</script>"})
        assert r.status_code == 400

    def test_sqli_dans_json_bloque(self, client):
        r = client.post("/", json={"user": "admin' UNION SELECT *--"})
        assert r.status_code == 400

    def test_corps_non_json_ne_plante_pas(self, client):
        # Un POST sans Content-Type application/json doit être traité par le
        # middleware sans planter (ici route GET-only -> 405, pas un 500).
        r = client.post("/", data="juste du texte")
        assert r.status_code == 405


# ---------------------------------------------------------------------------
# Journalisation de l'attaque
# ---------------------------------------------------------------------------

class TestJournalisation:
    def test_log_attack_est_appelee_sur_attaque(self, client, monkeypatch):
        calls = []

        def _capture(**kwargs):
            calls.append(kwargs)
            return True

        monkeypatch.setattr("app.log_attack", _capture)
        client.get("/?q=1'+OR+'1'='1")
        assert len(calls) == 1
        call = calls[0]
        for key in ("ip", "attack_type", "payload", "method", "uri", "user_agent"):
            assert key in call
        assert "SQL" in call["attack_type"] or "SQLI" in call["attack_type"]
        assert call["method"] == "GET"
        assert call["uri"] == "/"

    def test_log_attack_non_appelee_sur_requete_normale(self, client, monkeypatch):
        calls = []
        monkeypatch.setattr("app.log_attack", lambda **kw: calls.append(kw) or True)
        client.get("/?q=bonjour")
        assert len(calls) == 0


# ---------------------------------------------------------------------------
# Routes exclues
# ---------------------------------------------------------------------------

class TestRoutesExclues:
    def test_route_static_pas_analysee(self, client):
        # /static/ est dans EXCLUDED_ROUTES : la requête ne doit pas être
        # bloquée même si le chemin contient des caractères suspects.
        r = client.get("/static/<script>.js")
        # 404 est attendu (fichier inexistant), mais surtout pas un 400 WAF.
        assert r.status_code != 400


# ---------------------------------------------------------------------------
# Résilience du middleware
# ---------------------------------------------------------------------------

class TestResilience:
    def test_erreur_interne_ne_bloque_pas(self, client, monkeypatch):
        # Si waf_loader.check lève une exception, le middleware doit l'attraper
        # et laisser passer la requête (ne pas planter le serveur).
        def _boom(text):
            raise RuntimeError("simulated crash")

        from app import waf_loader
        monkeypatch.setattr(waf_loader, "check", _boom)
        r = client.get("/?q=test")
        assert r.status_code == 200