"""Tests du proxy inverse WAF (``proxy/transporteur.py``).

Le proxy reçoit les requêtes sur ``/<path>``, applique le middleware WAF
(``waf_middleware`` importé depuis ``app.py``) puis transmet la requête au
backend via ``requests.request(...)``. Comme le backend n'est pas disponible
en environnement de test, ``requests.request`` est mocké.

``log_attack`` (appelé par le middleware WAF quand une attaque est détectée)
est également mockée pour éviter toute dépendance à PostgreSQL.
"""
import warnings
from unittest import mock

import pytest
import requests

warnings.filterwarnings("ignore")

from proxy.transporteur import (
    app,
    BACKEND_URL,
    TIMEOUT,
    MAX_CONTENT_LENGTH,
    EXCLUDED_HEADERS,
    filter_headers,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class FakeResponse:
    """Simulation d'un objet requests.Response."""

    def __init__(self, content=b"ok", status_code=200, headers=None):
        self.content = content
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/plain"}


@pytest.fixture
def fake_request(monkeypatch):
    """Mocke requests.request et retourne un traqueur d'appels."""
    calls = []

    def _fake_request(**kwargs):
        calls.append(kwargs)
        return FakeResponse()

    monkeypatch.setattr("proxy.transporteur.requests.request", _fake_request)
    return calls


@pytest.fixture
def client(fake_request, monkeypatch):
    """Client de test Flask avec le backend mocké et la journalisation mockée."""
    app.config["TESTING"] = True
    # Évite l'interaction avec PostgreSQL lors du blocage d'attaques.
    monkeypatch.setattr("app.log_attack", lambda **kw: True)
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Constantes de configuration
# ---------------------------------------------------------------------------

class TestConfiguration:
    def test_backend_url_definie(self):
        assert BACKEND_URL.startswith("http://")

    def test_timeout_positif(self):
        assert TIMEOUT > 0

    def test_max_content_length_raisonnable(self):
        assert MAX_CONTENT_LENGTH > 0
        # 16 Mo par défaut
        assert MAX_CONTENT_LENGTH == 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# filter_headers
# ---------------------------------------------------------------------------

class TestFilterHeaders:
    def test_supprime_les_headers_exclus(self):
        headers = {
            "Host": "example.com",
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
            "Connection": "keep-alive",
            "X-Custom": "value",
        }
        filtered = filter_headers(headers)
        for h in EXCLUDED_HEADERS:
            assert h not in filtered, f"{h} n'aurait pas dû être conservé"
        assert "X-Custom" in filtered

    def test_conserve_les_headers_autorises(self):
        headers = {"Authorization": "Bearer token", "Accept": "application/json"}
        filtered = filter_headers(headers)
        assert filtered == headers

    def test_dict_vide_retourne_dict_vide(self):
        assert filter_headers({}) == {}


# ---------------------------------------------------------------------------
# Transmission au backend (proxy normal)
# ---------------------------------------------------------------------------

class TestTransmission:
    def test_get_transmet_au_backend(self, client, fake_request):
        r = client.get("/api/users")
        assert r.status_code == 200
        assert len(fake_request) == 1
        call = fake_request[0]
        assert call["method"] == "GET"
        assert call["url"] == f"{BACKEND_URL}/api/users"
        assert call["timeout"] == TIMEOUT

    def test_renvoie_le_contenu_et_statut_du_backend(self, client, monkeypatch):
        monkeypatch.setattr(
            "proxy.transporteur.requests.request",
            lambda **kw: FakeResponse(content=b"hello", status_code=201),
        )
        r = client.get("/api/data")
        assert r.status_code == 201
        assert r.data == b"hello"

    def test_post_transmet_le_body(self, client, fake_request):
        r = client.post("/api/submit", data={"field": "value"})
        assert r.status_code == 200
        call = fake_request[0]
        assert call["method"] == "POST"
        assert "data" in call

    def test_get_nenvoie_pas_de_body(self, client, fake_request):
        client.get("/api/users")
        call = fake_request[0]
        # GET/HEAD ne doivent pas avoir de body
        assert "data" not in call

    def test_headers_exclus_filtres_avant_transmission(self, client, fake_request):
        client.get("/api/users", headers={"Host": "evil", "X-Test": "1"})
        call = fake_request[0]
        assert "Host" not in call["headers"]
        assert call["headers"].get("X-Test") == "1"

    def test_pas_de_redirects(self, client, fake_request):
        client.get("/api/users")
        assert fake_request[0]["allow_redirects"] is False


# ---------------------------------------------------------------------------
# Protection WAF (le middleware bloque avant le proxy)
# ---------------------------------------------------------------------------

class TestProtectionWAF:
    def test_xss_bloque_avant_transmission(self, client, fake_request):
        r = client.get("/api/users?q=<script>alert(1)</script>")
        assert r.status_code == 400
        # Le backend n'a jamais été appelé
        assert len(fake_request) == 0

    def test_sqli_bloque_avant_transmission(self, client, fake_request):
        r = client.get("/api/users?q=1'+OR+'1'='1")
        assert r.status_code == 400
        assert len(fake_request) == 0

    def test_requete_normale_atteint_le_backend(self, client, fake_request):
        r = client.get("/api/users?q=bonjour")
        assert r.status_code == 200
        assert len(fake_request) == 1


# ---------------------------------------------------------------------------
# Gestion des erreurs backend
# ---------------------------------------------------------------------------

class TestErreursBackend:
    def test_timeout_retourne_504(self, client, monkeypatch):
        def _timeout(**kw):
            raise requests.exceptions.Timeout("timeout")
        monkeypatch.setattr("proxy.transporteur.requests.request", _timeout)
        r = client.get("/api/users")
        assert r.status_code == 504
        assert b"timeout" in r.data.lower()

    def test_connexion_refusee_retourne_502(self, client, monkeypatch):
        def _conn_err(**kw):
            raise requests.exceptions.ConnectionError("refused")
        monkeypatch.setattr("proxy.transporteur.requests.request", _conn_err)
        r = client.get("/api/users")
        assert r.status_code == 502
        assert b"unavailable" in r.data.lower()

    def test_erreur_generique_retourne_500(self, client, monkeypatch):
        def _err(**kw):
            raise requests.exceptions.RequestException("boom")
        monkeypatch.setattr("proxy.transporteur.requests.request", _err)
        r = client.get("/api/users")
        assert r.status_code == 500
        assert b"proxy error" in r.data.lower()


# ---------------------------------------------------------------------------
# Gestionnaires d'erreurs
# ---------------------------------------------------------------------------

class TestHandlers:
    def test_handler_404(self, client):
        # Une route inconnue sans path (impossible via /<path:path> qui capture
        # tout) : on teste directement le handler via le contexte d'app.
        with app.test_request_context("/route-qui-nexiste-pas-sans-slash"):
            from proxy.transporteur import not_found
            resp = not_found(None)
            assert resp[1] == 404

    def test_handler_429_ratelimit(self):
        # jsonify() nécessite un contexte d'application.
        from proxy.transporteur import ratelimit_handler
        with app.app_context():
            resp = ratelimit_handler(None)
        assert resp[1] == 429
        body = resp[0].get_json()
        assert "error" in body

    def test_handler_413_payload_trop_grand(self):
        from proxy.transporteur import content_too_large
        with app.app_context():
            resp = content_too_large(None)
        assert resp[1] == 413
        body = resp[0].get_json()
        assert "Payload too large" in body.get("error", "")


# ---------------------------------------------------------------------------
# Limites de taille
# ---------------------------------------------------------------------------

class TestLimites:
    def test_requête_trop_grande_rejetee(self, client, monkeypatch):
        # MAX_CONTENT_LENGTH est configuré : un body dépassant la limite
        # doit déclencher un 413 (avant d'atteindre le backend).
        big_body = b"x" * (MAX_CONTENT_LENGTH + 1)
        r = client.post("/api/upload", data=big_body,
                        headers={"Content-Type": "application/octet-stream"})
        assert r.status_code == 413