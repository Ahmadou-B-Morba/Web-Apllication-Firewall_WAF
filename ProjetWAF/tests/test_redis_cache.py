import pytest
import time
import re
from app import app, redis_client, REDIS_AVAILABLE
from regles.loader import RuleLoader

@pytest.fixture
def client():
    """Fixture pour le client Flask en mode test."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def clear_redis_cache():
    """Vide le cache Redis avant chaque test."""
    if REDIS_AVAILABLE:
        redis_client.flushdb()
    yield
    if REDIS_AVAILABLE:
        redis_client.flushdb()

def test_redis_connection():
    """Teste que Redis est connecté et disponible."""
    if not REDIS_AVAILABLE:
        pytest.skip("Redis non disponible")
    assert redis_client.ping() is True

def test_cache_allowed_request(client):
    """Teste le cache pour une requête légitime."""
    if not REDIS_AVAILABLE:
        pytest.skip("Redis non disponible")

    # Première requête (cache miss)
    response1 = client.get("/?test=hello")
    assert response1.status_code == 200

    # Vérifier qu'une clé a été ajoutée au cache
    assert len(redis_client.keys()) > 0

    # Deuxième requête (cache hit)
    response2 = client.get("/?test=hello")
    assert response2.status_code == 200

def test_cache_blocked_request(client):
    """Teste le cache pour une requête bloquée (SQLi)."""
    if not REDIS_AVAILABLE:
        pytest.skip("Redis non disponible")

    # Ajouter une règle SQLi temporaire pour le test
    loader = RuleLoader()
    loader.rules = [
        {
            "id": "SQL-001",
            "nom": "SQL Injection Test",
            "regex": re.compile("'\\s+OR\\s+'"),
            "gravite": "high",
            "category": "sqli",
            "compiled_re": re.compile("'\\s+OR\\s+'"),
            "source_file": "test",
            "priority": 1
        }
    ]

    # Remplacer temporairement le loader dans l'app
    original_loader = app.config.get("waf_loader")
    app.config["waf_loader"] = loader

    try:
        # Requête SQLi (cache miss)
        response1 = client.get("/?id=1' OR '1'='1")
        assert response1.status_code == 400

        # Vérifier qu'une clé a été ajoutée au cache
        assert len(redis_client.keys()) > 0

        # Deuxième requête (cache hit)
        response2 = client.get("/?id=1' OR '1'='1")
        assert response2.status_code == 400
    finally:
        # Restaurer le loader original
        if original_loader:
            app.config["waf_loader"] = original_loader

def test_fallback_without_redis(monkeypatch, client):
    """Teste le fallback si Redis est indisponible."""
    # Simuler une erreur Redis
    monkeypatch.setattr("app.REDIS_AVAILABLE", False)

    response = client.get("/?test=hello")
    assert response.status_code == 200  # Doit fonctionner sans cache

def test_clear_cache_route(client):
    """Teste la route /clear_cache."""
    if not REDIS_AVAILABLE:
        pytest.skip("Redis non disponible")

    # Ajouter une entrée au cache
    redis_client.set("test_key", "test_value")

    # Vider le cache
    response = client.get("/clear_cache")
    assert response.status_code == 200
    assert len(redis_client.keys()) == 0  # Cache vide