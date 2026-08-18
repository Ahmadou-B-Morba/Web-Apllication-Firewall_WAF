# Suite de tests ProjetWAF

La suite de tests centralise tous les tests du projet, y compris ceux qui
étaient auparavant définis dans les blocs `if __name__ == "__main__"` des
modules (`loader.py`, `analyseur.py`, `transporteur.py`, …) et l'ancien
fichier racine `test_db.py`.

## Structure

```
tests/
├── __init__.py
├── conftest.py          # Configuration pytest + marqueur "db"
├── test_loader.py       # Chargeur de règles (regles/loader.py)
├── test_analyseur.py    # Moteur d'analyse (moteur_ia/analyseur.py)
├── test_logger.py       # Journalisation (logs/logger.py) — DB mockée
├── test_app.py          # Middleware WAF Flask (app.py)
├── test_transporteur.py # Proxy inverse (proxy/transporteur.py)
└── test_db.py           # Intégration PostgreSQL (marqueur @db)
```

## Exécution

```bash
# Tous les tests (y compris ceux nécessitant PostgreSQL)
just test
# ou directement
pytest tests/

# Tests sans la base de données (idéal pour le CI)
just test_ci
# ou
pytest tests/ -m "not db"
```

## Pré-requis

```bash
pip install -r requirements.txt
```

Les tests de `test_logger.py`, `test_app.py` et `test_transporteur.py`
mockent la connexion PostgreSQL et le backend HTTP : aucune dépendance
externe n'est nécessaire.

Les tests de `test_db.py` sont marqués `@pytest.mark.db` et sont
automatiquement ignorés (`skip`) si PostgreSQL n'est pas joignable. Pour
les activer, configurer les variables d'environnement `DB_*` et appliquer
le schéma `logs/waf_query.sql`.

## Conventions

- Les noms de fichiers suivent le pattern `test_<module>.py`.
- Les classes de test suivent le pattern `Test<Section>`.
- Les fonctions de test commencent par `test_`.
- Les payloads d'attaque sont paramétrés via `@pytest.mark.parametrize`.