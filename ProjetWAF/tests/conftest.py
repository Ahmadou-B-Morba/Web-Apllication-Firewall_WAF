"""Configuration partagée de la suite de tests ProjetWAF.

Ajoute la racine du projet (``ProjetWAF/``) au ``sys.path`` afin que les
modules internes (``regles``, ``moteur_ia``, ``logs``, ``proxy``, ``app``)
soient importables quel que soit le répertoire depuis lequel pytest est
lancé. La racine du projet est le répertoire parent de ``tests/``.
"""
import os
import sys

# Répertoire contenant ce fichier : <project>/tests
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
# Racine du projet : <project>/  (parent de tests/)
PROJECT_ROOT = os.path.dirname(TESTS_DIR)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def pytest_configure(config):
    """Déclare un marqueur personnalisé pour les tests nécessitant une
    base PostgreSQL réelle (non exécutés par défaut en CI sans DB)."""
    config.addinivalue_line(
        "markers",
        "db: tests nécessitant une connexion PostgreSQL réelle (deselect with '-m \"not db\"')",
    )
