import sys
import os
import urllib.parse

# ÉTAPE 1 : Configuration du chemin pour Docker et les exécutions directes
# On récupère le chemin absolu du dossier parent (ProjetWAF)
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

# Maintenant l'import fonctionnera car ProjetWAF est dans le path
from regles.loader import RuleLoader

class AnalyseurWAF:
    def __init__(self):
        """
        Initialise le moteur en chargeant toutes les signatures via le Loader.
        """
        print("[*] Initialisation du moteur d'analyse...")
        self.loader = RuleLoader()
        self.signatures = self.loader.load_all()
        print(f"[*] Moteur prêt : {len(self.signatures)} signatures actives.")

    def _nettoyer_donnees(self, data):
        """
        Décode les données pour éviter les contournements (URL Encoding).
        """
        try:
            return urllib.parse.unquote(str(data))
        except Exception:
            return str(data)

    def analyser_requete(self, payload):
        """
        Analyse une chaîne contre les signatures chargées.
        """
        if not payload:
            return {"status": "clean"}

        texte_propre = self._nettoyer_donnees(payload)

        for rule in self.signatures:
            if rule['compiled_re'].search(texte_propre):
                return {
                    "status": "blocked",
                    "rule_id": rule.get('id'),
                    "category": rule.get('categorie'),
                    "reason": rule.get('nom'),
                    "severity": rule.get('gravite'),
                    "match": rule['compiled_re'].search(texte_propre).group()
                }

        return {"status": "clean"}

# ==========================================
# TEST DU MOTEUR
# ==========================================
if __name__ == "__main__":
    analyseur = AnalyseurWAF()
    
    # Test avec une attaque XSS et une injection SQL
    tests = [
        "search?q=cybersecurite", 
        "<script>alert('XSS')</script>", 
        "1' OR '1'='1"
    ]

    print("\n--- Lancement des tests de détection ---")
    for t in tests:
        res = analyseur.analyser_requete(t)
        print(f"Test: {t} -> Resultat: {res['status']}")