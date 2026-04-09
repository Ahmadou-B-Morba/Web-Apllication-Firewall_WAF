import sys
import os
import urllib.parse

# ÉTAPE 1 : Configuration du chemin pour Docker et les exécutions directes
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

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
        Applique plusieurs passes de décodage pour détecter les encodages imbriqués.
        """
        try:
            texte = str(data)
            # Double décodage pour détecter les encodages imbriqués (%253Cscript%253E)
            precedent = None
            while precedent != texte:
                precedent = texte
                texte = urllib.parse.unquote(texte)
            return texte
        except Exception:
            return str(data)

    def analyser_requete(self, payload):
        """
        Analyse une chaîne contre toutes les signatures chargées.
        Retourne un dict avec le statut et les détails si une menace est détectée.
        """
        if not payload:
            return {"status": "clean"}

        texte_propre = self._nettoyer_donnees(payload)

        for rule in self.signatures:
            match = rule['compiled_re'].search(texte_propre)
            if match:
                return {
                    "status": "blocked",
                    "rule_id": rule.get('id'),
                    "category": rule.get('categorie'),
                    "reason": rule.get('nom'),
                    "severity": rule.get('gravite'),
                    "match": match.group()
                }

        return {"status": "clean"}

    def analyser_requete_complete(self, methode=None, url=None, headers=None, body=None):
        """
        Analyse l'ensemble des composants d'une requête HTTP.
        Retourne dès la première menace détectée.
        """
        composants = {
            "url": url,
            "body": body,
            "headers": str(headers) if headers else None,
        }

        for nom, valeur in composants.items():
            if not valeur:
                continue
            resultat = self.analyser_requete(valeur)
            if resultat["status"] == "blocked":
                resultat["source"] = nom  # indique où la menace a été trouvée
                return resultat

        return {"status": "clean"}


# ==========================================
# TEST DU MOTEUR
# ==========================================
if __name__ == "__main__":
    analyseur = AnalyseurWAF()

    tests = [
        ("URL normale",       "search?q=cybersecurite"),
        ("XSS basique",       "<script>alert('XSS')</script>"),
        ("SQLi basique",      "1' OR '1'='1"),
        ("XSS encodé",        "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        ("SQLi encodé",       "1%27%20OR%20%271%27%3D%271"),
        ("Double encodage",   "%253Cscript%253Ealert(2)%253C%252Fscript%253E"),
    ]

    print("\n--- Lancement des tests de détection ---")
    print(f"{'Test':<30} {'Statut':<10} {'Catégorie':<20} {'Sévérité'}")
    print("-" * 75)

    for nom, payload in tests:
        res = analyseur.analyser_requete(payload)
        statut = res['status']
        categorie = res.get('category', '-')
        severite = res.get('severity', '-')
        print(f"{nom:<30} {statut:<10} {str(categorie):<20} {severite}")