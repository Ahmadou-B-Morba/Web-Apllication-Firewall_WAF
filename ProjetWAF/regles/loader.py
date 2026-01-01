import os
import json
import re

class RuleLoader:
    def __init__(self, rules_dir=None):
        """
        Initialise le chargeur de règles avec gestion de chemin absolu.
        """
        if rules_dir is None:
            # Récupère le chemin du dossier où se trouve loader.py
            base_path = os.path.dirname(os.path.abspath(__file__))
            self.rules_dir = os.path.join(base_path, "signatures")
        else:
            self.rules_dir = rules_dir
            
        self.rules = []
        self.seen_ids = set()

    def load_all(self):
        """
        Parcourt le dossier signatures et charge chaque fichier JSON trouvé.
        """
        if not os.path.isdir(self.rules_dir):
            print(f"[ERREUR] Dossier de signatures introuvable : {self.rules_dir}")
            return []

        self.rules = []
        self.seen_ids = set()

        # Lister les fichiers JSON dans le dossier
        files = [f for f in os.listdir(self.rules_dir) if f.endswith(".json")]
        
        for filename in sorted(files):
            self._load_file(filename)

        print(f"\n[INFO] TOTAL : {len(self.rules)} règles uniques chargées dans le moteur.")
        return self.rules

    def _load_file(self, filename):
        """
        Analyse le fichier JSON et extrait les règles peu importe la structure.
        """
        filepath = os.path.join(self.rules_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            regles_extraites = []

            # --- CAS 1 : Structure imbriquée (comme owasp10.json) ---
            # On cherche s'il y a une clé "signatures" qui contient des listes "regles"
            if "signatures" in data and isinstance(data["signatures"], list):
                for section in data["signatures"]:
                    # On cherche la liste de règles dans chaque section
                    liste = section.get("regles") or section.get("rules")
                    if liste and isinstance(liste, list):
                        regles_extraites.extend(liste)

            # --- CAS 2 : Structure directe (comme xss.json) ---
            else:
                regles_extraites = data.get("regles") or data.get("rules") or data.get("signatures") or []

            # --- TRAITEMENT DES RÈGLES ---
            count_file = 0
            for rule in regles_extraites:
                rule_id = rule.get("id")

                # Ignorer si pas d'ID ou si déjà chargé ailleurs
                if not rule_id:
                    continue
                if rule_id in self.seen_ids:
                    # Optionnel : print(f"   [DOUBLON] {rule_id} déjà vu")
                    continue

                # Compilation de la Regex pour la rapidité
                try:
                    pattern = rule.get("regex")
                    if pattern:
                        rule["compiled_re"] = re.compile(pattern)
                        rule["source_file"] = filename
                        
                        self.rules.append(rule)
                        self.seen_ids.add(rule_id)
                        count_file += 1
                except re.error:
                    print(f"   [ERREUR REGEX] ID {rule_id} dans {filename} invalide.")
                    continue

            print(f"[DEBUG] {filename} : {count_file} nouvelles règles ajoutées.")

        except json.JSONDecodeError:
            print(f"[ERREUR] Syntaxe JSON invalide dans {filename}")
        except Exception as e:
            print(f"[ERREUR] Impossible de lire {filename} : {e}")

    def check(self, text):
        """
        Scanne un texte et retourne la première règle qui match.
        """
        if not text or not isinstance(text, str):
            return None
            
        for rule in self.rules:
            if rule["compiled_re"].search(text):
                # On retourne un dictionnaire avec les détails pour le log
                return {
                    "nom": rule.get("nom"),
                    "id": rule.get("id"),
                    "gravite": rule.get("gravite", "Inconnue")
                }
        return None
# ==========================================
# Script de test
# ==========================================
if __name__ == "__main__":
    print("=== TEST DU CHARGEUR DE RÈGLES PROJETWAF ===")
    loader = RuleLoader()
    all_rules = loader.load_all()

    if all_rules:
        print("\nExemple de règles chargées :")
        # Affiche les 5 premières pour vérification
        for r in all_rules[:5]:
            print(f" - [{r.get('id')}] {r.get('nom')}")