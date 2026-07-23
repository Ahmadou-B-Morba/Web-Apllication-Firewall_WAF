import os
import json
import re
import jsonschema
from pathlib import Path
from typing import List, Dict, Optional, Any
import logging

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Schéma de validation pour une règle
# NOTE: "additionalProperties" est mis à True car les fichiers de signatures
# utilisent des champs métier variés (commentaire, categorie, action, presence,
# headers_requis, limite_ms, requetes_par_minute...) selon le type de règle.
# On ne verrouille que les champs qu'on connait vraiment pour éviter les
# faux positifs de validation, tout en gardant "id"/"nom"/"regex" obligatoires.
RULE_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "nom": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "regex": {"type": "string", "minLength": 1},
        # Accepte n'importe quelle chaîne ici : la normalisation FR -> EN
        # (low/medium/high/critical) est faite dans _add_rule(), pas dans
        # le schéma, pour ne jamais faire échouer le chargement à cause
        # d'une langue.
        "gravite": {"type": "string", "minLength": 1},
        "category": {"type": "string", "minLength": 1},
        "categorie": {"type": "string", "minLength": 1},
        "priority": {"type": "integer", "minimum": 1, "maximum": 10},
        "examples": {"type": "array", "items": {"type": "string"}},
        "commentaire": {"type": "string"},
        "action": {"type": "string"},
        "type": {"type": "string"},
        "methode": {"type": "string"},
        "presence": {"type": "string"},
        "headers_requis": {"type": "array", "items": {"type": "string"}},
        "limite_ms": {"type": "number"},
        "requetes_par_minute": {"type": "number"},
    },
    "required": ["id", "nom", "regex"],
    "additionalProperties": True,
}

# Table de correspondance FR -> EN pour normaliser la gravité,
# quelle que soit la langue utilisée dans les fichiers JSON.
GRAVITE_MAP = {
    "basse": "low", "low": "low",
    "moyenne": "medium", "medium": "medium",
    "haute": "high", "high": "high",
    "critique": "critical", "critical": "critical",
}

class RuleLoader:
    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialise le chargeur de règles.
        Args:
            rules_dir: Chemin vers le dossier des signatures (optionnel).
                     Si None, utilise le dossier 'signatures' adjacent à loader.py.
        """
        if rules_dir is None:
            base_path = os.path.dirname(os.path.abspath(__file__))
            self.rules_dir = os.path.join(base_path, "signatures")
        else:
            self.rules_dir = os.path.abspath(rules_dir)

        self.rules: List[Dict[str, Any]] = []
        self.seen_ids: set = set()
        self._cache: Dict[str, re.Pattern] = {}  # Cache pour les regex compilées

    def load_all(self) -> List[Dict[str, Any]]:
        """
        Charge toutes les règles depuis les fichiers JSON du dossier.
        Returns:
            Liste des règles chargées.
        """
        if not os.path.isdir(self.rules_dir):
            logger.error(f"Dossier de signatures introuvable : {self.rules_dir}")
            return []

        self.rules = []
        self.seen_ids = set()
        self._cache = {}

        files = [
            f for f in os.listdir(self.rules_dir)
            if f.endswith(".json") and os.path.isfile(os.path.join(self.rules_dir, f))
        ]

        if not files:
            logger.warning(f"Aucun fichier JSON trouvé dans {self.rules_dir}")
            return []

        total_rules = 0
        for filename in sorted(files):
            file_rules = self._load_file(filename)
            total_rules += file_rules

        # Trier les règles par priorité (descendante) puis par ID
        self.rules.sort(key=lambda x: (-x.get("priority", 1), x.get("id", "")))

        logger.info(f"TOTAL : {total_rules} règles uniques chargées dans le moteur.")
        return self.rules

    def _load_file(self, filename: str) -> int:
        """
        Charge un fichier JSON et extrait les règles.
        Args:
            filename: Nom du fichier JSON à charger.
        Returns:
            Nombre de règles valides ajoutées.
        """
        filepath = os.path.join(self.rules_dir, filename)
        count_file = 0

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Extraire les règles selon différents formats possibles
            rules_list = self._extract_rules_from_data(data, filename)
            if not rules_list:
                logger.debug(f"Aucune règle valide trouvée dans {filename}")
                return 0

            # Traiter chaque règle
            for rule in rules_list:
                if self._add_rule(rule, filename):
                    count_file += 1

        except json.JSONDecodeError as e:
            logger.error(f"Syntaxe JSON invalide dans {filename} : {e}")
        except Exception as e:
            logger.error(f"Erreur lors de la lecture de {filename} : {e}")

        logger.debug(f"{filename} : {count_file} nouvelles règles ajoutées.")
        return count_file

    def _extract_rules_from_data(self, data: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
        """
        Extrait les règles d'une structure JSON, quel que soit son format.
        Args:
            data: Données JSON chargées.
            filename: Nom du fichier (pour le logging).
        Returns:
            Liste des règles extraites.
        """
        rules = []

        # --- Cas 1: Structure imbriquée (ex: owasp10.json -> "signatures": [{"regles": [...]}]) ---
        if isinstance(data, dict):
            # Chercher dans les clés connues
            for key in ["signatures", "rules", "regles", "data"]:
                if key in data and isinstance(data[key], list):
                    for item in data[key]:
                        if not isinstance(item, dict):
                            continue

                        # Section imbriquée : contient elle-même une liste de règles
                        nested_found = False
                        for rule_key in ["regles", "rules", "signatures"]:
                            if rule_key in item and isinstance(item[rule_key], list):
                                rules.extend(item[rule_key])
                                nested_found = True
                                break

                        # Cas 1bis : liste à plat (ex: xss.json -> "regles": [{"id": ..., "regex": ...}])
                        # Ici chaque élément EST directement une règle (présence de "id"/"regex"),
                        # pas une section contenant d'autres règles.
                        if not nested_found and ("id" in item or "regex" in item):
                            rules.append(item)

        # --- Cas 2: Liste directe de règles ---
        elif isinstance(data, list):
            rules = data

        # Filtrer les entrées qui ne sont pas des dictionnaires
        rules = [r for r in rules if isinstance(r, dict)]

        return rules

    def _add_rule(self, rule: Dict[str, Any], source_file: str) -> bool:
        """
        Ajoute une règle après validation et compilation.
        Args:
            rule: Règle à ajouter.
            source_file: Fichier source (pour le logging).
        Returns:
            True si la règle a été ajoutée, False sinon.
        """
        rule_id = rule.get("id")
        if not rule_id:
            logger.warning(f"Règle sans ID ignorée dans {source_file}")
            return False

        if rule_id in self.seen_ids:
            logger.debug(f"Doublon ignoré : {rule_id} (déjà chargé depuis {rule.get('source_file', '?')})")
            return False

        # Validation avec jsonschema
        try:
            jsonschema.validate(instance=rule, schema=RULE_SCHEMA)
        except jsonschema.ValidationError as e:
            logger.warning(f"Règle invalide {rule_id} dans {source_file} : {e.message}")
            return False

        # Normalisation de la gravité (FR -> EN), quelle que soit la casse/langue
        gravite_brute = rule.get("gravite", "low")
        rule["gravite"] = GRAVITE_MAP.get(str(gravite_brute).strip().lower(), "low")

        # Garde-fou : certaines règles ne sont pas des signatures de contenu
        # mais des règles de seuil/rate-limit (type="threshold",
        # requetes_par_minute, regex=".*" ou "^$"). Les charger dans le moteur
        # de matching regex bloquerait TOUT le trafic (ex: DDOS-002 avec
        # regex=".*") ou RIEN d'utile (regex="^$"). Elles doivent être gérées
        # par une logique dédiée (rate limiting, timers) et pas ici.
        regex_pattern = rule.get("regex")
        non_content_rule = (
            rule.get("type") == "threshold"
            or "requetes_par_minute" in rule
            or "limite_ms" in rule
            or regex_pattern in (".*", "^$")
        )
        if non_content_rule:
            logger.info(
                f"Règle {rule_id} ignorée par le moteur regex (règle de seuil/"
                f"rate-limit, à implémenter séparément) : {rule.get('nom')}"
            )
            return False

        if not regex_pattern:
            logger.warning(f"Règle {rule_id} sans regex dans {source_file}")
            return False

        try:
            # Utiliser le cache ou compiler
            if regex_pattern not in self._cache:
                self._cache[regex_pattern] = re.compile(regex_pattern)
            rule["compiled_re"] = self._cache[regex_pattern]
            rule["source_file"] = source_file
            rule["priority"] = rule.get("priority", 1)  # Priorité par défaut = 1

            self.rules.append(rule)
            self.seen_ids.add(rule_id)
            return True

        except re.error as e:
            logger.error(f"Regex invalide pour {rule_id} dans {source_file} : {e}")
            return False

    def check(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Vérifie si un texte correspond à une règle.
        Args:
            text: Texte à analyser.
        Returns:
            Dictionnaire avec les détails de la règle correspondante, ou None.
        """
        if not text or not isinstance(text, str):
            return None

        for rule in self.rules:
            if rule["compiled_re"].search(text):
                return {
                    "id": rule.get("id"),
                    "nom": rule.get("nom"),
                    "gravite": rule.get("gravite", "unknown"),
                    "category": rule.get("category", "unknown"),
                    "priority": rule.get("priority", 1),
                    "source": rule.get("source_file", "unknown"),
                }
        return None

    def reload(self) -> List[Dict[str, Any]]:
        """
        Recharge toutes les règles (utile pour les mises à jour à chaud).
        Returns:
            Liste des nouvelles règles chargées.
        """
        logger.info("Rechargement des règles...")
        return self.load_all()

    def get_rules_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Récupère toutes les règles d'une catégorie donnée.
        Args:
            category: Catégorie à filtrer (ex: "xss", "injection").
        Returns:
            Liste des règles de la catégorie.
        """
        return [rule for rule in self.rules if rule.get("category", "").lower() == category.lower()]

    def get_rule_stats(self) -> Dict[str, Any]:
        """
        Retourne des statistiques sur les règles chargées.
        Returns:
            Dictionnaire avec :
            - total: Nombre total de règles.
            - by_category: Répartition par catégorie.
            - by_gravity: Répartition par gravité.
        """
        stats = {
            "total": len(self.rules),
            "by_category": {},
            "by_gravity": {},
        }

        for rule in self.rules:
            # Par catégorie
            category = rule.get("category", "unknown").lower()
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

            # Par gravité
            gravity = rule.get("gravite", "unknown").lower()
            stats["by_gravity"][gravity] = stats["by_gravity"].get(gravity, 0) + 1

        return stats

# ==========================================
# Script de test
# ==========================================
if __name__ == "__main__":
    print("=" * 50)
    print("TEST DU CHARGEUR DE RÈGLES PROJETWAF")
    print("=" * 50)

    # Initialisation
    loader = RuleLoader()
    all_rules = loader.load_all()

    # Afficher les stats
    if all_rules:
        stats = loader.get_rule_stats()
        print(f"\n📊 Statistiques des règles chargées:")
        print(f"   - Total: {stats['total']}")
        print(f"   - Par catégorie: {stats['by_category']}")
        print(f"   - Par gravité: {stats['by_gravity']}")

        # Tester la détection
        test_payloads = [
            ("' OR '1'='1", "SQL Injection"),
            ("<script>alert(1)</script>", "XSS"),
            ("../../../etc/passwd", "Path Traversal"),
            ("GET /admin HTTP/1.1", "Normal"),
        ]

        print("\n🔍 Tests de détection:")
        for payload, description in test_payloads:
            match = loader.check(payload)
            if match:
                print(f"   ✅ {description:20} -> DÉTECTÉ: {match['nom']} (ID: {match['id']})")
            else:
                print(f"   ❌ {description:20} -> NON DÉTECTÉ")
    else:
        print("\n❌ Aucune règle chargée. Vérifiez le dossier 'signatures'.")