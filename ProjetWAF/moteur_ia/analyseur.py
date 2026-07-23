import sys
import os
import re
import urllib.parse
import logging
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ÉTAPE 1 : Configuration du chemin pour Docker et les exécutions directes
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from regles.loader import RuleLoader

@dataclass
class AnalyseResult:
    """Classe pour structurer les résultats d'analyse."""
    status: str  # "clean" ou "blocked"
    rule_id: Optional[str] = None
    category: Optional[str] = None
    reason: Optional[str] = None
    severity: Optional[str] = None
    match: Optional[str] = None
    source: Optional[str] = None  # "url", "body", "headers", etc.
    confidence: float = 0.0  # Score de confiance (0-1)
    obfuscation_detected: bool = False  # Si du code obfusqué est détecté

class AnalyseurWAF:
    """
    Moteur d'analyse des requêtes HTTP pour détecter les attaques.
    Combine :
    - Détection basée sur des signatures (règles regex).
    - Détection d'obfuscation (encodage multiple, Unicode, etc.).
    """

    def __init__(self):
        """
        Initialise le moteur en chargeant toutes les signatures via le Loader.
        """
        logger.info("Initialisation du moteur d'analyse...")
        self.loader = RuleLoader()
        self.signatures = self.loader.load_all()
        self._init_obfuscation_patterns()
        logger.info(f"Moteur prêt : {len(self.signatures)} signatures actives.")

    def _init_obfuscation_patterns(self):
        """Initialise les motifs pour détecter l'obfuscation."""
        # Patterns pour détecter l'obfuscation (Unicode, hex, base64, etc.)
        self.obfuscation_patterns = [
            re.compile(r'\\x[0-9a-fA-F]{2}'),  # Hex encoding (\x41)
            re.compile(r'&#x?[0-9a-fA-F]+;'),  # HTML entities
            re.compile(r'%[0-9a-fA-F]{2}'),    # URL encoding (%41)
            re.compile(r'\b(eval|fromCharCode|String\.fromCharCode)\b', re.IGNORECASE),  # JS obfuscation
            re.compile(r'\b(atob|btoa)\b', re.IGNORECASE),  # Base64 obfuscation
            re.compile(r'[^\x00-\x7F]'),      # Non-ASCII characters (Unicode)
        ]

    def _nettoyer_donnees(self, data: Union[str, bytes, None]) -> str:
        """
        Nettoie et décode les données pour éviter les contournements.
        Applique plusieurs passes de décodage pour détecter :
        - URL Encoding (%20, %2520, etc.)
        - Unicode escaping
        - Hex encoding
        - Base64 (optionnel)

        Args:
            data: Données à nettoyer (str, bytes, ou None).

        Returns:
            str: Données décodées.
        """
        if data is None:
            return ""

        try:
            # Convertir en str si c'est des bytes
            if isinstance(data, bytes):
                data = data.decode("utf-8", errors="ignore")

            texte = str(data)
            precedent = None

            # Décodage URL (jusqu'à stabilisation)
            while precedent != texte:
                precedent = texte
                texte = urllib.parse.unquote(texte)

            # Décodage des caractères Unicode (\u0041 -> A)
            texte = texte.encode("utf-8", errors="ignore").decode("unicode-escape", errors="ignore")

            # Décodage de l'hexadécimal brut (ex: 0x53454C454354 -> SELECT)
            # On décode et on AJOUTE le résultat au texte (au lieu de remplacer)
            # pour ne pas perdre le payload original dans le scan.
            for hexmatch in re.finditer(r'0x([0-9a-fA-F]{4,})', texte):
                hex_digits = hexmatch.group(1)
                if len(hex_digits) % 2 == 0:
                    try:
                        decoded = bytes.fromhex(hex_digits).decode("utf-8", errors="ignore")
                        if decoded.isprintable():
                            texte += " " + decoded
                    except ValueError:
                        pass

            return texte
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage des données: {e}")
            return str(data)

    def _detecter_obfuscation(self, texte: str) -> bool:
        """
        Détecte si le texte contient des motifs d'obfuscation.

        Args:
            texte: Texte à analyser.

        Returns:
            bool: True si de l'obfuscation est détectée.
        """
        for pattern in self.obfuscation_patterns:
            if pattern.search(texte):
                return True
        return False

    def _calculer_confiance(self, match: re.Match, rule: Dict[str, Any]) -> float:
        """
        Calcule un score de confiance pour une détection.
        Prend en compte :
        - La gravité de la règle.
        - La longueur du match.
        - La présence d'obfuscation.

        Args:
            match: Objet Match de la regex.
            rule: Règle correspondante.

        Returns:
            float: Score de confiance (0-1).
        """
        # Poids par gravité
        severity_weights = {
            "low": 0.3,
            "medium": 0.6,
            "high": 0.8,
            "critical": 1.0
        }
        gravity = rule.get("gravite", "low").lower()
        confidence = severity_weights.get(gravity, 0.5)

        # Bonus si obfuscation détectée
        if self._detecter_obfuscation(match.group()):
            confidence = min(confidence + 0.2, 1.0)

        # Bonus si le match est long (plus susceptible d'être malveillant)
        match_length = len(match.group())
        if match_length > 20:
            confidence = min(confidence + 0.1, 1.0)

        return round(confidence, 2)

    def analyser_requete(
        self,
        payload: Union[str, bytes, None],
        source: Optional[str] = None
    ) -> AnalyseResult:
        """
        Analyse une chaîne contre toutes les signatures chargées.

        Args:
            payload: Données à analyser (str, bytes, ou None).
            source: Origine des données (ex: "url", "body"). Utile pour le logging.

        Returns:
            AnalyseResult: Résultat de l'analyse.
        """
        if not payload:
            return AnalyseResult(status="clean")

        texte_propre = self._nettoyer_donnees(payload)
        obfuscation = self._detecter_obfuscation(texte_propre)

        for rule in self.signatures:
            try:
                match = rule["compiled_re"].search(texte_propre)
                if match:
                    confidence = self._calculer_confiance(match, rule)
                    return AnalyseResult(
                        status="blocked",
                        rule_id=rule.get("id"),
                        category=rule.get("categorie"),
                        reason=rule.get("nom"),
                        severity=rule.get("gravite"),
                        match=match.group(),
                        source=source,
                        confidence=confidence,
                        obfuscation_detected=obfuscation
                    )
            except re.error as e:
                logger.error(f"Erreur regex dans la règle {rule.get('id')}: {e}")
                continue

        return AnalyseResult(
            status="clean",
            source=source,
            confidence=0.0,
            obfuscation_detected=obfuscation
        )

    def analyser_requete_complete(
        self,
        methode: Optional[str] = None,
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Union[str, bytes]] = None,
        query_params: Optional[Dict[str, str]] = None
    ) -> AnalyseResult:
        """
        Analyse l'ensemble des composants d'une requête HTTP.
        Retourne dès la première menace détectée.

        Args:
            methode: Méthode HTTP (GET, POST, etc.).
            url: URL de la requête.
            headers: Headers HTTP.
            body: Corps de la requête.
            query_params: Paramètres de requête (GET).

        Returns:
            AnalyseResult: Résultat de l'analyse.
        """
        composants = {
            "method": methode,
            "url": url,
            "query_params": str(query_params) if query_params else None,
            "headers": str(headers) if headers else None,
            "body": body
        }

        for nom, valeur in composants.items():
            if not valeur:
                continue
            resultat = self.analyser_requete(valeur, source=nom)
            if resultat.status == "blocked":
                return resultat

        return AnalyseResult(status="clean")

    def analyser_liste_payloads(self, payloads: List[Union[str, bytes]]) -> List[AnalyseResult]:
        """
        Analyse une liste de payloads (ex: tous les paramètres d'une requête).
        Retourne tous les résultats (pas seulement le premier bloqué).

        Args:
            payloads: Liste de payloads à analyser.

        Returns:
            List[AnalyseResult]: Liste des résultats.
        """
        resultats = []
        for payload in payloads:
            resultats.append(self.analyser_requete(payload))
        return resultats

# ==========================================
# TEST DU MOTEUR
# ==========================================
if __name__ == "__main__":
    analyseur = AnalyseurWAF()

    # Tests étendus (incluant obfuscation et cas complexes)
    tests = [
        # Cas normaux
        ("URL normale",               "search?q=cybersecurite",                          "clean"),
        ("Paramètre normal",         "user=ahmadou&action=login",                      "clean"),
        ("JSON normal",              '{"name": "test", "value": 42}',                   "clean"),

        # Attaques XSS
        ("XSS basique",               "<script>alert('XSS')</script>",                  "blocked"),
        ("XSS encodé (URL)",          "%3Cscript%3Ealert(1)%3C%2Fscript%3E",             "blocked"),
        ("XSS double encodé",         "%253Cscript%253Ealert(2)%253C%252Fscript%253E",   "blocked"),
        ("XSS avec HTML entities",    "&#60;script&#62;alert(3)&#60;/script&#62;",        "blocked"),
        ("XSS Unicode",               "\u003Cscript\u003Ealert(4)\u003C/script\u003E",    "blocked"),
        ("XSS dans un header",         "User-Agent: <script>alert(5)</script>",          "blocked"),

        # Attaques SQLi
        ("SQLi basique",              "1' OR '1'='1",                                   "blocked"),
        ("SQLi encodé",              "1%27%20OR%20%271%27%3D%271",                     "blocked"),
        ("SQLi avec commentaire",    "1' UNION SELECT * FROM users--",               "blocked"),
        ("SQLi hex",                 "0x53454C454354",                                "blocked"),

        # Attaques DLP (Data Leak Prevention)
        ("Numéro de carte bancaire", "4111111111111111",                              "blocked"),
        ("Email sensible",           "admin@monentreprise.com",                       "blocked"),

        # Obfuscation avancée
        ("Obfuscation JS",            "eval('al'+'ert(6)')",                           "blocked"),
        ("Obfuscation Base64",        "atob('YWxlcnQoMTAp')",                          "blocked"),
        ("Obfuscation Unicode + URL", "%u003Cscript%u003Ealert(8)%u003C/script%u003E", "blocked"),
    ]

    print("\n" + "=" * 100)
    print("LANCEMENT DES TESTS DE DÉTECTION - AnalyseurWAF".center(100))
    print("=" * 100)
    print(f"{'Test':<40} {'Statut':<10} {'Catégorie':<20} {'Sévérité':<10} {'Confiance':<10} {'Obfuscation':<12}")
    print("-" * 100)

    stats = {"blocked": 0, "clean": 0, "obfuscated": 0}
    for nom, payload, expected in tests:
        res = analyseur.analyser_requete(payload)
        statut = res.status
        categorie = res.category or "-"
        severite = res.severity or "-"
        confidence = res.confidence
        obfuscation = "✅" if res.obfuscation_detected else "❌"

        # Vérification du résultat attendu
        if statut == expected:
            status_color = "✅"
        else:
            status_color = "❌ (ERREUR)"
            stats["errors"] = stats.get("errors", 0) + 1

        stats[statut] += 1
        if res.obfuscation_detected:
            stats["obfuscated"] += 1

        print(
            f"{nom:<40} {status_color} {statut:<8} {categorie:<20} {severite:<10} "
            f"{confidence:<10.2f} {obfuscation:<12}"
        )

    print("-" * 100)
    print(f"STATISTIQUES: {stats['blocked']} bloqués | {stats['clean']} propres | {stats.get('obfuscated', 0)} obfusqués | {stats.get('errors', 0)} erreurs".center(100))
    print("=" * 100 + "\n")