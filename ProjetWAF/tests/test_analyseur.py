"""Tests du moteur d'analyse (``moteur_ia/analyseur.py``).

Reprend fidèlement la table de tests du bloc ``if __name__ == "__main__"``
de ``analyseur.py`` (cas propres, XSS simple/encodé/double-encodé/HTML
entities/Unicode/header, SQLi simple/encodée/commentaire/hex, DLP carte
bancaire/email, obfuscation JS/Base64/Unicode+URL) et y ajoute des tests
ciblés sur les méthodes internes : nettoyage/décodage, détection
d'obfuscation, calcul de confiance, analyse de requête complète et
analyse d'une liste de payloads.
"""
import warnings

import pytest

# flask_limiter émet un UserWarning sur le storage en mémoire ; on le filtre
# pour garder une sortie de tests lisible.
warnings.filterwarnings("ignore")

from moteur_ia.analyseur import AnalyseurWAF, AnalyseResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def analyseur():
    """Instance unique partagée : le chargement des signatures est coûteux."""
    return AnalyseurWAF()


# ---------------------------------------------------------------------------
# Table de tests du bloc __main__ de analyseur.py
# ---------------------------------------------------------------------------

# (nom, payload, statut_attendu)
CAS_TESTS_MAIN = [
    # Cas normaux
    ("URL normale", "search?q=cybersecurite", "clean"),
    ("Paramètre normal", "user=ahmadou&action=login", "clean"),
    ("JSON normal", '{"name": "test", "value": 42}', "clean"),

    # Attaques XSS
    ("XSS basique", "<script>alert('XSS')</script>", "blocked"),
    ("XSS encodé (URL)", "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "blocked"),
    ("XSS double encodé", "%253Cscript%253Ealert(2)%253C%252Fscript%253E", "blocked"),
    ("XSS avec HTML entities", "&#60;script&#62;alert(3)&#60;/script&#62;", "blocked"),
    ("XSS Unicode", "\u003Cscript\u003Ealert(4)\u003C/script\u003E", "blocked"),
    ("XSS dans un header", "User-Agent: <script>alert(5)</script>", "blocked"),

    # Attaques SQLi
    ("SQLi basique", "1' OR '1'='1", "blocked"),
    ("SQLi encodé", "1%27%20OR%20%271%27%3D%271", "blocked"),
    ("SQLi avec commentaire", "1' UNION SELECT * FROM users--", "blocked"),
    ("SQLi hex", "0x53454C454354", "blocked"),

    # Attaques DLP
    ("Numéro de carte bancaire", "4111111111111111", "blocked"),
    ("Email sensible", "admin@monentreprise.com", "blocked"),

    # Obfuscation avancée
    ("Obfuscation JS", "eval('al'+'ert(6)')", "blocked"),
    ("Obfuscation Base64", "atob('YWxlcnQoMTAp')", "blocked"),
    ("Obfuscation Unicode + URL", "%u003Cscript%u003Ealert(8)%u003C/script%u003E", "blocked"),
]


@pytest.mark.parametrize("nom,payload,expected", CAS_TESTS_MAIN, ids=[c[0] for c in CAS_TESTS_MAIN])
def test_cas_du_bloc_main(analyseur, nom, payload, expected):
    """Chaque cas du bloc __main__ doit produire le statut attendu."""
    resultat = analyseur.analyser_requete(payload)
    assert resultat.status == expected, (
        f"{nom}: attendu {expected!r}, obtenu {resultat.status!r} "
        f"(rule_id={resultat.rule_id}, reason={resultat.reason})"
    )


# ---------------------------------------------------------------------------
# Structure du résultat
# ---------------------------------------------------------------------------

class TestAnalyseResult:
    def test_payload_vide_retourne_clean(self, analyseur):
        r = analyseur.analyser_requete("")
        assert r.status == "clean"
        assert r.confidence == 0.0

    def test_payload_none_retourne_clean(self, analyseur):
        r = analyseur.analyser_requete(None)
        assert r.status == "clean"

    def test_detection_bloquee_remplit_les_champs(self, analyseur):
        r = analyseur.analyser_requete("<script>alert(1)</script>")
        assert r.status == "blocked"
        assert r.rule_id is not None
        assert r.reason is not None  # nom de la règle
        assert r.severity is not None
        assert r.match is not None  # portion correspondante
        assert 0.0 <= r.confidence <= 1.0

    def test_dataclass_analyse_result_champs_defauts(self):
        r = AnalyseResult(status="clean")
        assert r.rule_id is None
        assert r.confidence == 0.0
        assert r.obfuscation_detected is False
        assert r.source is None


# ---------------------------------------------------------------------------
# Décodage / nettoyage des données (_nettoyer_donnees)
# ---------------------------------------------------------------------------

class TestNettoyage:
    def test_decode_url_encoding(self, analyseur):
        # %3C = '<', la règle XSS doit donc déclencher après décodage
        r = analyseur.analyser_requete("%3Cscript%3E")
        assert r.status == "blocked"

    def test_decode_double_url_encoding(self, analyseur):
        # %253C -> %3C -> '<'
        r = analyseur.analyser_requete("%253Cscript%253E")
        assert r.status == "blocked"

    def test_decode_unicode_escape(self, analyseur):
        r = analyseur.analyser_requete("\u003Cscript\u003E")
        assert r.status == "blocked"

    def test_decode_hex_ajoute_au_texte(self, analyseur):
        # 0x53454C454354 -> "SELECT" décodé, qui déclenche la règle SQLi
        r = analyseur.analyser_requete("0x53454C454354")
        assert r.status == "blocked"

    def test_bytes_sont_convertis_en_str(self, analyseur):
        r = analyseur.analyser_requete(b"<script>alert(1)</script>")
        assert r.status == "blocked"

    def test_none_retourne_chaine_vide(self, analyseur):
        assert analyseur._nettoyer_donnees(None) == ""

    def test_ne_leve_pas_sur_entree_bizarre(self, analyseur):
        # Des bytes invalides ne doivent pas faire planter le nettoyage
        out = analyseur._nettoyer_donnees(b"\xff\xfe\x00\x01")
        assert isinstance(out, str)


# ---------------------------------------------------------------------------
# Détection d'obfuscation
# ---------------------------------------------------------------------------

class TestObfuscation:
    @pytest.mark.parametrize("payload", [
        "%3Cscript%3E",              # URL encoding
        "&#60;script&#62;",          # HTML entities
        "\\x3cscript\\x3e",          # hex encoding
        "atob('test')",              # base64 obfuscation
        "eval('x')",                 # JS obfuscation
    ])
    def test_obfuscation_detectee(self, analyseur, payload):
        assert analyseur._detecter_obfuscation(payload) is True

    def test_texte_normal_sans_obfuscation(self, analyseur):
        assert analyseur._detecter_obfuscation("hello world 12345") is False

    def test_obfuscation_renvoie_drapeau_dans_resultat(self, analyseur):
        # atob(...) est à la fois obfusqué ET bloqué par une signature
        r = analyseur.analyser_requete("atob('YWxlcnQoMTAp')")
        assert r.obfuscation_detected is True


# ---------------------------------------------------------------------------
# Calcul de confiance (_calculer_confiance)
# ---------------------------------------------------------------------------

class TestConfiance:
    def test_confiance_dans_intervalle_0_1(self, analyseur):
        r = analyseur.analyser_requete("' OR '1'='1")
        assert 0.0 <= r.confidence <= 1.0

    def test_gravite_critique_donne_confiance_elevee(self, analyseur):
        # SQLi hex déclenche une règle critique
        r = analyseur.analyser_requete("0x53454C454354")
        assert r.severity == "critical"
        assert r.confidence >= 0.8

    def test_obfuscation_augmente_la_confiance(self, analyseur):
        # atob(...) est obfusqué et déclenche une règle critique ; le bonus
        # d'obfuscation doit faire grimper la confiance au plafond (1.0).
        r = analyseur.analyser_requete("atob('YWxlcnQoMTAp')")
        assert r.obfuscation_detected is True
        assert r.confidence == 1.0


# ---------------------------------------------------------------------------
# Analyse de requête complète et listes de payloads
# ---------------------------------------------------------------------------

class TestAnalyseComplete:
    def test_detecte_dans_url(self, analyseur):
        r = analyseur.analyser_requete_complete(url="search?q=<script>alert(1)</script>")
        assert r.status == "blocked"
        assert r.source == "url"

    def test_detecte_dans_body(self, analyseur):
        r = analyseur.analyser_requete_complete(body="' OR '1'='1")
        assert r.status == "blocked"
        assert r.source == "body"

    def test_detecte_dans_headers(self, analyseur):
        r = analyseur.analyser_requete_complete(headers={"X": "<script>x</script>"})
        assert r.status == "blocked"
        assert r.source == "headers"

    def test_detecte_dans_query_params(self, analyseur):
        r = analyseur.analyser_requete_complete(query_params={"q": "1' UNION SELECT *"})
        assert r.status == "blocked"
        assert r.source == "query_params"

    def test_requete_tout_propre(self, analyseur):
        r = analyseur.analyser_requete_complete(
            methode="GET",
            url="/search?q=bonjour",
            headers={"User-Agent": "Mozilla"},
            body=None,
            query_params={"q": "bonjour"},
        )
        assert r.status == "clean"

    def test_retourne_des_la_premiere_menace(self, analyseur):
        # body contient une attaque, headers aussi ; on doit obtenir l'un
        # des deux (et pas clean).
        r = analyseur.analyser_requete_complete(
            url="/ok",
            body="' OR '1'='1",
            headers={"X": "<script>x</script>"},
        )
        assert r.status == "blocked"
        assert r.source in ("body", "headers")


class TestListePayloads:
    def test_retourne_une_liste_de_resultats(self, analyseur):
        payloads = ["normal", "<script>alert(1)</script>", "encore normal"]
        resultats = analyseur.analyser_liste_payloads(payloads)
        assert len(resultats) == len(payloads)
        assert resultats[0].status == "clean"
        assert resultats[1].status == "blocked"
        assert resultats[2].status == "clean"

    def test_liste_vide_retourne_liste_vide(self, analyseur):
        assert analyseur.analyser_liste_payloads([]) == []

    def test_chaque_element_est_un_analyse_result(self, analyseur):
        resultats = analyseur.analyser_liste_payloads(["a", "b"])
        for r in resultats:
            assert isinstance(r, AnalyseResult)
