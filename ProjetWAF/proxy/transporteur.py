from flask import Flask, request, abort
import sys
import os

# Ajout du chemin pour importer l'analyseur
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from moteur_ia.analyseur import AnalyseurWAF

app = Flask(__name__)
waf = AnalyseurWAF()

# L'adresse de votre "vrai" serveur à protéger (plus tard)
# TARGET_SERVER = "http://localhost:5000" 

@app.before_request
def filtrer_trafic():
    # On analyse plusieurs parties de la requête
    query_string = request.query_string.decode()
    user_agent = request.headers.get('User-Agent', '')
    
    # Test sur les paramètres d'URL (GET)
    verdict = waf.analyser_requete(query_string)
    
    # Test sur le User-Agent (pour les bots)
    if verdict["status"] == "clean":
        verdict = waf.analyser_requete(user_agent)

    if verdict["status"] == "blocked":
        print(f"[BLOCAGE] Tentative détectée ! ID: {verdict['rule_id']} | Raison: {verdict['reason']}")
        return f"""
        <html>
            <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
                <h1 style="color:red;">Accès Refusé par le ProjetWAF</h1>
                <p>Votre requête a été identifiée comme malveillante.</p>
                <hr>
                <p>ID de l'incident : {verdict['rule_id']}</p>
            </body>
        </html>
        """, 403

@app.route('/')
def home():
    return "<h1>Bienvenue sur le site sécurisé</h1><p>Le WAF vous surveille (en bien !).</p>"

if __name__ == "__main__":
    # On lance le proxy sur le port 8080
    app.run(port=8080, debug=False)