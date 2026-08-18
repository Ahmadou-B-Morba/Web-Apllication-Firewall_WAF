from flask import Flask, request, jsonify
from logs.logger import log_attack
from regles.loader import RuleLoader
import re

app = Flask(__name__)

# Initialisation du moteur de règles
waf_loader = RuleLoader()
waf_loader.load_all()

# Routes à exclure (ex: static files)
EXCLUDED_ROUTES = ["/static/", "/favicon.ico"]

@app.before_request
def waf_middleware():
    # Exclure les routes sûres
    if any(request.path.startswith(route) for route in EXCLUDED_ROUTES):
        return None

    # Analyser tous les champs possibles
    # request.json lève une erreur si le Content-Type n'est pas application/json ;
    # on l'intercepte pour ne pas bloquer les requêtes classiques.
    json_body = {}
    try:
        json_body = request.get_json(silent=True) or {}
    except Exception:
        json_body = {}

    params = {
        **request.args.to_dict(),       # Query parameters (GET)
        **request.form.to_dict(),       # Form data (POST)
        **json_body,                    # JSON body
        **dict(request.headers),        # Headers
    }

    try:
        for key, value in params.items():
            if isinstance(value, (list, tuple)):
                value = " ".join(value)
            if isinstance(value, str):
                match = waf_loader.check(str(value))
                if match:
                    attack_info = f"[{match.get('id')}] {match.get('nom')}"
                    log_attack(
                        ip=request.remote_addr,
                        attack_type=attack_info,
                        payload=value,
                        method=request.method,
                        uri=request.path,
                        user_agent=request.headers.get('User-Agent', 'Unknown')
                    )
                    return f"<h1>🚫 Accès Refusé</h1><p>Requête bloquée pour des raisons de sécurité.</p>", 400
    except Exception as e:
        # Log l'erreur sans bloquer la requête
        app.logger.error(f"WAF Error: {e}")
        return None

    return None

@app.route('/')
def home():
    return "<h1>Bienvenue</h1><p>Le serveur est sous protection WAF.</p>"

if __name__ == '__main__':
    app.run(debug=True, port=5000)