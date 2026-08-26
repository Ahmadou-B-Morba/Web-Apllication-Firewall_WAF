from flask import Flask, request, jsonify
from logs.logger import log_attack
from regles.loader import RuleLoader
import redis
from redis import Redis
import hashlib
import json
import re

app = Flask(__name__)

# --- Configuration Redis (optionnelle) ---
REDIS_AVAILABLE = False
redis_client = None

try:
    redis_client = Redis(host='localhost', port=6379, db=0)
    redis_client.ping()  # Teste la connexion
    REDIS_AVAILABLE = True
    print("✅ Redis connecté avec succès")
except Exception as e:
    REDIS_AVAILABLE = False
    print(f"⚠️  Redis non disponible: {e}. Le cache sera désactivé.")

# --- Fonction pour générer une clé de cache unique ---
def generate_cache_key():
    """Génère une clé unique pour le cache Redis.

    Inclut le corps de la requête (form/JSON/raw) en plus de path+query+method :
    sans ça, deux requêtes POST différentes vers la même URL (ex: un payload
    malveillant puis une requête légitime) partageraient la même entrée de
    cache, faisant bloquer à tort tout trafic légitime pendant le TTL.
    """
    body_bytes = request.get_data(cache=True) or b""
    raw = (
        request.path.encode("utf-8")
        + request.query_string
        + request.method.encode("utf-8")
        + body_bytes
    )
    return hashlib.sha256(raw).hexdigest()

# --- Initialisation du moteur de règles ---
waf_loader = RuleLoader()
waf_loader.load_all()

# --- Routes à exclure (ex: static files) ---
EXCLUDED_ROUTES = ["/static/", "/favicon.ico", "/clear_cache"]

# TTL du cache Redis, en secondes.
# - Un verdict "bloqué" reste en cache plus longtemps : peu de raisons pour
#   qu'une même requête malveillante devienne légitime dans l'intervalle.
# - Un verdict "autorisé" a un TTL plus court : si les règles WAF sont mises
#   à jour (ajout d'une signature), on ne veut pas laisser passer trop
#   longtemps une requête qui vient d'être requalifiée de dangereuse.
CACHE_TTL_BLOCKED = 300   # 5 minutes
CACHE_TTL_ALLOWED = 60    # 1 minute

# --- Middleware WAF ---
@app.before_request
def waf_middleware():
    # Exclure les routes sûres
    if any(request.path.startswith(route) for route in EXCLUDED_ROUTES):
        return None

    # Générer la clé de cache
    cache_key = generate_cache_key()

    # Vérifier si la requête est déjà en cache (bloquée OU autorisée)
    if REDIS_AVAILABLE:
        cached_raw = redis_client.get(cache_key)
        if cached_raw:
            try:
                cached = json.loads(cached_raw)
            except (TypeError, ValueError):
                # Ancien format de cache (texte brut = toujours bloqué) :
                # on l'interprète comme tel plutôt que de planter.
                return cached_raw.decode("utf-8"), 400

            if cached.get("status") == "blocked":
                return cached["response"], 400
            # status == "allowed" : on ne rejoue pas le scan de règles,
            # on laisse Flask traiter la requête normalement.
            return None

    # Analyser tous les champs possibles
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
                    response = "<h1>🚫 Accès Refusé</h1><p>Requête bloquée pour des raisons de sécurité.</p>"
                    if REDIS_AVAILABLE:
                        redis_client.setex(
                            cache_key,
                            CACHE_TTL_BLOCKED,
                            json.dumps({"status": "blocked", "response": response}),
                        )
                    return response, 400
    except Exception as e:
        app.logger.error(f"WAF Error: {e}")
        return None

    # Aucune règle déclenchée : mémoriser le verdict "autorisé" pour éviter
    # de rescanner une requête identique tant que le cache est valide.
    if REDIS_AVAILABLE:
        redis_client.setex(
            cache_key,
            CACHE_TTL_ALLOWED,
            json.dumps({"status": "allowed"}),
        )

    return None

# --- Routes ---
@app.route('/')
def home():
    return "<h1>Bienvenue</h1><p>Le serveur est sous protection WAF.</p>"

@app.route('/clear_cache')
def clear_cache():
    """Vide le cache Redis."""
    if REDIS_AVAILABLE:
        redis_client.flushdb()
        return "Cache Redis vidé avec succès.", 200
    else:
        return "Redis non disponible. Rien à vider.", 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)