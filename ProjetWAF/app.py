from flask import Flask, request, jsonify
from logs.logger import log_attack
from regles.loader import RuleLoader
import hashlib
import os
import re

app = Flask(__name__)

# Initialisation du moteur de regles
waf_loader = RuleLoader()
waf_loader.load_all()
# Le loader est aussi expose dans app.config pour permettre aux tests
# (et a l'avenir a l'admin) de le remplacer a chaud.
app.config["waf_loader"] = waf_loader

# Routes a exclure (ex: static files)
EXCLUDED_ROUTES = ["/static/", "/favicon.ico"]

# ---------------------------------------------------------------------------
# Integration Redis (cache des decisions du WAF)
# ---------------------------------------------------------------------------
# Redis est optionnel : si le serveur n'est pas joignable, le WAF continue
# de fonctionner sans cache (degradation gracieuse). Les variables de
# configuration sont lues depuis l'environnement :
#   REDIS_HOST (defaut: localhost), REDIS_PORT (defaut: 6379),
#   REDIS_DB (defaut: 0), REDIS_PASSWORD (defaut: None)
REDIS_AVAILABLE = False
redis_client = None

try:
    import redis as redis_module

    redis_client = redis_module.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        password=os.getenv("REDIS_PASSWORD") or None,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    redis_client.ping()
    REDIS_AVAILABLE = True
except Exception:
    # Redis indisponible : on continue sans cache.
    redis_client = None
    REDIS_AVAILABLE = False


def _cache_key(method, uri, query_string):
    """Construit la cle de cache d'une requete a partir de son empreinte."""
    raw = f"{method}:{uri}:{query_string}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"waf:{digest}"


@app.before_request
def waf_middleware():
    # Exclure les routes sures
    if any(request.path.startswith(route) for route in EXCLUDED_ROUTES):
        return None

    # Route de gestion du cache (ne doit pas etre analysee par le WAF).
    if request.path == "/clear_cache":
        return None

    # Loader : on lit depuis app.config pour permettre aux tests d'injecter
    # un loader personnalise (ex: test_cache_blocked_request).
    loader = app.config.get("waf_loader", waf_loader)

    # Cle de cache basee sur la methode, l'URI et la query string.
    cache_key = _cache_key(request.method, request.path, request.query_string.decode("utf-8"))

    # --- Cache hit : Redis disponible et decision cachee ---
    if REDIS_AVAILABLE and redis_client is not None:
        cached = redis_client.get(cache_key)
        if cached is not None:
            cached_value = str(cached)
            if cached_value == "allow":
                return None  # requete deja validee, on laisse passer
            elif cached_value.startswith("block:"):
                # Decision de blocage cachee : renvoyer la meme reponse.
                # Format : "block:<status>:<body>"
                parts = cached_value.split(":", 2)
                status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 400
                body = parts[2] if len(parts) > 2 else "Acces Refuse"
                return body, status

    # --- Cache miss : analyser la requete ---
    # request.json leve une erreur si le Content-Type n'est pas application/json ;
    # on l'intercepte pour ne pas bloquer les requetes classiques.
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

    blocked = False
    try:
        for key, value in params.items():
            if isinstance(value, (list, tuple)):
                value = " ".join(value)
            if isinstance(value, str):
                match = loader.check(str(value))
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
                    blocked = True
                    break
    except Exception as e:
        # Log l'erreur sans bloquer la requete
        app.logger.error(f"WAF Error: {e}")
        return None

    if blocked:
        # Mettre en cache la decision de blocage (TTL 5 min)
        if REDIS_AVAILABLE and redis_client is not None:
            body = "<h1>\U0001f6ab Acces Refuse</h1><p>Requete bloquee pour des raisons de securite.</p>"
            redis_client.setex(cache_key, 300, f"block:400:{body}")
        return "<h1>\U0001f6ab Acces Refuse</h1><p>Requete bloquee pour des raisons de securite.</p>", 400

    # Mettre en cache la decision d'autorisation (TTL 5 min)
    if REDIS_AVAILABLE and redis_client is not None:
        redis_client.setex(cache_key, 300, "allow")

    return None


@app.route('/clear_cache')
def clear_cache():
    """Vide le cache Redis des decisions du WAF."""
    if REDIS_AVAILABLE and redis_client is not None:
        redis_client.flushdb()
        return jsonify({"status": "cache cleared"}), 200
    return jsonify({"status": "redis unavailable", "cleared": False}), 200


@app.route('/')
def home():
    return "<h1>Bienvenue</h1><p>Le serveur est sous protection WAF.</p>"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
