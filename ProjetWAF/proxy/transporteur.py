from flask import Flask, request, jsonify, Response
import requests
from app import waf_middleware  # Middleware WAF pour l'analyse des requêtes
from urllib.parse import urljoin
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time

# Configuration
BACKEND_URL = "http://localhost:5000"  # URL du backend à protéger
TIMEOUT = 10  # Timeout en secondes pour les requêtes vers le backend
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limite de taille des requêtes (16 Mo)

# Initialisation de l'application Flask
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate Limiting (100 requêtes/minute par IP)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

# Appliquer le middleware WAF à toutes les requêtes
app.before_request(waf_middleware)

# Liste des headers à exclure (éviter les conflits)
EXCLUDED_HEADERS = [
    'Host',  # Éviter les conflits avec le backend
    'Content-Length',  # Recalculé automatiquement par requests
    'Transfer-Encoding',
    'Connection'
]

def filter_headers(headers):
    """Filtre les headers pour éviter les conflits avec le backend."""
    return {
        key: value for key, value in headers.items()
        if key not in EXCLUDED_HEADERS
    }

def forward_request(path):
    """Transmet la requête au backend et retourne la réponse."""
    try:
        start_time = time.time()

        # Préparer les arguments pour requests.request
        req_args = {
            "method": request.method,
            "url": urljoin(BACKEND_URL, f"/{path}"),
            "headers": filter_headers(request.headers),
            "cookies": request.cookies,
            "allow_redirects": False,
            "timeout": TIMEOUT
        }

        # Ajouter le body si nécessaire (GET/HEAD n'ont pas de body)
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            req_args["data"] = request.get_data()

        # Envoyer la requête au backend
        resp = requests.request(**req_args)

        # Log des performances
        duration = time.time() - start_time
        logger.info(
            f"Proxy: {request.method} {path} -> {resp.status_code} in {duration:.2f}s"
        )

        # Retourner la réponse du backend
        return Response(
            response=resp.content,
            status=resp.status_code,
            headers=dict(resp.headers)
        )

    except requests.exceptions.Timeout:
        logger.error(f"Timeout when forwarding request to {BACKEND_URL}/{path}")
        return jsonify({"error": "Backend request timeout"}), 504

    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error when forwarding request to {BACKEND_URL}/{path}")
        return jsonify({"error": "Backend unavailable"}), 502

    except requests.exceptions.RequestException as e:
        logger.error(f"Error forwarding request: {e}")
        return jsonify({"error": "Proxy error"}), 500

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
@limiter.limit("100 per minute")  # Appliquer le rate limiting
def proxy(path):
    """
    Proxy HTTP qui transmet les requêtes au backend après analyse par le WAF.
    """
    # Si le middleware WAF a bloqué la requête, elle ne parvient pas ici.
    # Sinon, on transmet la requête au backend.
    return forward_request(path)

@app.errorhandler(404)
def not_found(error):
    """Gestion des erreurs 404."""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(429)
def ratelimit_handler(error):
    """Gestion des erreurs de rate limiting."""
    return jsonify({
        "error": "Too many requests",
        "message": "Rate limit exceeded. Try again later."
    }), 429

@app.errorhandler(413)
def content_too_large(error):
    """Gestion des erreurs de taille de requête."""
    return jsonify({"error": "Payload too large"}), 413

if __name__ == '__main__':
    logger.info("Starting WAF Proxy on port 8080...")
    app.run(host='0.0.0.0', port=8080, debug=False)  # debug=False en production