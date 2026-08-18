from flask import Flask, request, jsonify, Response
import requests
from urllib.parse import urljoin
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import ssl
from app import waf_middleware  # Middleware WAF pour l'analyse des requêtes

# Configuration
BACKEND_URL = "https://backend-example.com"  # URL HTTPS du backend à protéger
PROXY_HOST = "0.0.0.0"  # Écoute sur toutes les interfaces
PROXY_PORT = 8443  # Port HTTPS pour le proxy
TIMEOUT = 10  # Timeout en secondes pour les requêtes vers le backend
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Limite de taille des requêtes (16 Mo)

# Configuration SSL/TLS pour le proxy (à adapter avec vos certificats)
SSL_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
SSL_CONTEXT.load_cert_chain(
    certfile="path/to/cert.pem",  # Chemin vers votre certificat
    keyfile="path/to/key.pem"      # Chemin vers votre clé privée
)

# Initialisation de l'application Flask
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('proxy.log')  # Logs dans un fichier
    ]
)
logger = logging.getLogger(__name__)

# Rate Limiting (100 requêtes/minute par IP)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri="memory://"  # Stockage en mémoire (pour un seul processus)
)

# Appliquer le middleware WAF à toutes les requêtes
app.before_request(waf_middleware)

# Liste des headers à exclure (éviter les conflits avec le backend)
EXCLUDED_HEADERS = [
    'Host',  # Éviter les conflits avec le backend
    'Content-Length',  # Recalculé automatiquement par requests
    'Transfer-Encoding',
    'Connection',
    'X-Forwarded-For',  # Géré manuellement
    'X-Forwarded-Proto'  # Géré manuellement
]

# Headers à ajouter pour le forwarding (transparence)
FORWARDED_HEADERS = {
    'X-Forwarded-For': lambda: request.headers.get('X-Forwarded-For', request.remote_addr),
    'X-Forwarded-Proto': lambda: request.scheme,
    'X-Forwarded-Host': lambda: request.host
}

def filter_headers(headers):
    """Filtre les headers pour éviter les conflits avec le backend."""
    filtered = {
        key: value for key, value in headers.items()
        if key not in EXCLUDED_HEADERS
    }
    # Ajouter les headers forwardés
    for header, value_func in FORWARDED_HEADERS.items():
        filtered[header] = value_func()
    return filtered

def forward_request(path):
    """
    Transmet la requête au backend via HTTPS et retourne la réponse.
    Gère les erreurs de connexion, timeout, et taille de payload.
    """
    try:
        start_time = time.time()

        # Préparer l'URL du backend (avec path préservé)
        backend_url = urljoin(BACKEND_URL, f"/{path}")

        # Préparer les arguments pour requests.request
        req_args = {
            "method": request.method,
            "url": backend_url,
            "headers": filter_headers(request.headers),
            "cookies": request.cookies,
            "allow_redirects": False,  # Gérer les redirections manuellement si nécessaire
            "timeout": TIMEOUT,
            "verify": True  # Vérifier le certificat SSL du backend
        }

        # Ajouter le body si la méthode le permet
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            req_args["data"] = request.get_data()

        # Envoyer la requête au backend
        resp = requests.request(**req_args)

        # Log des performances
        duration = time.time() - start_time
        logger.info(
            f"Proxy: {request.method} {path} -> {resp.status_code} in {duration:.2f}s"
        )

        # Construire la réponse à retourner au client
        response_headers = dict(resp.headers)
        # Supprimer les headers qui pourraient causer des problèmes
        response_headers.pop('Transfer-Encoding', None)
        response_headers.pop('Connection', None)

        return Response(
            response=resp.content,
            status=resp.status_code,
            headers=response_headers
        )

    except requests.exceptions.Timeout:
        logger.error(f"Timeout when forwarding request to {BACKEND_URL}/{path}")
        return jsonify({
            "error": "Backend request timeout",
            "details": f"Request to {BACKEND_URL} timed out after {TIMEOUT}s"
        }), 504

    except requests.exceptions.SSLError as e:
        logger.error(f"SSL error when connecting to {BACKEND_URL}: {e}")
        return jsonify({
            "error": "Backend SSL certificate verification failed",
            "details": str(e)
        }), 502

    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error when forwarding request to {BACKEND_URL}/{path}: {e}")
        return jsonify({
            "error": "Backend unavailable",
            "details": f"Could not connect to {BACKEND_URL}"
        }), 502

    except requests.exceptions.RequestException as e:
        logger.error(f"Error forwarding request to {BACKEND_URL}/{path}: {e}")
        return jsonify({
            "error": "Proxy error",
            "details": str(e)
        }), 500

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
@limiter.limit("100 per minute")  # Rate limiting global
def proxy(path):
    """
    Proxy HTTPS/HTTP qui transmet les requêtes au backend après analyse par le WAF.
    Si la requête est bloquée par le WAF, elle ne parvient pas ici.
    """
    return forward_request(path)

# Gestion des erreurs
@app.errorhandler(404)
def not_found(error):
    """Erreur 404 : Ressource non trouvée."""
    return jsonify({
        "error": "Not found",
        "message": f"Resource {request.path} not found on backend"
    }), 404

@app.errorhandler(429)
def ratelimit_handler(error):
    """Erreur 429 : Trop de requêtes (rate limiting)."""
    return jsonify({
        "error": "Too many requests",
        "message": "Rate limit exceeded. Try again later.",
        "retry_after": error.description  # flask-limiter ajoute cette info
    }), 429

@app.errorhandler(413)
def content_too_large(error):
    """Erreur 413 : Payload trop volumineux."""
    return jsonify({
        "error": "Payload too large",
        "message": f"Request size exceeds {MAX_CONTENT_LENGTH // (1024 * 1024)}MB limit"
    }), 413

@app.errorhandler(500)
def internal_error(error):
    """Erreur 500 : Erreur interne du serveur."""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        "error": "Internal server error",
        "message": "An unexpected error occurred"
    }), 500

if __name__ == '__main__':
    logger.info(f"Starting WAF Proxy on {PROXY_HOST}:{PROXY_PORT} (HTTPS)...")
    app.run(
        host=PROXY_HOST,
        port=PROXY_PORT,
        ssl_context=SSL_CONTEXT,  # Activer HTTPS
        debug=False,  # Désactiver le mode debug en production
        threaded=True  # Gérer les requêtes en threads (pour les performances)
    )