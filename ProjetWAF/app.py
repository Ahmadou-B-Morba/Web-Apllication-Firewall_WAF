from flask import Flask, request
from logs.logger import log_attack
from regles.loader import RuleLoader

app = Flask(__name__)

# Initialisation silencieuse du moteur
waf_loader = RuleLoader()
waf_loader.load_all()

@app.before_request
def waf_middleware():
    # On scanne les données GET (URL) et POST (Formulaires)
    params = {**request.args.to_dict(), **request.form.to_dict()}
    
    for key, value in params.items():
        match = waf_loader.check(value)
        
        if match:
            # Formatage propre pour la base de données
            attack_info = f"[{match.get('id')}] {match.get('nom')}"
            
            # Envoi vers PostgreSQL
            log_attack(
                ip=request.remote_addr,
                attack_type=attack_info,
                payload=value,
                method=request.method,
                uri=request.path,
                user_agent=request.headers.get('User-Agent', 'Unknown')
            )
            
            # Réponse de blocage au client
            return f"<h1>🚫 Accès Refusé</h1><p>Menace détectée : {match.get('nom')}</p>", 403
    
    return None

@app.route('/')
def home():
    return "<h1>Bienvenue</h1><p>Le serveur est sous protection WAF.</p>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    return "<h1>Page de connexion</h1>"

if __name__ == '__main__':
    app.run(debug=True, port=5000)