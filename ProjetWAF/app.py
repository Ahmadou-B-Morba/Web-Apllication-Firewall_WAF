from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/test', methods=['POST'])
def verifier_requete():
    # On récupère les données envoyées
    donnees = request.get_json()
    print(f"Analyse de la requête : {donnees}")
    
    # Simulation d'une règle simple : on cherche le mot "ATTACK"
    if "ATTACK" in str(donnees).upper():
        return jsonify({"verdict": "BLOQUÉ", "raison": "Mot clé suspect détecté"}), 403
    
    return jsonify({"verdict": "AUTORISÉ", "message": "Requête saine"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=8080)