#🔐 ProjetWAF – Web Application Firewall intelligent en Python
📌 Présentation

ProjetWAF est un Web Application Firewall (WAF) développé en Python, conçu dans une démarche pédagogique et expérimentale afin d’explorer les mécanismes modernes de sécurisation des applications web.

Contrairement à une approche classique reposant uniquement sur des signatures statiques, ce projet propose une vision hybride combinant détection par règles et analyse intelligente basée sur l’intelligence artificielle. L’objectif est de reproduire, à échelle réduite, le fonctionnement des solutions de sécurité actuelles capables de s’adapter à des comportements malveillants de plus en plus complexes.

Le système agit comme une couche intermédiaire entre l’utilisateur et l’application web, en interceptant et analysant chaque requête HTTP avant qu’elle ne soit traitée.

#🧠 Fonctionnement global

Le cœur du projet repose sur un mécanisme d’interception des requêtes via un middleware Flask. Chaque requête entrante est inspectée en profondeur : les paramètres, les en-têtes et les données envoyées sont extraits puis soumis à différents niveaux d’analyse.

Dans un premier temps, un moteur de détection basé sur des règles identifie rapidement les signatures connues d’attaques telles que les injections SQL, les scripts malveillants ou les tentatives de contournement. Cette approche permet une détection rapide et efficace des menaces classiques.

En complément, une couche d’analyse intelligente vient enrichir cette détection en évaluant le comportement global de la requête. Plutôt que de se limiter à des motifs précis, cette couche cherche à identifier des anomalies ou des patterns suspects qui pourraient échapper aux règles statiques.

#🤖 Intégration de l’intelligence artificielle

L’un des aspects centraux de ce projet réside dans l’intégration d’un module d’intelligence artificielle permettant d’améliorer la détection des attaques.

Ce module repose sur une logique d’apprentissage supervisé (ou semi-supervisé selon l’évolution du projet), dans laquelle des requêtes sont analysées et transformées en caractéristiques exploitables (features). Ces caractéristiques peuvent inclure, par exemple, la longueur des entrées, la présence de caractères spéciaux, la structure des données ou encore la fréquence de certains motifs.

À partir de ces données, un modèle est capable de distinguer des requêtes légitimes de requêtes potentiellement malveillantes. Ce modèle agit comme un complément aux règles traditionnelles, permettant de détecter des attaques inconnues ou obfusquées.

L’IA introduit ainsi une dimension adaptative au WAF, en rendant la détection moins dépendante de signatures fixes et plus orientée vers l’analyse comportementale.

#📊 Journalisation et analyse

Chaque requête analysée génère des informations exploitables qui sont enregistrées dans un système de journalisation structuré. Lorsqu’une menace est détectée, plusieurs éléments sont conservés afin de permettre une analyse approfondie :

le type d’attaque identifié ou suspecté,
les données ayant déclenché la détection,
le niveau de risque estimé,
la décision prise par le système (autorisation ou blocage),
l’horodatage de l’événement.

Ces données peuvent être utilisées pour améliorer les règles existantes, entraîner le modèle d’intelligence artificielle ou encore fournir une base pour la visualisation et le monitoring.

#🧩 Architecture du projet

Le projet adopte une architecture modulaire afin de séparer clairement les responsabilités et faciliter son évolution.

Le système s’organise autour de plusieurs composants principaux :

un module d’interception des requêtes intégré à Flask,
un moteur de règles chargé de la détection par signatures,
un module d’intelligence artificielle dédié à l’analyse comportementale,
un système de journalisation pour la traçabilité,
une couche de configuration permettant d’ajouter ou modifier facilement les règles.

Cette organisation permet de faire évoluer indépendamment chaque partie du système, notamment le module IA qui peut être enrichi sans impacter le reste de l’application.

#🎯 Objectifs

À travers ce projet, plusieurs objectifs sont poursuivis :

comprendre en profondeur le fonctionnement d’un WAF,
expérimenter des techniques de détection d’attaques web,
intégrer des concepts d’intelligence artificielle dans un contexte de cybersécurité,
développer une architecture logicielle claire et extensible,
simuler des mécanismes utilisés dans des solutions de sécurité réelles.

#🚀 Perspectives d’évolution

ProjetWAF a été conçu comme une base évolutive. Plusieurs améliorations peuvent être envisagées :

enrichissement du modèle d’intelligence artificielle,
ajout de mécanismes de scoring et de classification avancée,
mise en place d’une interface de visualisation des attaques,
détection en temps réel avec apprentissage continu,
intégration avec des outils externes de monitoring ou de SIEM.

#🧑‍💻 Auteur

Ce projet a été réalisé dans le cadre d’un apprentissage en cybersécurité, avec une volonté de combiner développement logiciel et sécurité offensive/défensive.
