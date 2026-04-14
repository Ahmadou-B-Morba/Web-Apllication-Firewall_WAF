# 🔐 ProjetWAF – Intelligent Web Application Firewall

## 📌 Overview

ProjetWAF is a Python-based Web Application Firewall (WAF) designed for educational and experimental purposes.  
It aims to provide a practical understanding of how modern web applications can be protected against common and advanced attacks.

Unlike traditional WAFs that rely solely on static signatures, this project introduces a **hybrid detection approach**, combining:

- Rule-based detection (signatures)
- AI-based behavioral analysis

The system acts as an intermediary layer between the client and the web application, inspecting and filtering HTTP requests before they are processed.

---

## 🧠 How It Works

ProjetWAF is built around a Flask middleware that intercepts all incoming HTTP requests. Each request is analyzed through multiple layers:

### 🔍 Rule-Based Detection

The first layer relies on a set of predefined security rules using regular expressions.  
These rules are designed to detect known attack patterns such as:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal

This ensures fast and efficient detection of well-known threats.

### 🤖 AI-Based Detection

To go beyond static rules, the project integrates an **Artificial Intelligence module** capable of detecting suspicious behavior.

Instead of looking only for known patterns, the AI analyzes requests based on extracted features such as:

- Input length
- Special character distribution
- Suspicious keywords frequency
- Structural anomalies in payloads

A trained model is then used to classify requests as **legitimate or potentially malicious**.

This allows the system to detect:
- Unknown attacks
- Obfuscated payloads
- Unusual request patterns

---

## 📊 Logging & Monitoring

All analyzed requests and detected threats are logged for traceability and analysis.

Each event may include:
- Detected attack type (or suspicion level)
- Malicious input data
- Risk score (if AI is used)
- Decision taken (allowed / blocked)
- Timestamp

Logs can be stored in structured files or a database, making them useful for:
- Security auditing
- Model training
- Attack analysis

---

## 🧩 Architecture

The project follows a modular architecture to ensure clarity and scalability:

- **Middleware Layer**: Intercepts HTTP requests via Flask
- **Rule Engine**: Handles signature-based detection
- **AI Module**: Performs behavioral analysis and classification
- **Logging System**: Records detected events
- **Configuration Layer**: Allows easy rule management

This design makes it easy to extend or improve each component independently.

---

## 🎯 Objectives

This project was built to:

- Understand how a Web Application Firewall works
- Explore web security vulnerabilities and protections
- Apply AI techniques in a cybersecurity context
- Design a modular and extensible system
- Simulate real-world defensive mechanisms

---

## 🚀 Future Improvements

ProjetWAF can be extended in several ways:

- Improve the AI model (better accuracy, new features)
- Add real-time adaptive learning
- Implement a web dashboard for monitoring
- Introduce advanced scoring and anomaly detection
- Integrate with SIEM or external security tools

---

## 🧑‍💻 Author

This project was developed as part of a learning journey in cybersecurity and software engineering, with a focus on building practical and intelligent security solutions.
