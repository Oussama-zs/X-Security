# 🛡️ X-SECURITY: Hybrid AI-Powered Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Security](https://img.shields.io/badge/Security-SAST%20%7C%20DAST-green)
![AI](https://img.shields.io/badge/AI-LLM%20Powered-purple)
![Academic](https://img.shields.io/badge/ESI-PFA%202025%2F2026-red)

> **Projet de Fin d'Année (PFA)** - École des Sciences de l'Information (ESI), Rabat.
> *Option : ISSIC (Ingénierie de la Sécurité des Systèmes d'Information et Cyberdéfense)*

## 📖 La Problématique
Lors des audits de sécurité professionnels, la vérification manuelle du code source et l'analyse de centaines de fausses alertes générées par les scanners traditionnels consomment un temps précieux. **X-SECURITY** résout ce problème en automatisant l'audit de bout en bout grâce à une architecture hybride (SAST + DAST) et en confiant la tâche ardue du triage des faux positifs à une **Intelligence Artificielle**.

## 🏗️ Architecture du Projet (5 Phases)
L'outil est architecturé autour de 5 moteurs distincts :
1. **Reconnaissance & Ingestion** : Filtrage intelligent du code source pour éviter le bruit (ex: `node_modules`).
2. **SAST (Static Analysis)** : Analyse de l'AST via `Semgrep` pour détecter les failles logiques dans le code hors-ligne.
3. **DAST (Dynamic Analysis)** : Attaque Multi-Moteurs (`Wapiti`, `Nuclei`, `OWASP ZAP`) sur l'application en cours d'exécution.
4. **AI Supervisor** : Corrélation des failles et élimination des **Faux Positifs** via un LLM (OpenAI-compatible ou Anthropic Claude).
5. **Reporting** : Génération automatique d'un rapport PDF professionnel listant les vulnérabilités prouvées avec preuves de concept (PoC) et remédiations.

## ⚙️ Installation

1. Clonez ce dépôt GitHub :
   ```bash
   git clone https://github.com/oussama-zs/X-SECURITY.git
   cd X-SECURITY
   ```

2. Installez l'outil globalement via `pip` (Mode Éditable) :
   ```bash
   pip install -e .
   ```

## 🚀 Utilisation (CLI)

X-SECURITY s'utilise directement depuis n'importe quel terminal via la commande globale `xsecurity`.

### Mode Hybride (SAST + DAST simultanés) - Recommandé
```bash
xsecurity -H --target_dir ./mon_code --target-url "http://127.0.0.1:8080" --dast-engines "wapiti,nuclei,zap" --api-url "https://api.anthropic.com/v1/messages" --model "claude-3-5-sonnet-20240620" --api-key "VOTRE_CLE_API"
```

### Autres Modes
*   **Mode SAST Uniquement :** `xsecurity -S --target_dir ./mon_code ...`
*   **Mode DAST Uniquement :** `xsecurity -D --target-url "http://monsite.com" ...`

## 🧪 Fichiers de Démonstration (TP)
Le dossier inclut une application Flask intentionnellement vulnérable (`dummy_vulnerable_app`) contenant 6 failles critiques (SQLi, XSS, Command Injection, LFI, SSRF, Pickle Deserialization) pour tester la robustesse de l'IA.

## 👨‍💻 Auteur
**Oussama Elattaoui** - Élève Ingénieur en Cybersécurité @ ESI Rabat.
*Encadrant entreprise : CGX (Creative Generated Experience)*
