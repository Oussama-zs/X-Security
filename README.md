# 🛡️ X-SECURITY: Hybrid AI-Powered Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Security](https://img.shields.io/badge/Security-SAST%20%7C%20DAST-green)
![AI](https://img.shields.io/badge/AI-LLM%20Powered-purple)
![Academic](https://img.shields.io/badge/ESI-PFA%202025%2F2026-red)

> **Projet de Fin d'Année (PFA)** - École des Sciences de l'Information (ESI), Rabat.
> *Option : ISSIC (Ingénierie de la Sécurité des Systèmes d'Information et Cyberdéfense)*

## 📖 La Problématique
Lors des audits de sécurité professionnels, la vérification manuelle du code source et l'analyse de centaines de fausses alertes (False Positives) générées par les scanners traditionnels consomment un temps précieux. **X-SECURITY** résout ce problème en automatisant l'audit de bout en bout grâce à une architecture hybride (SAST + DAST) et en confiant la tâche ardue du triage des alertes à un superviseur **Intelligence Artificielle (LLM)**.

## 🏗️ Architecture du Projet (5 Moteurs)
L'outil est architecturé autour de 5 moteurs distincts travaillant en pipeline :
1. **Reconnaissance & Ingestion** : Filtrage intelligent du code source pour éviter le bruit (ex: `node_modules`, environnements virtuels).
2. **SAST (Static Analysis)** : Analyse de l'AST via `Semgrep` pour détecter les failles logiques dans le code source hors-ligne.
3. **DAST (Dynamic Analysis)** : Attaque Multi-Moteurs (`Wapiti`, `Nuclei`, `OWASP ZAP`) sur l'application en cours d'exécution via un orchestrateur asynchrone.
4. **AI Supervisor** : Corrélation des failles et élimination des **Faux Positifs** via un LLM. L'IA juge la criticité technique et propose des remédiations. Le système est résilient face aux API Rate Limits.
5. **Reporting (Markdown & PDF)** : Génération automatique d'un rapport technique sophistiqué en Markdown (résistant aux payloads d'attaque complexes) et d'un rapport PDF consolidé pour le management.

## ⚙️ Pré-requis et Installation

### Pré-requis
*   **Python 3.8+**
*   **Semgrep** : Pour l'analyse SAST (`pip install semgrep`).
*   **Nuclei & Wapiti** : Doivent être installés et accessibles dans la variable d'environnement `PATH`.
*   **OWASP ZAP** : Le démon ZAP doit être accessible via API (par défaut : `http://127.0.0.1:8081`).
*   **Clé API** : Une clé valide pour un modèle LLM (Anthropic Claude, Google Gemini, OpenAI, etc.).

### Installation
Clonez le dépôt et installez l'outil globalement (Mode Éditable) :
```bash
git clone https://github.com/oussama-zs/X-SECURITY.git
cd X-SECURITY
pip install -e .
```
L'outil sera alors accessible depuis n'importe où via la commande globale `xsecurity`.

## 🚀 Utilisation (CLI)

La syntaxe générale de X-SECURITY requiert les drapeaux de mode (`-H`, `-S`, ou `-D`), vos identifiants d'API, et **le chemin vers le dossier source en argument positionnel à la toute fin**.

### Mode Hybride (SAST + DAST simultanés) - 🔴 Recommandé
C'est le mode le plus puissant. Il lance l'analyse statique sur le code local ET les attaques dynamiques sur le serveur distant, puis l'IA consolide le tout. N'oubliez pas le `-H` !

```bash
xsecurity -H --target-url "http://127.0.0.1:8080" --dast-engines "wapiti,nuclei,zap" --api-url "https://api.anthropic.com/v1/messages" --model "claude-3-5-sonnet-20240620" --api-key "VOTRE_CLE_API" ./dossier_source
```

### Mode SAST Uniquement (Analyse Statique)
Si l'application n'est pas en cours d'exécution, vous pouvez analyser uniquement le code source :

```bash
xsecurity -S --api-url "https://api.anthropic.com/v1/messages" --model "claude-3-5-sonnet-20240620" --api-key "VOTRE_CLE_API" ./dossier_source
```

### Mode DAST Uniquement (Analyse Dynamique Boîte Noire)
Si vous n'avez pas accès au code source (Boîte Noire) :

```bash
xsecurity -D --target-url "http://monsite.com" --dast-engines "wapiti,nuclei,zap" --api-url "https://api.anthropic.com/v1/messages" --model "claude-3-5-sonnet-20240620" --api-key "VOTRE_CLE_API" .
```
*(Le `.` à la fin est requis pour fournir un argument positionnel factice au script CLI).*

### Mode Reprise (Resume Workflow) - 🔄 NOUVEAU
En cas de crash de l'IA (Rate Limit) après 30 minutes de scan, vous pouvez reprendre l'analyse sémantique sans refaire le scan SAST/DAST en chargeant le Checkpoint JSON de secours :

```bash
xsecurity --resume xsecurity_raw_findings.json --api-url "https://api.anthropic.com/v1/messages" --model "claude-3-5-sonnet-20240620" --api-key "VOTRE_CLE_API"
```

## 🛠️ Options de la Ligne de Commande (Référence)

| Option | Description |
| :--- | :--- |
| `-H`, `--hybrid` | Active le scan Hybride complet (SAST + DAST). |
| `-S`, `--sast` | Active le scan Statique uniquement (Code Source). |
| `-D`, `--dast` | Active le scan Dynamique uniquement (Réseau). |
| `--target-url` | L'URL de l'application cible (Obligatoire pour les modes `-H` et `-D`). |
| `--dast-engines` | Les moteurs DAST à utiliser, séparés par des virgules (ex: `wapiti,nuclei,zap`). |
| `--zap-url` | URL du démon ZAP (Défaut: `http://127.0.0.1:8081`). |
| `--zap-api-key` | Clé API pour contrôler l'instance ZAP (si configurée). |
| `--resume` | Chemin vers un fichier JSON de checkpoint pour reprendre l'analyse IA. |
| `--api-url` | L'endpoint REST du LLM (L'outil s'adapte automatiquement au format OpenAI ou Anthropic). |
| `--model` | Le nom du modèle LLM à interroger. |
| `--api-key` | Votre clé API pour l'IA. |
| `[target_dir]` | **(Argument positionnel)** Le chemin vers le dossier du code source à analyser. |

## 🧪 Environnement de Test
Le dépôt inclut une application Flask intentionnellement vulnérable dans le dossier `dummy_vulnerable_app`. Elle contient 6 failles critiques délibérées (SQLi, XSS, Command Injection, LFI, SSRF, Pickle Deserialization) permettant de valider l'architecture et la précision de l'IA (Supervisor).

*   Pour la démarrer : `python dummy_vulnerable_app/app.py` (Démarre sur le port `8080`).

## 👨‍💻 Auteur
**Oussama Elattaoui** (GitHub: oussama-zs) - Élève Ingénieur en Cybersécurité @ ESI Rabat.
*Encadrant entreprise : CGX (Creative Generated Experience)*
