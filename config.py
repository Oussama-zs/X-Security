# ==============================================================================
# X-SECURITY - Hybrid AI-Powered Vulnerability Scanner
# 
# Author: Oussama Elattaoui (GitHub: oussama-zs)
# Institution: Ecole des Sciences de l'Information (ESI), Rabat
# Project: Projet de Fin d'Annee (PFA) 2025/2026
# Company: CGX (Creative Generated Experience)
#
# This software is part of an academic project.
# Unauthorized copying, modification, or distribution without credit is prohibited.
# ==============================================================================

import os
from pathlib import Path

# Project Root
PROJECT_ROOT = Path(__file__).parent.absolute()

# Ignore Patterns (in addition to .gitignore)
DEFAULT_IGNORE_PATTERNS = [
    ".git/",
    ".venv/",
    "venv/",
    "node_modules/",
    "__pycache__/",
    "dist/",
    "build/",
    "*.pyc",
    "*.pdf",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.svg",
    "*.mp4",
    "*.wav",
    "*.mp3",
    ".DS_Store"
]

# Supported languages mapping (Extension -> Language Name)
# This will help us later when we configure Semgrep and the AI Prompts
SUPPORTED_LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".java": "Java",
    ".go": "Go",
    ".c": "C",
    ".cpp": "C++",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".html": "HTML",
    ".css": "CSS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".md": "Markdown",
    ".sh": "Shell Script",
    ".ps1": "PowerShell"
}

def get_language_from_extension(file_path: str) -> str:
    """Detects the programming language based on file extension."""
    ext = Path(file_path).suffix.lower()
    return SUPPORTED_LANGUAGES.get(ext, "Unknown")
